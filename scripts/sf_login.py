#!/usr/bin/env python3
"""Minimal S&F login + sanity listing in Python."""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, Tuple
from urllib.parse import urlparse

import requests

HASH_CONST = "ahHoj2woo1eeChiech6ohphoB7Aithoh"
APP_VERSION = "285000000000"
DEFAULT_CRYPTO_ID = "0-00000000000000"
DEFAULT_SESSION_ID = "00000000000000000000000000000000"
SSO_BASE_URL = "https://sso.playa-games.com"
SSO_CLIENT_ID = "i43nwwnmfc5tced4jtuk4auuygqghud2yopx"
SERVER_LOOKUP_URL = "https://sfgame.net/config.json"


@dataclass
class ResponseVal:
    value: str
    sub_key: str

    def as_list(self) -> list[int]:
        raw = self.value.strip().strip("/")
        if not raw:
            return []
        return [int(item) for item in raw.split("/") if item]


@dataclass
class SessionState:
    username: str
    server_url: str
    session_id: str = DEFAULT_SESSION_ID
    crypto_id: str = DEFAULT_CRYPTO_ID
    player_id: int = 0

    def has_session_id(self) -> bool:
        return any(ch != "0" for ch in self.session_id)


class SFClient:
    def __init__(
        self,
        username: str,
        password: str,
        server_url: str,
        bearer_token: str | None = None,
    ) -> None:
        self.username = username.strip()
        self.password = password.strip()
        self.server_url = normalize_server_url(server_url)
        self.state = SessionState(username=username, server_url=self.server_url)
        self.http = requests.Session()
        self.bearer_token = bearer_token

    def login(self) -> Dict[str, ResponseVal]:
        resp = self._login_regular()
        self._update_state(resp)
        return resp

    def login_sso(self, uuid: str, character_id: str) -> Dict[str, ResponseVal]:
        cmd_args = f"{uuid}/{character_id}/unity3d_webglplayer//{APP_VERSION}"
        resp = self._send_command("SFAccountCharLogin", cmd_args)
        self._update_state(resp)
        return resp

    def poll(self) -> Dict[str, ResponseVal]:
        resp = self._send_command("Poll", "")
        self._update_state(resp)
        return resp

    def _send_command(self, cmd_name: str, cmd_args: str) -> Dict[str, ResponseVal]:
        encoded = base64.urlsafe_b64encode(cmd_args.encode("utf-8")).decode("utf-8")
        url = f"{self.server_url}cmd.php?req={cmd_name}&params={encoded}&sid={self.state.crypto_id}"
        headers = {
            "Referer": self.server_url,
            "PG-Player": str(self.state.player_id),
        }
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        if self.state.has_session_id():
            headers["PG-Session"] = self.state.session_id
        resp = self.http.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return parse_response(resp.text)

    def _update_state(self, resp: Dict[str, ResponseVal]) -> None:
        if "sessionid" in resp:
            self.state.session_id = resp["sessionid"].value
        if "cryptoid" in resp:
            self.state.crypto_id = resp["cryptoid"].value
        if "ownplayersave" in resp:
            parts = resp["ownplayersave"].value.split("/")
            if len(parts) > 1:
                try:
                    self.state.player_id = int(parts[1])
                except ValueError:
                    pass

    def _login_regular(self) -> Dict[str, ResponseVal]:
        pw_hash = sha1_hash(f"{self.password}{HASH_CONST}")
        login_count = 1
        full_hash = sha1_hash(f"{pw_hash}{login_count}")
        cmd_args = (
            f"{self.username}/{full_hash}/{login_count}/"
            f"unity3d_webglplayer//{APP_VERSION}///0/"
        )
        return self._send_command("AccountLogin", cmd_args)


def sha1_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def normalize_server_url(server: str) -> str:
    candidate = server.strip()
    if not candidate.startswith("http"):
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if not parsed.netloc:
        raise ValueError(f"Invalid server URL: {server}")
    if not candidate.endswith("/"):
        candidate = f"{candidate}/"
    return candidate


def parse_response(raw_body: str) -> Dict[str, ResponseVal]:
    body = raw_body.rstrip("|")
    body = body.lstrip("\n\r ")
    while body and not body[0].isalpha():
        body = body[1:]
    if not body:
        raise ValueError("Empty response body")
    if body.lower().startswith("error"):
        error_msg = body.split(":", 1)[1] if ":" in body else body
        raise ValueError(f"Server error: {error_msg}")

    resp: Dict[str, ResponseVal] = {}
    for part in body.split("&"):
        if not part:
            continue
        if ":" not in part:
            continue
        full_key, value = part.split(":", 1)
        if not full_key:
            continue
        if "." in full_key:
            key, sub_key = full_key.split(".", 1)
        elif "(" in full_key:
            key, sub_key = full_key.split("(", 1)
            sub_key = sub_key.rstrip(")")
        else:
            key, sub_key = full_key, ""
        if not key:
            continue
        resp[key] = ResponseVal(value=value, sub_key=sub_key)
    return resp


def sso_login(username: str, password: str) -> Tuple[str, str]:
    pw_hash = sha1_hash(f"{password}{HASH_CONST}")
    payload = {
        "username": username,
        "password": sha1_hash(f"{pw_hash}0"),
    }
    params = {"client_id": SSO_CLIENT_ID, "auth_type": "access_token"}
    resp = requests.post(
        f"{SSO_BASE_URL}/json/login",
        params=params,
        data=payload,
        headers={
            "Accept": "application/json",
            "Referer": SSO_BASE_URL,
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise ValueError("SSO login failed")
    payload_data = data.get("data") or data.get("message")
    if not payload_data:
        raise ValueError("SSO login missing data payload")
    try:
        bearer_token = payload_data["token"]["access_token"]
        uuid = payload_data["account"]["uuid"]
    except (KeyError, TypeError) as exc:
        raise ValueError("SSO login missing auth data") from exc
    return bearer_token, uuid


def sso_characters(bearer_token: str) -> list[dict]:
    resp = requests.get(
        f"{SSO_BASE_URL}/json/client/characters",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {bearer_token}",
            "Referer": SSO_BASE_URL,
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise ValueError("SSO characters request failed")
    payload_data = data.get("data") or data.get("message")
    if isinstance(payload_data, dict):
        payload_data = payload_data.get("characters")
    if not isinstance(payload_data, list):
        raise ValueError("Unexpected SSO characters response")
    return payload_data


def fetch_server_lookup() -> dict[int, str]:
    resp = requests.get(SERVER_LOOKUP_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    servers = data.get("servers", [])
    lookup: dict[int, str] = {}
    for server in servers:
        try:
            server_id = int(server["i"])
            host = server["d"]
        except (KeyError, TypeError, ValueError):
            continue
        lookup[server_id] = f"https://{host}"
    if not lookup:
        raise ValueError("Server lookup returned no servers")
    return lookup


def choose_character(
    characters: Iterable[dict],
    desired_name: str | None,
) -> dict:
    character_list = list(characters)
    if desired_name:
        for character in character_list:
            if character.get("name") == desired_name:
                return character
        raise ValueError(
            f"Character '{desired_name}' not found. Available: "
            f"{', '.join(sorted(c.get('name', '') for c in character_list))}"
        )
    if len(character_list) == 1:
        return character_list[0]
    raise ValueError(
        "Multiple characters found. Use --character to choose one: "
        f"{', '.join(sorted(c.get('name', '') for c in character_list))}"
    )


def extract_listing(resp: Dict[str, ResponseVal]) -> Tuple[int | None, int | None]:
    mushrooms = None
    level = None

    resources = resp.get("resources")
    if resources:
        res_list = resources.as_list()
        if len(res_list) > 1:
            mushrooms = res_list[1]

    player_save = resp.get("ownplayersave")
    if player_save:
        ps_list = player_save.as_list()
        if len(ps_list) > 7:
            level = ps_list[7] & 0xFFFF

    return mushrooms, level


def merge_listing(
    primary: Tuple[int | None, int | None],
    fallback: Tuple[int | None, int | None],
) -> Tuple[int | None, int | None]:
    mushrooms = primary[0] if primary[0] is not None else fallback[0]
    level = primary[1] if primary[1] is not None else fallback[1]
    return mushrooms, level


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="S&F login + basic listing (mushrooms/level)."
    )
    parser.add_argument("--username", required=True, help="Character name")
    parser.add_argument("--password", required=True, help="Character password")
    parser.add_argument(
        "--server",
        help="Server URL or hostname (e.g. f1.sfgame.net). Required for regular logins.",
    )
    parser.add_argument(
        "--sso",
        action="store_true",
        help="Use S&F account login (SSO) and pick a character.",
    )
    parser.add_argument(
        "--character",
        help="Character name to use with --sso (required if multiple chars).",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.sso:
            bearer_token, uuid = sso_login(args.username, args.password)
            characters = sso_characters(bearer_token)
            selected = choose_character(characters, args.character)
            server_lookup = fetch_server_lookup()
            server_id = int(selected["server_id"])
            server_url = server_lookup.get(server_id)
            if not server_url:
                raise ValueError(f"Unknown server id: {server_id}")
            client = SFClient(
                selected["name"],
                args.password,
                server_url,
                bearer_token=bearer_token,
            )
            login_resp = client.login_sso(uuid, selected["id"])
        else:
            if not args.server:
                raise ValueError("--server is required for regular logins")
            client = SFClient(args.username, args.password, args.server)
            login_resp = client.login()
        poll_resp = client.poll()
        mushrooms, level = merge_listing(
            extract_listing(poll_resp),
            extract_listing(login_resp),
        )
        print("Login OK.")
        print(f"Mushrooms: {mushrooms if mushrooms is not None else 'n/a'}")
        print(f"Level: {level if level is not None else 'n/a'}")
    except (requests.RequestException, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
