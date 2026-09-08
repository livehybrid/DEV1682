"""REST endpoints backing the Buttercup Security MCP tools."""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any, Dict, List
from urllib.parse import parse_qs

import splunk.rest as splunk_rest
from splunk.persistconn.application import PersistentServerConnectionApplication


APP_ID = "buttercup_security_mcp"
SEARCH_ENDPOINT = f"/servicesNS/nobody/{APP_ID}/search/jobs/export"
SEARCH_TIMEOUT_SECONDS = 120
MAX_ATTACKERS = 25
MAX_TARGETS = 25
MAX_TARGET_PAIR_ROWS = 1000

logger = logging.getLogger(__name__)


class RequestValidationError(ValueError):
    """Raised when an endpoint receives an invalid caller argument."""


class SearchExecutionError(RuntimeError):
    """Raised when Splunk cannot execute or decode an endpoint search."""


def _response(status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": status,
        "headers": {"Content-Type": "application/json; charset=UTF-8"},
        "payload": payload,
    }


def _error_response(status: int, message: str) -> Dict[str, Any]:
    return _response(status, {"error": True, "message": message})


def _extract_session_key(request: Dict[str, Any]) -> str:
    session = request.get("session")
    if isinstance(session, dict):
        token = session.get("authtoken")
        if isinstance(token, str) and token:
            return token

    for key in ("system_authtoken", "systemAuthtoken"):
        token = request.get(key)
        if isinstance(token, str) and token:
            return token
    return ""


def _parse_payload(raw_payload: Any) -> Dict[str, Any]:
    if raw_payload is None or raw_payload == "":
        return {}
    if isinstance(raw_payload, dict):
        return raw_payload
    if not isinstance(raw_payload, str):
        raise RequestValidationError("Request body must be a JSON object.")

    text = raw_payload.strip()
    if not text:
        return {}

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        form = parse_qs(text, keep_blank_values=True)
        payload = {
            key: values[0] if len(values) == 1 else values
            for key, values in form.items()
        }

    if not isinstance(payload, dict):
        raise RequestValidationError("Request body must be a JSON object.")
    return payload


def _validate_ipv4(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RequestValidationError("'ip' is required and must be an IPv4 address.")

    candidate = value.strip()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise RequestValidationError("'ip' must be a valid IPv4 address.") from exc

    if address.version != 4:
        raise RequestValidationError("'ip' must be a valid IPv4 address.")
    return str(address)


def _validate_limit(
    value: Any,
    *,
    default: int,
    maximum: int,
) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise RequestValidationError("'limit' must be an integer.")

    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise RequestValidationError("'limit' must be an integer.") from exc

    if limit < 1 or limit > maximum:
        raise RequestValidationError(
            f"'limit' must be between 1 and {maximum}."
        )
    return limit


def _decode_export_results(content: Any) -> List[Dict[str, Any]]:
    if isinstance(content, bytes):
        text = content.decode("utf-8", errors="replace")
    else:
        text = str(content)

    results: List[Dict[str, Any]] = []
    errors: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SearchExecutionError(
                "Splunk returned an invalid search response."
            ) from exc

        result = record.get("result")
        if isinstance(result, dict):
            results.append(result)

        for message in record.get("messages", []):
            if not isinstance(message, dict):
                continue
            if str(message.get("type", "")).upper() in {"ERROR", "FATAL"}:
                errors.append(str(message.get("text", "Search failed.")))

    if errors and not results:
        raise SearchExecutionError(" ".join(errors))
    return results


def _run_export_search(session_key: str, search: str) -> List[Dict[str, Any]]:
    try:
        response, content = splunk_rest.simpleRequest(
            path=SEARCH_ENDPOINT,
            method="POST",
            sessionKey=session_key,
            postargs={
                "search": search,
                "output_mode": "json",
                "preview": "false",
                "provenance": f"MCP:{APP_ID}",
            },
            rawResult=True,
            raiseAllErrors=True,
            timeout=SEARCH_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        raise SearchExecutionError("Splunk search execution failed.") from exc

    status = int(getattr(response, "status", 500))
    if status != 200:
        raise SearchExecutionError(
            f"Splunk search execution failed with HTTP status {status}."
        )
    return _decode_export_results(content)


def _coerce_int_fields(row: Dict[str, Any], field_names: List[str]) -> Dict[str, Any]:
    normalized = dict(row)
    for field_name in field_names:
        value = normalized.get(field_name)
        if value in (None, ""):
            normalized[field_name] = 0
            continue
        try:
            normalized[field_name] = int(value)
        except (TypeError, ValueError):
            pass
    return normalized


def _as_list(value: Any) -> List[Any]:
    if value in (None, ""):
        return []
    return value if isinstance(value, list) else [value]


class _BaseSecurityHandler:
    """Common request, authentication, and error handling."""

    def __init__(self, _command_line: Any, _command_arg: Any) -> None:
        pass

    def handle(self, in_string: str) -> Dict[str, Any]:
        try:
            request = json.loads(in_string)
        except (TypeError, json.JSONDecodeError):
            return _error_response(400, "Request envelope must be valid JSON.")

        if not isinstance(request, dict):
            return _error_response(400, "Request envelope must be a JSON object.")
        if str(request.get("method", "")).upper() != "POST":
            return _error_response(405, "Only POST is supported.")

        session_key = _extract_session_key(request)
        if not session_key:
            return _error_response(401, "A valid Splunk session is required.")

        try:
            payload = _parse_payload(request.get("payload"))
            result = self._handle_post(payload, session_key)
            return _response(200, result)
        except RequestValidationError as exc:
            return _error_response(400, str(exc))
        except SearchExecutionError:
            logger.exception("Buttercup Security MCP search failed")
            return _error_response(500, "Unable to query Buttercup security data.")
        except Exception:
            logger.exception("Unexpected Buttercup Security MCP endpoint failure")
            return _error_response(500, "Unexpected endpoint failure.")

    def _handle_post(
        self,
        payload: Dict[str, Any],
        session_key: str,
    ) -> Dict[str, Any]:
        raise NotImplementedError


class RankSSHAttackersHandler(_BaseSecurityHandler):
    """Rank source IPs by failed SSH authentication volume."""

    def _handle_post(
        self,
        payload: Dict[str, Any],
        session_key: str,
    ) -> Dict[str, Any]:
        limit = _validate_limit(
            payload.get("limit"),
            default=5,
            maximum=MAX_ATTACKERS,
        )

        search = (
            'search source="tutorialdata.zip:*" sourcetype="secure-2" '
            'earliest=0 latest=now "Failed password" '
            r'| rex field=_raw "(?i)failed password for (?:invalid user )?'
            r'(?<bc_ssh_username>[^ ]+) from '
            r'(?<bc_ssh_src_ip>\d{1,3}(?:\.\d{1,3}){3}) port" '
            "| where isnotnull(bc_ssh_src_ip) "
            "| stats count AS failed_logins "
            "dc(bc_ssh_username) AS targeted_usernames "
            "dc(host) AS target_hosts "
            "min(_time) AS first_seen max(_time) AS last_seen "
            "by bc_ssh_src_ip "
            "| rename bc_ssh_src_ip AS ip "
            "| convert ctime(first_seen) ctime(last_seen) "
            "| sort 0 - failed_logins ip "
            f"| head {limit}"
        )

        attackers = [
            _coerce_int_fields(
                row,
                ["failed_logins", "targeted_usernames", "target_hosts"],
            )
            for row in _run_export_search(session_key, search)
        ]
        return {
            "attackers": attackers,
            "returned": len(attackers),
            "limit": limit,
        }


class SSHSourceProfileHandler(_BaseSecurityHandler):
    """Summarize failed and accepted SSH activity for one source IP."""

    def _handle_post(
        self,
        payload: Dict[str, Any],
        session_key: str,
    ) -> Dict[str, Any]:
        ip = _validate_ipv4(payload.get("ip"))
        search = (
            'search source="tutorialdata.zip:*" sourcetype="secure-2" '
            f'earliest=0 latest=now "{ip}" '
            r'| rex field=_raw "(?i)(?<bc_ssh_outcome>failed|accepted) '
            r'password for (?:invalid user )?(?<bc_ssh_username>[^ ]+) '
            r'from (?<bc_ssh_src_ip>\d{1,3}(?:\.\d{1,3}){3}) port" '
            f'| where bc_ssh_src_ip="{ip}" '
            "| eval bc_ssh_outcome=lower(bc_ssh_outcome) "
            "| stats count AS authentication_events "
            'count(eval(bc_ssh_outcome="failed")) AS failed_logins '
            'count(eval(bc_ssh_outcome="accepted")) AS successful_logins '
            "dc(bc_ssh_username) AS usernames "
            "dc(host) AS target_hosts values(host) AS target_host_names "
            "min(_time) AS first_seen max(_time) AS last_seen "
            "by bc_ssh_src_ip "
            "| rename bc_ssh_src_ip AS ip "
            "| convert ctime(first_seen) ctime(last_seen)"
        )

        rows = _run_export_search(session_key, search)
        if not rows:
            return {"ip": ip, "found": False, "profile": None}

        profile = _coerce_int_fields(
            rows[0],
            [
                "authentication_events",
                "failed_logins",
                "successful_logins",
                "usernames",
                "target_hosts",
            ],
        )
        profile["target_host_names"] = _as_list(profile.get("target_host_names"))
        return {"ip": ip, "found": True, "profile": profile}


class SSHSourceTargetsHandler(_BaseSecurityHandler):
    """Return host and username targeting summaries for one source IP."""

    def _handle_post(
        self,
        payload: Dict[str, Any],
        session_key: str,
    ) -> Dict[str, Any]:
        ip = _validate_ipv4(payload.get("ip"))
        limit = _validate_limit(
            payload.get("limit"),
            default=10,
            maximum=MAX_TARGETS,
        )

        search = (
            'search source="tutorialdata.zip:*" sourcetype="secure-2" '
            f'earliest=0 latest=now "Failed password" "{ip}" '
            r'| rex field=_raw "(?i)failed password for (?:invalid user )?'
            r'(?<bc_ssh_username>[^ ]+) from '
            r'(?<bc_ssh_src_ip>\d{1,3}(?:\.\d{1,3}){3}) port" '
            f'| where bc_ssh_src_ip="{ip}" '
            "| stats count AS failed_logins by host bc_ssh_username "
            "| rename host AS target_host bc_ssh_username AS username "
            "| sort 0 - failed_logins target_host username "
            f"| head {MAX_TARGET_PAIR_ROWS}"
        )

        pair_rows = _run_export_search(session_key, search)
        hosts: Dict[str, Dict[str, Any]] = {}
        usernames: Dict[str, Dict[str, Any]] = {}

        for row in pair_rows:
            host = str(row.get("target_host", ""))
            username = str(row.get("username", ""))
            try:
                failed_logins = int(row.get("failed_logins", 0))
            except (TypeError, ValueError):
                failed_logins = 0

            host_summary = hosts.setdefault(
                host,
                {
                    "target_host": host,
                    "failed_logins": 0,
                    "_usernames": set(),
                },
            )
            host_summary["failed_logins"] += failed_logins
            host_summary["_usernames"].add(username)

            username_summary = usernames.setdefault(
                username,
                {
                    "username": username,
                    "failed_logins": 0,
                    "_hosts": set(),
                },
            )
            username_summary["failed_logins"] += failed_logins
            username_summary["_hosts"].add(host)

        host_results = [
            {
                "target_host": item["target_host"],
                "failed_logins": item["failed_logins"],
                "targeted_usernames": len(item["_usernames"]),
            }
            for item in hosts.values()
        ]
        host_results.sort(
            key=lambda item: (-item["failed_logins"], item["target_host"])
        )

        username_results = [
            {
                "username": item["username"],
                "failed_logins": item["failed_logins"],
                "target_hosts": len(item["_hosts"]),
            }
            for item in usernames.values()
        ]
        username_results.sort(
            key=lambda item: (-item["failed_logins"], item["username"])
        )

        return {
            "ip": ip,
            "hosts": host_results[:limit],
            "usernames": username_results[:limit],
            "total_hosts": len(host_results),
            "total_usernames": len(username_results),
            "limit": limit,
        }


class SecurityAPIHandler(PersistentServerConnectionApplication):
    """The single persistent handler required by Splunk's script loader."""

    _ROUTES = {
        "/buttercup/security/rank_ssh_attackers": RankSSHAttackersHandler,
        "/buttercup/security/ssh_source_profile": SSHSourceProfileHandler,
        "/buttercup/security/ssh_source_targets": SSHSourceTargetsHandler,
    }

    def __init__(self, _command_line: Any, _command_arg: Any) -> None:
        super().__init__()

    def handle(self, in_string: str) -> Dict[str, Any]:
        try:
            request = json.loads(in_string)
        except (TypeError, json.JSONDecodeError):
            return _error_response(400, "Request envelope must be valid JSON.")

        if not isinstance(request, dict):
            return _error_response(400, "Request envelope must be a JSON object.")
        request_path = str(
            request.get("rest_path") or request.get("path_info") or ""
        ).split("?", 1)[0].rstrip("/")
        for route_suffix, handler_class in self._ROUTES.items():
            if request_path.endswith(route_suffix):
                return handler_class("", "").handle(in_string)
        return _error_response(404, "Unknown Buttercup Security MCP endpoint.")
