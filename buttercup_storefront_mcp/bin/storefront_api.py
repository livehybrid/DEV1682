"""REST endpoints backing the Buttercup Storefront MCP tools."""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any, Dict, List
from urllib.parse import parse_qs

import splunk.rest as splunk_rest
from splunk.persistconn.application import PersistentServerConnectionApplication


APP_ID = "buttercup_storefront_mcp"
SEARCH_ENDPOINT = f"/servicesNS/nobody/{APP_ID}/search/jobs/export"
SEARCH_TIMEOUT_SECONDS = 120
MAX_SESSIONS = 25

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


def _validate_limit(value: Any) -> int:
    if value is None or value == "":
        return 3
    if isinstance(value, bool):
        raise RequestValidationError("'limit' must be an integer.")

    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise RequestValidationError("'limit' must be an integer.") from exc

    if limit < 1 or limit > MAX_SESSIONS:
        raise RequestValidationError(
            f"'limit' must be between 1 and {MAX_SESSIONS}."
        )
    return limit


def _validate_outcome(value: Any) -> str:
    if value is None or value == "":
        return "completed"
    if not isinstance(value, str):
        raise RequestValidationError(
            "'outcome' must be one of: completed, error, all."
        )

    outcome = value.strip().lower()
    if outcome not in {"completed", "error", "all"}:
        raise RequestValidationError(
            "'outcome' must be one of: completed, error, all."
        )
    return outcome


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


class _BaseStorefrontHandler:
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
            logger.exception("Buttercup Storefront MCP search failed")
            return _error_response(500, "Unable to query Buttercup storefront data.")
        except Exception:
            logger.exception("Unexpected Buttercup Storefront MCP endpoint failure")
            return _error_response(500, "Unexpected endpoint failure.")

    def _handle_post(
        self,
        payload: Dict[str, Any],
        session_key: str,
    ) -> Dict[str, Any]:
        raise NotImplementedError


class StorefrontIPProfileHandler(_BaseStorefrontHandler):
    """Summarize storefront behavior for one IPv4 client."""

    def _handle_post(
        self,
        payload: Dict[str, Any],
        session_key: str,
    ) -> Dict[str, Any]:
        ip = _validate_ipv4(payload.get("ip"))
        search = (
            'search source="tutorialdata.zip:*" '
            'sourcetype="access_combined_wcookie" '
            f'earliest=0 latest=now "{ip}" '
            r'| rex field=_raw "^(?<bc_web_ip>\S+).*?\"'
            r'(?<bc_http_method>\S+) (?<bc_request_uri>\S+)" '
            f'| where bc_web_ip="{ip}" '
            '| eval bc_endpoint=mvindex(split(bc_request_uri,"?"),0) '
            r'| rex field=bc_request_uri "(?:[?&])action='
            r'(?<bc_request_action>[^&]+)" '
            r'| rex field=bc_request_uri "(?:[?&])productId='
            r'(?<bc_product_id>[^&]+)" '
            r'| rex field=bc_request_uri "(?:[?&])JSESSIONID='
            r'(?<bc_session_id>[^&]+)" '
            "| stats count AS requests "
            "dc(bc_session_id) AS sessions "
            "dc(bc_product_id) AS products_seen "
            'count(eval(bc_endpoint="/cart.do" AND '
            'bc_request_action="addtocart")) AS cart_add_requests '
            'count(eval(bc_endpoint="/cart.do" AND '
            'bc_request_action="purchase")) AS checkout_attempt_requests '
            'count(eval(bc_endpoint="/cart/success.do")) '
            "AS checkout_success_pages "
            'count(eval(bc_endpoint="/cart/error.do")) '
            "AS checkout_error_pages "
            'dc(eval(if(bc_endpoint="/cart/success.do",bc_session_id,null()))) '
            "AS completed_checkout_sessions "
            'dc(eval(if(bc_endpoint="/cart/error.do",bc_session_id,null()))) '
            "AS checkout_error_sessions "
            r'count(eval(match(bc_endpoint,"^/(passwords\.pdf|'
            r'hidden/anna_nicole\.html|rush/signals\.zip)$"))) '
            "AS notable_path_requests "
            r'values(eval(if(match(bc_endpoint,"^/(passwords\.pdf|'
            r'hidden/anna_nicole\.html|rush/signals\.zip)$"),'
            "bc_endpoint,null()))) AS notable_paths "
            "min(_time) AS first_seen max(_time) AS last_seen "
            "by bc_web_ip "
            "| rename bc_web_ip AS ip "
            "| convert ctime(first_seen) ctime(last_seen)"
        )

        rows = _run_export_search(session_key, search)
        if not rows:
            return {"ip": ip, "found": False, "profile": None}

        profile = _coerce_int_fields(
            rows[0],
            [
                "requests",
                "sessions",
                "products_seen",
                "cart_add_requests",
                "checkout_attempt_requests",
                "checkout_success_pages",
                "checkout_error_pages",
                "completed_checkout_sessions",
                "checkout_error_sessions",
                "notable_path_requests",
            ],
        )
        profile["notable_paths"] = _as_list(profile.get("notable_paths"))
        return {"ip": ip, "found": True, "profile": profile}


class StorefrontSessionsHandler(_BaseStorefrontHandler):
    """List bounded storefront session summaries for one IPv4 client."""

    def _handle_post(
        self,
        payload: Dict[str, Any],
        session_key: str,
    ) -> Dict[str, Any]:
        ip = _validate_ipv4(payload.get("ip"))
        limit = _validate_limit(payload.get("limit"))
        outcome = _validate_outcome(payload.get("outcome"))
        outcome_filter = (
            "" if outcome == "all" else f'| where outcome="{outcome}" '
        )

        search = (
            'search source="tutorialdata.zip:*" '
            'sourcetype="access_combined_wcookie" '
            f'earliest=0 latest=now "{ip}" '
            r'| rex field=_raw "^(?<bc_web_ip>\S+).*?\"'
            r'(?<bc_http_method>\S+) (?<bc_request_uri>\S+)" '
            f'| where bc_web_ip="{ip}" '
            '| eval bc_endpoint=mvindex(split(bc_request_uri,"?"),0) '
            r'| rex field=bc_request_uri "(?:[?&])action='
            r'(?<bc_request_action>[^&]+)" '
            r'| rex field=bc_request_uri "(?:[?&])productId='
            r'(?<bc_product_id>[^&]+)" '
            r'| rex field=bc_request_uri "(?:[?&])JSESSIONID='
            r'(?<bc_session_id>[^&]+)" '
            "| where isnotnull(bc_session_id) "
            "| stats count AS requests "
            'count(eval(bc_endpoint="/cart/success.do")) AS success_pages '
            'count(eval(bc_endpoint="/cart/error.do")) AS error_pages '
            'values(eval(if(bc_endpoint="/cart.do" AND '
            'bc_request_action="addtocart",bc_product_id,null()))) '
            "AS products_added "
            r'values(eval(if(match(bc_endpoint,"^/(passwords\.pdf|'
            r'hidden/anna_nicole\.html|rush/signals\.zip)$"),'
            "bc_endpoint,null()))) AS notable_paths "
            "min(_time) AS first_seen max(_time) AS last_seen "
            "by bc_session_id "
            '| eval outcome=case(success_pages>0,"completed",'
            'error_pages>0,"error",true(),"other") '
            f"{outcome_filter}"
            "| rename bc_session_id AS session_id "
            "| convert ctime(first_seen) ctime(last_seen) "
            "| sort 0 - success_pages - requests session_id "
            f"| head {limit}"
        )

        rows = _run_export_search(session_key, search)
        sessions: List[Dict[str, Any]] = []
        for row in rows:
            session = _coerce_int_fields(
                row,
                ["requests", "success_pages", "error_pages"],
            )
            session["products_added"] = _as_list(session.get("products_added"))
            session["notable_paths"] = _as_list(session.get("notable_paths"))
            sessions.append(session)

        return {
            "ip": ip,
            "outcome_filter": outcome,
            "sessions": sessions,
            "returned": len(sessions),
            "limit": limit,
        }


class StorefrontAPIHandler(PersistentServerConnectionApplication):
    """The single persistent handler required by Splunk's script loader."""

    _ROUTES = {
        "/buttercup/storefront/ip_profile": StorefrontIPProfileHandler,
        "/buttercup/storefront/sessions": StorefrontSessionsHandler,
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
        return _error_response(404, "Unknown Buttercup Storefront MCP endpoint.")
