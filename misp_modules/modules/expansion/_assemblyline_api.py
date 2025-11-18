import json
from typing import Any, Dict, Optional

import requests

# Contributions: Adam McHugh <adam@mchughcyber.com.au>


class AssemblyLineError(Exception):
    """Exception raised when the AssemblyLine API returns an error."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class AssemblyLineAPI:
    """Minimal AssemblyLine API wrapper built on top of requests."""

    def __init__(self, base_url: str, *, verify: bool = True, timeout: Optional[int] = 30):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify
        self.timeout = timeout
        self._auth_payload: Optional[Dict[str, Any]] = None

    def authenticate(
        self, *, user: str, apikey: Optional[str] = None, password: Optional[str] = None
    ) -> Dict[str, Any]:
        if not user:
            raise AssemblyLineError("Missing AssemblyLine user identifier.")
        if apikey:
            payload = {"user": user, "apikey": apikey}
        elif password:
            payload = {"user": user, "password": password}
        else:
            raise AssemblyLineError("Provide an AssemblyLine API key or password.")

        response = self.session.post(
            self._build_url("/api/v4/auth/login/"),
            json=payload,
            timeout=self.timeout,
        )
        data = self._decode_response(response)

        xsrf_token = self.session.cookies.get("XSRF-TOKEN")
        if xsrf_token:
            self.session.headers["X-XSRF-TOKEN"] = xsrf_token

        self.session.headers.setdefault("Content-Type", "application/json")
        session_duration = data.get("session_duration")
        if session_duration:
            self.session.timeout = session_duration

        self._auth_payload = {"user": user, "apikey": apikey, "password": password}
        return data

    def get_json(self, path: str, *, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request_json("get", path, params=params)

    def post_json(self, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request_json("post", path, json=payload)

    def post_multipart(
        self,
        path: str,
        *,
        data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        headers = self.session.headers.copy()
        headers.pop("Content-Type", None)
        response = self.session.post(
            self._build_url(path),
            data=data,
            files=files,
            headers=headers,
            timeout=self.timeout,
        )
        return self._decode_response(response)

    # ------------------------------------------------------------------ #
    # Internal helpers                                                   #
    # ------------------------------------------------------------------ #

    def _request_json(self, method: str, path: str, retry: bool = True, **kwargs) -> Dict[str, Any]:
        requester = getattr(self.session, method)
        response = requester(
            self._build_url(path),
            timeout=self.timeout,
            **kwargs,
        )
        if response.status_code == 401 and retry and self._auth_payload:
            self.authenticate(**self._auth_payload)
            return self._request_json(method, path, retry=False, **kwargs)
        return self._decode_response(response)

    def _decode_response(self, response: requests.Response) -> Dict[str, Any]:
        if response.ok:
            try:
                body = response.json()
            except ValueError as error:
                raise AssemblyLineError("AssemblyLine returned invalid JSON.", response.status_code) from error
            if isinstance(body, dict) and "api_response" in body:
                body = body["api_response"]
            if isinstance(body, (dict, list, bool, int, float, str)):
                return body
            raise AssemblyLineError("Unexpected AssemblyLine response format.", response.status_code)

        message = self._extract_error_message(response)
        raise AssemblyLineError(message, response.status_code)

    @staticmethod
    def _extract_error_message(response: requests.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            body = None

        if isinstance(body, dict):
            for key in ("api_error_message", "error", "message"):
                if body.get(key):
                    return str(body[key])
        return response.text or f"AssemblyLine request failed with HTTP {response.status_code}"

    def _build_url(self, path: str) -> str:
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self.base_url}{path}"
