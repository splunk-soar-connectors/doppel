# Copyright (c) 2025-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import time

import httpx
import pytest

import src.app as app_module
from src.app import Asset


class FakeAuthState:
    """Minimal stand-in for soar_sdk.asset_state.AssetState.

    SOARAssetOAuthClient only uses get_all()/put_all(), so a dict-backed
    fake is enough to exercise real token store/load/expiry logic.
    """

    def __init__(self) -> None:
        self._data: dict = {}

    def get_all(self) -> dict:
        return dict(self._data)

    def put_all(self, value: dict) -> None:
        self._data = dict(value)


@pytest.fixture
def api_key_asset() -> Asset:
    asset = Asset(doppel_api_key="test-api-key")
    asset._auth_state = FakeAuthState()
    return asset


@pytest.fixture
def oauth_asset() -> Asset:
    asset = Asset(client_id="test-client-id", client_secret="test-client-secret")
    asset._auth_state = FakeAuthState()
    return asset


class TokenEndpoint:
    """Fake https://api.doppel.com/oauth/token backed by httpx.MockTransport."""

    def __init__(self) -> None:
        self.mint_count = 0
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.mint_count += 1
        return httpx.Response(
            200,
            json={
                "access_token": f"token-{self.mint_count}",
                "token_type": "Bearer",
                "expires_in": 86400,
            },
        )


@pytest.fixture
def token_endpoint(monkeypatch: pytest.MonkeyPatch) -> TokenEndpoint:
    """Route the OAuth client's HTTP through a fake token endpoint.

    Wraps _oauth_client so the real SOARAssetOAuthClient (state persistence,
    expiry checks, mint requests) runs against httpx.MockTransport, keeping
    the attribution headers configured in the real implementation.
    """
    endpoint = TokenEndpoint()
    real_oauth_client = app_module._oauth_client

    def patched(asset: Asset):
        client = real_oauth_client(asset)
        client._http_client = httpx.Client(
            transport=httpx.MockTransport(endpoint.handler),
            headers=app_module.ATTRIBUTION_HEADERS,
        )
        return client

    monkeypatch.setattr(app_module, "_oauth_client", patched)
    return endpoint


class RecordedResponse:
    """Capture of one requests.request() call plus its canned response."""

    def __init__(self, kwargs: dict) -> None:
        self.kwargs = kwargs


class FakeDoppelApi:
    """Fake api.doppel.com for the requests-based API calls."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.responses: list[tuple[int, dict]] = []

    def queue(self, status_code: int, body: dict | None = None) -> None:
        self.responses.append((status_code, body or {}))

    def request(self, method: str, url: str, **kwargs) -> "FakeHttpResponse":
        self.calls.append({"method": method, "url": url, **kwargs})
        status, body = (
            self.responses.pop(0) if self.responses else (200, {"alerts": []})
        )
        return FakeHttpResponse(status, body)


class FakeHttpResponse:
    def __init__(self, status_code: int, body: dict) -> None:
        self.status_code = status_code
        self._body = body
        self.ok = 200 <= status_code < 300
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


@pytest.fixture
def doppel_api(monkeypatch: pytest.MonkeyPatch) -> FakeDoppelApi:
    api = FakeDoppelApi()
    monkeypatch.setattr(app_module.requests, "request", api.request)
    # Keep 429 retry tests fast if they ever queue one.
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    return api
