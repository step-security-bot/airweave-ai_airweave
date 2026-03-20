"""Tests for CustomAuthProvider."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from airweave.domains.auth_provider.exceptions import (
    AuthProviderAuthError,
    AuthProviderConfigError,
    AuthProviderMissingFieldsError,
    AuthProviderRateLimitError,
    AuthProviderTemporaryError,
)
from airweave.domains.auth_provider.providers.custom import CustomAuthProvider


@pytest.fixture
async def provider_bearer():
    """Create a Custom provider with bearer auth."""
    return await CustomAuthProvider.create(
        credentials={
            "endpoint_url": "https://api.example.com/tokens",
            "endpoint_auth_method": "bearer",
            "auth_value": "my-secret-token",
        }
    )


@pytest.fixture
async def provider_api_key():
    """Create a Custom provider with api_key_header auth."""
    return await CustomAuthProvider.create(
        credentials={
            "endpoint_url": "https://api.example.com/tokens",
            "endpoint_auth_method": "api_key_header",
            "api_key_header_name": "X-Custom-Key",
            "auth_value": "my-api-key",
        }
    )


@pytest.fixture
async def provider_none():
    """Create a Custom provider with no auth."""
    return await CustomAuthProvider.create(
        credentials={
            "endpoint_url": "https://api.example.com/tokens",
            "endpoint_auth_method": "none",
        }
    )


class TestCreate:
    """Tests for CustomAuthProvider.create()."""

    @pytest.mark.unit
    async def test_create_bearer(self, provider_bearer):
        assert provider_bearer.endpoint_url == "https://api.example.com/tokens"
        assert provider_bearer.endpoint_auth_method == "bearer"
        assert provider_bearer.auth_value == "my-secret-token"

    @pytest.mark.unit
    async def test_create_api_key_header(self, provider_api_key):
        assert provider_api_key.endpoint_auth_method == "api_key_header"
        assert provider_api_key.api_key_header_name == "X-Custom-Key"
        assert provider_api_key.auth_value == "my-api-key"

    @pytest.mark.unit
    async def test_create_no_auth(self, provider_none):
        assert provider_none.endpoint_auth_method == "none"
        assert provider_none.auth_value == ""

    @pytest.mark.unit
    async def test_create_defaults(self):
        provider = await CustomAuthProvider.create(
            credentials={"endpoint_url": "https://api.example.com/tokens"}
        )
        assert provider.endpoint_auth_method == "bearer"
        assert provider.api_key_header_name == "X-API-Key"
        assert provider.auth_value == ""


class TestBuildHeaders:
    """Tests for _build_headers()."""

    @pytest.mark.unit
    async def test_bearer_headers(self, provider_bearer):
        headers = provider_bearer._build_headers()
        assert headers["Content-Type"] == "application/json"
        assert headers["Authorization"] == "Bearer my-secret-token"

    @pytest.mark.unit
    async def test_api_key_headers(self, provider_api_key):
        headers = provider_api_key._build_headers()
        assert headers["Content-Type"] == "application/json"
        assert headers["X-Custom-Key"] == "my-api-key"
        assert "Authorization" not in headers

    @pytest.mark.unit
    async def test_no_auth_headers(self, provider_none):
        headers = provider_none._build_headers()
        assert headers == {"Content-Type": "application/json"}

    @pytest.mark.unit
    async def test_bearer_empty_value(self):
        provider = await CustomAuthProvider.create(
            credentials={
                "endpoint_url": "https://api.example.com/tokens",
                "endpoint_auth_method": "bearer",
                "auth_value": "",
            }
        )
        headers = provider._build_headers()
        assert "Authorization" not in headers


class TestGetCredsForSource:
    """Tests for get_creds_for_source()."""

    @pytest.mark.unit
    async def test_success(self, provider_bearer):
        mock_response = httpx.Response(
            200,
            json={"access_token": "eyJ-gdrive-token", "refresh_token": "rt-123"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            creds = await provider_bearer.get_creds_for_source(
                "google_drive",
                ["access_token"],
            )

        assert creds == {"access_token": "eyJ-gdrive-token"}

    @pytest.mark.unit
    async def test_post_body_includes_source(self, provider_bearer):
        mock_response = httpx.Response(
            200,
            json={"access_token": "token"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_post:
            await provider_bearer.get_creds_for_source("slack", ["access_token"])

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs["json"] == {"source": "slack"}

    @pytest.mark.unit
    async def test_optional_fields_not_required(self, provider_bearer):
        mock_response = httpx.Response(
            200,
            json={"access_token": "token"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            creds = await provider_bearer.get_creds_for_source(
                "google_drive",
                ["access_token", "refresh_token"],
                optional_fields={"refresh_token"},
            )

        assert creds == {"access_token": "token"}

    @pytest.mark.unit
    async def test_error_401(self, provider_bearer):
        mock_response = httpx.Response(
            401,
            json={"error": "unauthorized"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(AuthProviderAuthError, match="401"):
                await provider_bearer.get_creds_for_source("slack", ["access_token"])

    @pytest.mark.unit
    async def test_error_429(self, provider_bearer):
        mock_response = httpx.Response(
            429,
            json={"error": "rate limited"},
            headers={"retry-after": "60"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(AuthProviderRateLimitError) as exc_info:
                await provider_bearer.get_creds_for_source("slack", ["access_token"])
            assert exc_info.value.retry_after == 60.0

    @pytest.mark.unit
    async def test_error_500(self, provider_bearer):
        mock_response = httpx.Response(
            500,
            json={"error": "internal"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(AuthProviderTemporaryError, match="500"):
                await provider_bearer.get_creds_for_source("slack", ["access_token"])

    @pytest.mark.unit
    async def test_error_timeout(self, provider_bearer):
        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException("timed out"),
        ):
            with pytest.raises(AuthProviderTemporaryError, match="unreachable"):
                await provider_bearer.get_creds_for_source("slack", ["access_token"])

    @pytest.mark.unit
    async def test_error_missing_fields(self, provider_bearer):
        mock_response = httpx.Response(
            200,
            json={"some_other_field": "value"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(AuthProviderMissingFieldsError) as exc_info:
                await provider_bearer.get_creds_for_source("slack", ["access_token"])
            assert "access_token" in exc_info.value.missing_fields


class TestValidate:
    """Tests for validate()."""

    @pytest.mark.unit
    async def test_validate_success(self, provider_bearer):
        mock_response = httpx.Response(
            200,
            json={"access_token": "test-token"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            result = await provider_bearer.validate()

        assert result is True

    @pytest.mark.unit
    async def test_validate_missing_access_token(self, provider_bearer):
        mock_response = httpx.Response(
            200,
            json={"token": "test-token"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(AuthProviderConfigError, match="access_token"):
                await provider_bearer.validate()

    @pytest.mark.unit
    async def test_validate_auth_error(self, provider_bearer):
        mock_response = httpx.Response(
            401,
            json={"error": "unauthorized"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(AuthProviderAuthError):
                await provider_bearer.validate()

    @pytest.mark.unit
    async def test_validate_server_error(self, provider_bearer):
        mock_response = httpx.Response(
            503,
            json={"error": "unavailable"},
            request=httpx.Request("POST", "https://api.example.com/tokens"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(AuthProviderTemporaryError):
                await provider_bearer.validate()

    @pytest.mark.unit
    async def test_validate_timeout(self, provider_bearer):
        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException("timed out"),
        ):
            with pytest.raises(AuthProviderTemporaryError, match="unreachable"):
                await provider_bearer.validate()
