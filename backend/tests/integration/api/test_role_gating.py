"""Integration tests for role-based HTTP method authorization (CASA-13/32).

Verifies that:
- Members are rejected from privileged API key and auth provider operations.
- Admins/owners are permitted.
- API key auth is explicitly blocked for API key management endpoints.
- System auth bypasses role checks (existing test fixtures keep working).
- Operational endpoints remain open to all roles (no regression).
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from airweave import schemas
from airweave.api.context import ApiContext
from airweave.api.deps import get_container, get_context
from airweave.db.session import get_db
from airweave.core.logging import logger
from airweave.core.shared_models import AuthMethod
from airweave.schemas.organization import Organization
from airweave.schemas.user import User, UserOrganization

TEST_ORG_ID = uuid4()
TEST_USER_ID = uuid4()
TEST_REQUEST_ID = "test-role-gating-000"


def _make_fake_context_with_role(
    role: str,
    auth_method: AuthMethod = AuthMethod.AUTH0,
) -> ApiContext:
    """Build an ApiContext carrying a user with the given org role."""
    now = datetime.now(timezone.utc)
    org = Organization(
        id=TEST_ORG_ID,
        name="Test Organization",
        created_at=now,
        modified_at=now,
    )

    if auth_method == AuthMethod.API_KEY:
        # API key auth has no user
        return ApiContext(
            request_id=TEST_REQUEST_ID,
            organization=org,
            auth_method=auth_method,
            user=None,
            logger=logger.with_context(request_id=TEST_REQUEST_ID),
        )

    user = User(
        id=TEST_USER_ID,
        email="testuser@example.com",
        full_name="Test User",
        user_organizations=[
            UserOrganization(
                user_id=TEST_USER_ID,
                organization_id=TEST_ORG_ID,
                organization=org,
                role=role,
                is_primary=True,
            ),
        ],
    )

    return ApiContext(
        request_id=TEST_REQUEST_ID,
        organization=org,
        auth_method=auth_method,
        user=user,
        logger=logger.with_context(request_id=TEST_REQUEST_ID),
    )


def _make_system_context() -> ApiContext:
    """Build a system-auth context (no user, bypasses role checks)."""
    now = datetime.now(timezone.utc)
    org = Organization(
        id=TEST_ORG_ID,
        name="Test Organization",
        created_at=now,
        modified_at=now,
    )
    return ApiContext(
        request_id=TEST_REQUEST_ID,
        organization=org,
        auth_method=AuthMethod.SYSTEM,
        user=None,
        logger=logger.with_context(request_id=TEST_REQUEST_ID),
    )


@pytest_asyncio.fixture
async def _role_client(test_container):
    """Yield a factory that creates an HTTP client with a specific role context."""
    from airweave.core import container as container_mod
    from airweave.main import app

    async def _fake_db():
        yield None

    async def _build(ctx: ApiContext) -> AsyncClient:
        app.dependency_overrides[get_container] = lambda: test_container
        app.dependency_overrides[get_context] = lambda: ctx
        app.dependency_overrides[get_db] = _fake_db
        prev_container = container_mod.container
        container_mod.container = test_container
        app.state.http_metrics = test_container.metrics.http
        transport = ASGITransport(app=app)
        client = AsyncClient(transport=transport, base_url="http://test")
        client._prev_container = prev_container  # stash for cleanup
        return client

    clients: list[AsyncClient] = []
    original_build = _build

    async def tracked_build(ctx: ApiContext) -> AsyncClient:
        c = await original_build(ctx)
        clients.append(c)
        return c

    yield tracked_build

    for c in clients:
        await c.aclose()

    from airweave.core import container as container_mod
    from airweave.main import app

    app.dependency_overrides.clear()
    if clients:
        container_mod.container = clients[0]._prev_container


# ---------------------------------------------------------------------------
# API key endpoint tests (CASA-32)
# ---------------------------------------------------------------------------


class TestApiKeyRoleGating:
    """API key endpoints require owner/admin and block API key auth."""

    @pytest.mark.asyncio
    async def test_member_create_api_key_rejected(self, _role_client):
        ctx = _make_fake_context_with_role("member")
        client = await _role_client(ctx)
        response = await client.post("/api-keys/", json={})
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_admin_create_api_key_allowed(self, _role_client):
        ctx = _make_fake_context_with_role("admin")
        client = await _role_client(ctx)
        response = await client.post("/api-keys/", json={})
        # Not 403 — the request may fail for other reasons (no DB) but
        # the role gate itself does not reject it.
        assert response.status_code != 403

    @pytest.mark.asyncio
    async def test_owner_delete_api_key_allowed(self, _role_client):
        ctx = _make_fake_context_with_role("owner")
        client = await _role_client(ctx)
        fake_id = str(uuid4())
        response = await client.delete(f"/api-keys/?id={fake_id}")
        assert response.status_code != 403

    @pytest.mark.asyncio
    async def test_api_key_auth_create_rejected(self, _role_client):
        ctx = _make_fake_context_with_role("", auth_method=AuthMethod.API_KEY)
        client = await _role_client(ctx)
        response = await client.post("/api-keys/", json={})
        assert response.status_code == 403
        assert "API key authentication is not permitted" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_system_auth_create_api_key_allowed(self, _role_client):
        ctx = _make_system_context()
        client = await _role_client(ctx)
        response = await client.post("/api-keys/", json={})
        assert response.status_code != 403


# ---------------------------------------------------------------------------
# Auth provider endpoint tests (CASA-13)
# ---------------------------------------------------------------------------


class TestAuthProviderRoleGating:
    """Mutating auth provider endpoints require owner/admin."""

    @pytest.mark.asyncio
    async def test_member_delete_auth_provider_rejected(self, _role_client):
        ctx = _make_fake_context_with_role("member")
        client = await _role_client(ctx)
        response = await client.delete("/auth-providers/some-provider")
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_admin_put_auth_provider_allowed(self, _role_client):
        ctx = _make_fake_context_with_role("admin")
        client = await _role_client(ctx)
        response = await client.put(
            "/auth-providers/some-provider",
            json={"auth_provider_short_name": "x", "credentials": {}},
        )
        assert response.status_code != 403

    @pytest.mark.asyncio
    async def test_member_list_auth_providers_allowed(self, _role_client):
        ctx = _make_fake_context_with_role("member")
        client = await _role_client(ctx)
        response = await client.get("/auth-providers/list")
        # Read endpoints remain open to all roles.
        assert response.status_code != 403


# ---------------------------------------------------------------------------
# Operational endpoint regression (no role restriction)
# ---------------------------------------------------------------------------


class TestOperationalEndpointsNoRegression:
    """Collections and other operational endpoints stay open to members."""

    @pytest.mark.asyncio
    async def test_member_list_collections_allowed(self, _role_client):
        ctx = _make_fake_context_with_role("member")
        client = await _role_client(ctx)
        response = await client.get("/collections/")
        assert response.status_code != 403
