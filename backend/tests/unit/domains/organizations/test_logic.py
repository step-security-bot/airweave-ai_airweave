"""Unit tests for organization permission predicates."""

import pytest

from airweave.domains.organizations.logic import (
    can_manage_api_keys,
    can_manage_auth_providers,
    can_manage_members,
)


@pytest.mark.parametrize(
    "role, expected",
    [
        ("owner", True),
        ("admin", True),
        ("member", False),
        ("", False),
        ("unknown", False),
    ],
)
class TestPermissionPredicates:
    """All three management predicates share the same owner/admin gate."""

    def test_can_manage_api_keys(self, role: str, expected: bool) -> None:
        assert can_manage_api_keys(role) is expected

    def test_can_manage_auth_providers(self, role: str, expected: bool) -> None:
        assert can_manage_auth_providers(role) is expected

    def test_can_manage_members(self, role: str, expected: bool) -> None:
        assert can_manage_members(role) is expected
