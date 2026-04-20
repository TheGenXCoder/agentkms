"""
Unit tests for the honeytoken scope validator plugin.

These tests exercise the pure Python validation logic — no gRPC
infrastructure required. Run with:

    pytest test_plugin.py -v
"""

import pytest

from plugin import kind, narrow_scope, validate_params


# ── kind() ─────────────────────────────────────────────────────────────────────


def test_kind_returns_honeytoken() -> None:
    """Plugin reports the correct scope Kind."""
    assert kind() == "honeytoken"


# ── validate_params() ──────────────────────────────────────────────────────────


def test_validate_valid_scope() -> None:
    """A scope with name and purpose passes validation."""
    error = validate_params({"name": "prod-db-read", "purpose": "leak-detection"})
    assert error == ""


def test_validate_valid_scope_with_extra_params() -> None:
    """Extra params beyond name and purpose are silently allowed."""
    error = validate_params({
        "name": "s3-bucket-listing",
        "purpose": "insider-threat-test",
        "environment": "staging",
    })
    assert error == ""


def test_validate_missing_name() -> None:
    """A scope missing 'name' is rejected."""
    error = validate_params({"purpose": "leak-detection"})
    assert error != ""
    assert "name" in error


def test_validate_empty_name() -> None:
    """A scope with an empty 'name' string is rejected."""
    error = validate_params({"name": "", "purpose": "leak-detection"})
    assert error != ""
    assert "name" in error


def test_validate_whitespace_only_name() -> None:
    """A scope where 'name' is only whitespace is rejected."""
    error = validate_params({"name": "   ", "purpose": "leak-detection"})
    assert error != ""
    assert "name" in error


def test_validate_missing_purpose() -> None:
    """A scope missing 'purpose' is rejected."""
    error = validate_params({"name": "prod-db-read"})
    assert error != ""
    assert "purpose" in error


def test_validate_empty_purpose() -> None:
    """A scope with an empty 'purpose' string is rejected."""
    error = validate_params({"name": "prod-db-read", "purpose": ""})
    assert error != ""
    assert "purpose" in error


def test_validate_whitespace_only_purpose() -> None:
    """A scope where 'purpose' is only whitespace is rejected."""
    error = validate_params({"name": "prod-db-read", "purpose": "\t\n"})
    assert error != ""
    assert "purpose" in error


def test_validate_name_wrong_type() -> None:
    """A scope where 'name' is not a string is rejected."""
    error = validate_params({"name": 42, "purpose": "leak-detection"})
    assert error != ""
    assert "name" in error


def test_validate_purpose_wrong_type() -> None:
    """A scope where 'purpose' is not a string is rejected."""
    error = validate_params({"name": "prod-db-read", "purpose": ["oops"]})
    assert error != ""
    assert "purpose" in error


def test_validate_empty_params() -> None:
    """An empty params dict is rejected (both required fields missing)."""
    error = validate_params({})
    assert error != ""


# ── narrow_scope() ─────────────────────────────────────────────────────────────


def test_narrow_passes_through_unchanged() -> None:
    """Honeytoken scopes are not narrowed — requested params come back intact."""
    requested = {"name": "prod-db-read", "purpose": "leak-detection"}
    max_params = {"name": "prod-db-read", "purpose": "audit"}  # bounds (ignored)

    narrowed, error = narrow_scope(requested, max_params)

    assert error == ""
    assert narrowed == requested


def test_narrow_ignores_max_params() -> None:
    """The bounds max_params are irrelevant for honeytokens."""
    requested = {"name": "canary-token", "purpose": "exfil-detection"}
    max_params: dict = {}  # empty bounds — still passes through

    narrowed, error = narrow_scope(requested, max_params)

    assert error == ""
    assert narrowed == requested


def test_narrow_preserves_extra_params() -> None:
    """Any extra params in the requested scope survive narrowing."""
    requested = {
        "name": "s3-tripwire",
        "purpose": "cloud-exfil-test",
        "metadata": "extra",
    }
    narrowed, error = narrow_scope(requested, {})

    assert error == ""
    assert narrowed["metadata"] == "extra"
