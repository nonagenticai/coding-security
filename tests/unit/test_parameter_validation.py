"""Tests for parameter validation utilities."""

import pytest
from fastapi import HTTPException

from utils.parameter_validation import (
    validate_path_parameter,
    validate_project_root,
    validate_string_parameter,
)


class TestValidateProjectRoot:
    def test_none_allowed(self):
        """None is allowed when allow_none=True."""
        result = validate_project_root(None, allow_none=True)
        assert result is None

    def test_none_not_allowed(self):
        """None raises HTTPException when allow_none=False."""
        with pytest.raises(HTTPException) as exc_info:
            validate_project_root(None, allow_none=False)
        assert exc_info.value.status_code == 400

    def test_null_string_allowed(self):
        """'null' string treated as None when allow_none=True."""
        result = validate_project_root("null", allow_none=True)
        assert result is None

    def test_none_string_allowed(self):
        """'none' string treated as None when allow_none=True."""
        result = validate_project_root("none", allow_none=True)
        assert result is None

    def test_null_string_not_allowed(self):
        """'null' string raises when allow_none=False."""
        with pytest.raises(HTTPException) as exc_info:
            validate_project_root("null", allow_none=False)
        assert exc_info.value.status_code == 400

    def test_empty_string_allowed(self):
        """Empty string treated as None when allow_none=True."""
        result = validate_project_root("", allow_none=True)
        assert result is None

    def test_absolute_path(self):
        """Valid absolute path returns Path object."""
        from pathlib import Path

        result = validate_project_root("/tmp/test")
        assert isinstance(result, Path), "Should return a Path object for absolute paths"
        assert str(result) == "/tmp/test"

    def test_relative_path_rejected(self):
        """Relative path raises HTTPException."""
        with pytest.raises(HTTPException) as exc_info:
            validate_project_root("relative/path")
        assert exc_info.value.status_code == 400

    def test_test_path(self):
        """Test paths are allowed."""
        from pathlib import Path

        result = validate_project_root("/tmp/test-project")
        assert isinstance(result, Path), "Known test paths should return Path objects"
        assert str(result) == "/tmp/test-project"


class TestValidatePathParameter:
    def test_none_allowed(self):
        """None returns None when allowed."""
        result = validate_path_parameter(None, "test_param", allow_none=True)
        assert result is None

    def test_none_not_allowed(self):
        """None raises when not allowed."""
        with pytest.raises(HTTPException) as exc_info:
            validate_path_parameter(None, "test_param", allow_none=False)
        assert exc_info.value.status_code == 400

    def test_absolute_path(self):
        """Absolute path accepted."""
        from pathlib import Path

        result = validate_path_parameter("/tmp/test", "test_param")
        assert isinstance(result, Path), "Absolute path should return Path object"
        assert str(result) == "/tmp/test"

    def test_relative_path_rejected(self):
        """Relative path raises 400."""
        with pytest.raises(HTTPException) as exc_info:
            validate_path_parameter("relative/path", "test_param")
        assert exc_info.value.status_code == 400

    def test_must_exist_true(self, tmp_path):
        """must_exist=True passes for existing path."""
        from pathlib import Path

        result = validate_path_parameter(str(tmp_path), "test_param", must_exist=True)
        assert isinstance(result, Path), "Existing path should return Path object"
        assert result == tmp_path

    def test_must_exist_false_for_nonexistent(self):
        """must_exist=True raises for nonexistent path."""
        with pytest.raises(HTTPException) as exc_info:
            validate_path_parameter("/definitely/not/real/path", "test_param", must_exist=True)
        assert exc_info.value.status_code == 400

    def test_empty_string_allowed(self):
        """Empty string returns None when allowed."""
        result = validate_path_parameter("", "test_param", allow_none=True)
        assert result is None

    def test_whitespace_only_allowed(self):
        """Whitespace-only returns None when allowed."""
        result = validate_path_parameter("   ", "test_param", allow_none=True)
        assert result is None


class TestValidateStringParameter:
    def test_none_allowed(self):
        """None returns None when allowed."""
        result = validate_string_parameter(None, "test_param", allow_none=True)
        assert result is None

    def test_none_not_allowed(self):
        """None raises when not allowed."""
        with pytest.raises(HTTPException) as exc_info:
            validate_string_parameter(None, "test_param", allow_none=False)
        assert exc_info.value.status_code == 400

    def test_min_length(self):
        """String shorter than min_length raises."""
        with pytest.raises(HTTPException) as exc_info:
            validate_string_parameter("ab", "test_param", min_length=5)
        assert exc_info.value.status_code == 400

    def test_max_length(self):
        """String longer than max_length raises."""
        with pytest.raises(HTTPException) as exc_info:
            validate_string_parameter("a" * 101, "test_param", max_length=100)
        assert exc_info.value.status_code == 400

    def test_allowed_values_valid(self):
        """Valid allowed value passes."""
        result = validate_string_parameter(
            "github", "platform", allowed_values={"github", "gitlab"}
        )
        assert result == "github"

    def test_allowed_values_invalid(self):
        """Invalid allowed value raises."""
        with pytest.raises(HTTPException) as exc_info:
            validate_string_parameter("travis", "platform", allowed_values={"github", "gitlab"})
        assert exc_info.value.status_code == 400

    def test_allowed_values_case_insensitive(self):
        """Allowed values check is case-insensitive."""
        result = validate_string_parameter(
            "GitHub", "platform", allowed_values={"github", "gitlab"}
        )
        assert result == "GitHub"

    def test_null_strings_not_allowed(self):
        """Null-like strings raise when not allowed."""
        with pytest.raises(HTTPException) as exc_info:
            validate_string_parameter("null", "test_param", allow_null_strings=False)
        assert exc_info.value.status_code == 400

    def test_null_strings_allowed(self):
        """Null-like strings pass when allowed."""
        result = validate_string_parameter("null", "test_param", allow_null_strings=True)
        assert result == "null"

    def test_whitespace_trimmed(self):
        """Whitespace is trimmed."""
        result = validate_string_parameter("  hello  ", "test_param")
        assert result == "hello"

    def test_empty_string_allowed(self):
        """Empty string returns None when allowed."""
        result = validate_string_parameter("", "test_param", allow_none=True)
        assert result is None

    def test_empty_string_not_allowed(self):
        """Empty string raises when not allowed."""
        with pytest.raises(HTTPException) as exc_info:
            validate_string_parameter("", "test_param", allow_none=False)
        assert exc_info.value.status_code == 400

    def test_valid_string(self):
        """Valid string returns cleaned value."""
        result = validate_string_parameter("hello", "test_param")
        assert result == "hello"
