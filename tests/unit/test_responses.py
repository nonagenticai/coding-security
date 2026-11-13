"""Tests for response helper functions."""

from typing import cast

from models.responses import (
    bad_request,
    conflict,
    error_response,
    forbidden,
    internal_error,
    not_found,
    rate_limited,
    service_unavailable,
    success_response,
    timeout_error,
    unauthorized,
    validation_error,
)


class TestSuccessResponse:
    def test_default_message(self):
        result = success_response(data={"x": 1})
        assert result["status"] == "success"
        assert result["message"] == "Success"
        assert result["data"] == {"x": 1}

    def test_custom_message(self):
        result = success_response(data={}, message="Done")
        assert result["message"] == "Done"


class TestErrorResponse:
    def test_structure(self):
        exc = error_response(500, "fail", "ERR")
        assert exc.status_code == 500
        detail = cast(dict, exc.detail)
        assert detail["message"] == "fail"
        assert detail["error_code"] == "ERR"
        assert detail["status"] == "error"


class TestNotFound:
    def test_404(self):
        exc = not_found("User", "123")
        assert exc.status_code == 404
        detail = cast(dict, exc.detail)
        assert "User" in detail["message"]
        assert "123" in detail["message"]


class TestBadRequest:
    def test_400(self):
        exc = bad_request("Invalid input")
        assert exc.status_code == 400
        assert cast(dict, exc.detail)["error_code"] == "BAD_REQUEST"


class TestValidationError:
    def test_422(self):
        exc = validation_error("bad field", "name")
        assert exc.status_code == 422
        assert cast(dict, exc.detail)["details"]["field"] == "name"


class TestInternalError:
    def test_500(self):
        exc = internal_error("DB down")
        assert exc.status_code == 500


class TestUnauthorized:
    def test_401(self):
        exc = unauthorized()
        assert exc.status_code == 401
        assert cast(dict, exc.detail)["error_code"] == "UNAUTHORIZED"


class TestForbidden:
    def test_403(self):
        exc = forbidden("No access")
        assert exc.status_code == 403
        assert cast(dict, exc.detail)["error_code"] == "FORBIDDEN"


class TestConflict:
    def test_409(self):
        exc = conflict("Container", "Already exists")
        assert exc.status_code == 409


class TestServiceUnavailable:
    def test_503(self):
        exc = service_unavailable()
        assert exc.status_code == 503


class TestTimeoutError:
    def test_504(self):
        exc = timeout_error()
        assert exc.status_code == 504
        assert cast(dict, exc.detail)["error_code"] == "TIMEOUT"


class TestRateLimited:
    def test_429(self):
        exc = rate_limited()
        assert exc.status_code == 429
        assert cast(dict, exc.detail)["error_code"] == "RATE_LIMITED"
