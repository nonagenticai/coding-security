"""Tests that public endpoints don't require authentication."""


class TestPublicEndpoints:
    def test_health_no_auth(self, test_client):
        """Health endpoint works without auth headers."""
        response = test_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_root_no_auth(self, test_client):
        """Root endpoint works without auth headers."""
        response = test_client.get("/")
        assert response.status_code == 200

    def test_docs_available_in_test(self, test_client):
        """Docs endpoint available when ENABLE_DOCS=true."""
        response = test_client.get("/openapi.json")
        assert response.status_code == 200
