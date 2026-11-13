"""Tests for tenant isolation."""


class TestTenantIsolation:
    def test_default_tenant_used(self, test_client):
        """Without X-Tenant-Id header, default tenant is used."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "x = 1", "language": "python"},
        )
        # Should succeed with default tenant
        assert response.status_code == 200

    def test_custom_tenant(self, test_client):
        """Custom X-Tenant-Id header is accepted."""
        response = test_client.post(
            "/api/security/validate",
            json={"code": "x = 1", "language": "python"},
            headers={"X-Tenant-Id": "custom-tenant"},
        )
        assert response.status_code == 200

    def test_tenant_from_query_param(self, test_client):
        """Tenant can be provided via query param."""
        response = test_client.post(
            "/api/security/validate?tenant_id=query-tenant",
            json={"code": "x = 1", "language": "python"},
        )
        assert response.status_code == 200
