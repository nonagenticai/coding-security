"""Tests for the CVE-driven upgrade picker algorithm."""

from __future__ import annotations

import pytest

from models.architecture_models import Vulnerability
from services.dependency_upgrade import constraint_allows, pick_safest_fix_version


def _v(vuln_id: str, fixed: list[str], *, severity: str = "HIGH") -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        severity=severity,
        summary="",
        details="",
        affected_versions=[],
        fixed_versions=fixed,
        references=[],
        published_date="",
        modified_date="",
        package_name="httpx",
    )


class TestPickSafestFixVersion:
    def test_single_vuln_single_fix(self):
        vulns = [_v("CVE-1", ["1.5.0"])]
        assert pick_safest_fix_version("1.0.0", vulns) == "1.5.0"

    def test_two_vulns_picks_max_of_minimums(self):
        # Vuln A is cleared by >=1.5.0; Vuln B is cleared by >=2.0.0.
        # The smallest version that clears BOTH is 2.0.0.
        vulns = [_v("CVE-A", ["1.5.0"]), _v("CVE-B", ["2.0.0"])]
        assert pick_safest_fix_version("1.0.0", vulns) == "2.0.0"

    def test_single_vuln_multiple_fixes_picks_smallest_above_installed(self):
        # Multiple branch fixes — patch in 1.5.x, in 2.x, and in 3.x.
        # Installed on 1.4.0 → 1.5.0 is the smallest sufficient bump.
        vulns = [_v("CVE-1", ["1.5.0", "2.0.0", "3.0.0"])]
        assert pick_safest_fix_version("1.4.0", vulns) == "1.5.0"

    def test_installed_already_past_all_fixes_returns_none(self):
        vulns = [_v("CVE-1", ["1.5.0"])]
        assert pick_safest_fix_version("2.0.0", vulns) is None

    def test_wildcard_fix_returns_none(self):
        vulns = [_v("CVE-1", ["*"])]
        assert pick_safest_fix_version("1.0.0", vulns) is None

    def test_empty_fix_list_returns_none(self):
        vulns = [_v("CVE-1", [])]
        assert pick_safest_fix_version("1.0.0", vulns) is None

    def test_one_unfixable_among_others_returns_none(self):
        # If ANY vuln is unfixable, we can't clear all of them — return None.
        vulns = [_v("CVE-A", ["1.5.0"]), _v("CVE-B", [])]
        assert pick_safest_fix_version("1.0.0", vulns) is None

    def test_no_vulns_returns_none(self):
        assert pick_safest_fix_version("1.0.0", []) is None


class TestConstraintAllows:
    @pytest.mark.parametrize(
        "constraint,target,expected",
        [
            (">=0.25,<1.0", "0.27.0", True),
            (">=0.25,<1.0", "1.0.0", False),  # excluded upper bound
            (">=2.13.0,<3.0.0", "3.0.0", False),  # the fastmcp case
            (">=2.13.0,<3.0.0", "2.14.2", True),
            (None, "anything", True),  # missing constraint = permissive
            ("", "anything", True),
            (">=1.0", "0.5.0", False),
            ("not-a-constraint", "1.0.0", True),  # unparsable → permissive (safety net)
        ],
    )
    def test_constraint_allows_cases(self, constraint, target, expected):
        assert constraint_allows(constraint, target) is expected
