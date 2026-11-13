"""Tests for BugAnalyzer service."""

import pytest

from models.bug_models import BugAnalysisResult, CodeFix, ErrorType, ParsedError
from services.bug_analysis import BugAnalyzer


def make_error(
    error_type: ErrorType = ErrorType.SYNTAX_ERROR,
    message: str = "test error",
    file_path: str | None = "app/main.py",
    line_number: int = 10,
    confidence: float = 0.9,
) -> ParsedError:
    return ParsedError(
        error_type=error_type,
        message=message,
        file_path=file_path,
        line_number=line_number,
        function_name="test_fn",
        stack_trace=[],
        confidence=confidence,
    )


def make_fix(
    file_path: str = "app/main.py",
    fixed_code: str = "x = 1",
    explanation: str = "Fix the bug",
    confidence: float = 0.9,
) -> CodeFix:
    return CodeFix(
        file_path=file_path,
        line_number=10,
        original_code="x = ",
        fixed_code=fixed_code,
        explanation=explanation,
        confidence=confidence,
    )


@pytest.fixture
def analyzer():
    return BugAnalyzer()


class TestAnalyzeRootCauses:
    def test_empty_errors(self, analyzer):
        result = analyzer.analyze_root_causes([], [])
        assert result == "No errors found to analyze."

    def test_single_error(self, analyzer):
        errors = [make_error(ErrorType.SYNTAX_ERROR)]
        result = analyzer.analyze_root_causes(errors, [])
        assert "Total Errors Found:** 1" in result
        assert "Syntax Error" in result

    def test_multiple_error_types(self, analyzer):
        errors = [
            make_error(ErrorType.SYNTAX_ERROR),
            make_error(ErrorType.IMPORT_ERROR, message="missing module"),
            make_error(ErrorType.NAME_ERROR, message="undefined var"),
        ]
        result = analyzer.analyze_root_causes(errors, [])
        assert "Total Errors Found:** 3" in result
        assert "Mixed error types" in result

    def test_most_problematic_file(self, analyzer):
        errors = [
            make_error(file_path="a.py"),
            make_error(file_path="b.py"),
            make_error(file_path="a.py", error_type=ErrorType.IMPORT_ERROR),
        ]
        result = analyzer.analyze_root_causes(errors, [])
        assert "`a.py`" in result
        assert "2 errors" in result

    def test_single_error_type_assessment(self, analyzer):
        errors = [
            make_error(ErrorType.SYNTAX_ERROR),
            make_error(ErrorType.SYNTAX_ERROR, file_path="b.py"),
        ]
        result = analyzer.analyze_root_causes(errors, [])
        assert "specific issue that can be systematically addressed" in result


class TestGenerateFixSummary:
    def test_empty_resolves(self, analyzer):
        result = analyzer.generate_fix_summary([])
        assert result == "No resolves generated."

    def test_groups_by_file(self, analyzer):
        resolves = [
            make_fix(file_path="a.py"),
            make_fix(file_path="b.py"),
            make_fix(file_path="a.py", explanation="Another fix"),
        ]
        result = analyzer.generate_fix_summary(resolves)
        assert "**a.py:** 2 resolves" in result
        assert "**b.py:** 1 resolves" in result

    def test_confidence_ordering(self, analyzer):
        resolves = [
            make_fix(confidence=0.9, explanation="High conf fix"),
            make_fix(confidence=0.6, explanation="Medium conf fix"),
            make_fix(confidence=0.3, explanation="Low conf fix"),
        ]
        result = analyzer.generate_fix_summary(resolves)
        assert "High-Confidence Resolves" in result
        assert "Medium-Confidence Resolves" in result
        assert "Low-Confidence Resolves" in result


class TestEstimateEffort:
    def test_empty_resolves(self, analyzer):
        result = analyzer.estimate_effort([])
        assert "No effort required" in result

    def test_simple_fix(self, analyzer):
        resolves = [make_fix(confidence=0.9, fixed_code="x=1")]
        result = analyzer.estimate_effort(resolves)
        assert "Basic resolves:** 1" in result
        assert "5 minutes" in result

    def test_moderate_fix(self, analyzer):
        resolves = [make_fix(confidence=0.6, fixed_code="x" * 200)]
        result = analyzer.estimate_effort(resolves)
        assert "Moderate resolves:** 1" in result

    def test_complex_fix(self, analyzer):
        resolves = [make_fix(confidence=0.3, fixed_code="x" * 300)]
        result = analyzer.estimate_effort(resolves)
        assert "Complex resolves:** 1" in result


class TestAssessRisks:
    def test_empty_resolves(self, analyzer):
        result = analyzer.assess_risks([])
        assert "No risks" in result

    def test_low_confidence_flagged(self, analyzer):
        resolves = [
            make_fix(confidence=0.3, file_path="core/base.py", explanation="Fix auth token")
        ]
        result = analyzer.assess_risks(resolves)
        # Low confidence (0.3 < 0.5 => +3) + core file (+2) + "auth"/"token" (+2) = 7 => high risk
        assert "High Risk:** 1" in result

    def test_core_file_changes_flagged(self, analyzer):
        resolves = [make_fix(confidence=0.4, file_path="core/main.py")]
        result = analyzer.assess_risks(resolves)
        # 0.4 < 0.5 => +3, "core" and "main" => +2, total 5 => high risk
        assert "High Risk:** 1" in result

    def test_low_risk_fix(self, analyzer):
        resolves = [make_fix(confidence=0.9, file_path="utils/helper.py", explanation="Fix typo")]
        result = analyzer.assess_risks(resolves)
        # confidence > 0.7 => +0, short code (<200) => +0, no core path => +0, no security term => +0 => low risk
        assert "Low Risk:** 1" in result


class TestAnalyzeBugsAndFixes:
    def test_returns_bug_analysis_result(self, analyzer):
        errors = [make_error()]
        resolves = [make_fix()]
        result = analyzer.analyze_bugs_and_fixes(errors, resolves)
        assert isinstance(result, BugAnalysisResult)
        assert result.errors == errors
        assert result.resolves == resolves
        assert "Root Cause Analysis" in result.root_cause_analysis
        assert "Resolve Summary" in result.fix_summary
        assert "Effort Estimation" in result.estimated_effort
        assert "Risk Assessment" in result.risk_assessment

    def test_empty_inputs(self, analyzer):
        result = analyzer.analyze_bugs_and_fixes([], [])
        assert isinstance(result, BugAnalysisResult)
        assert result.root_cause_analysis == "No errors found to analyze."
        assert result.fix_summary == "No resolves generated."


class TestAnalyzeRootCausesEdgeCases:
    def test_not_a_list_raises(self, analyzer):
        """Passing a non-list errors raises ValueError."""
        with pytest.raises(ValueError, match="Expected list"):
            analyzer.analyze_root_causes("not-a-list", [])

    def test_error_with_bad_attribute(self, analyzer):
        """Error object missing error_type.value is skipped gracefully."""
        bad_error = type("FakeError", (), {"error_type": None, "file_path": "a.py"})()
        good_error = make_error(ErrorType.SYNTAX_ERROR)
        result = analyzer.analyze_root_causes([good_error, bad_error], [])
        assert "Total Errors Found:** 2" in result
        # Only the good error's type should appear
        assert "Syntax Error" in result

    def test_more_than_5_error_types(self, analyzer):
        """More than 5 error types triggers systemic issues assessment."""
        errors = [
            make_error(ErrorType.SYNTAX_ERROR),
            make_error(ErrorType.IMPORT_ERROR, message="m1"),
            make_error(ErrorType.NAME_ERROR, message="m2"),
            make_error(ErrorType.TYPE_ERROR, message="m3"),
            make_error(ErrorType.ATTRIBUTE_ERROR, message="m4"),
            make_error(ErrorType.INDEX_ERROR, message="m5"),
        ]
        result = analyzer.analyze_root_causes(errors, [])
        assert "systemic issues" in result

    def test_confidence_distribution_in_output(self, analyzer):
        """Confidence distribution is shown when resolves are provided."""
        errors = [make_error()]
        resolves = [
            make_fix(confidence=0.9),
            make_fix(confidence=0.6),
            make_fix(confidence=0.3),
        ]
        result = analyzer.analyze_root_causes(errors, resolves)
        assert "High confidence" in result
        assert "Medium confidence" in result
        assert "Low confidence" in result

    def test_no_file_path_errors(self, analyzer):
        """Errors with no file_path don't appear in file patterns."""
        errors = [make_error(file_path=None)]
        result = analyzer.analyze_root_causes(errors, [])
        assert "Most problematic file" not in result


class TestGenerateFixSummaryEdgeCases:
    def test_not_a_list_raises(self, analyzer):
        with pytest.raises(ValueError, match="Expected list"):
            analyzer.generate_fix_summary("not-a-list")

    def test_bad_resolve_object_skipped_in_grouping(self, analyzer):
        """Resolve object with bad file_path attribute is skipped during grouping
        but still counted in the total."""
        # Give it a low confidence so it falls into "low" bucket and avoids detail iteration
        bad_fix = type("FakeFix", (), {"confidence": 0.3})()
        good_fix = make_fix(confidence=0.9, explanation="Good fix")
        result = analyzer.generate_fix_summary([good_fix, bad_fix])
        assert "Total Resolves:** 2" in result
        assert "app/main.py" in result

    def test_only_medium_confidence(self, analyzer):
        """Only medium confidence fixes."""
        resolves = [make_fix(confidence=0.6, explanation="Medium fix")]
        result = analyzer.generate_fix_summary(resolves)
        assert "Medium-Confidence Resolves" in result
        assert "High-Confidence Resolves" not in result

    def test_only_low_confidence(self, analyzer):
        """Only low confidence fixes."""
        resolves = [make_fix(confidence=0.3)]
        result = analyzer.generate_fix_summary(resolves)
        assert "Low-Confidence Resolves" in result
        assert "manual review" in result

    def test_many_high_confidence_only_shows_top5(self, analyzer):
        """Only first 5 high confidence resolves are shown."""
        resolves = [make_fix(confidence=0.9, explanation=f"Fix {i}") for i in range(7)]
        result = analyzer.generate_fix_summary(resolves)
        assert "Fix 4" in result
        # The 6th and 7th (Fix 5, Fix 6) should not appear in the high-confidence section

    def test_many_medium_confidence_only_shows_top3(self, analyzer):
        """Only first 3 medium confidence resolves are shown."""
        resolves = [make_fix(confidence=0.6, explanation=f"MedFix {i}") for i in range(5)]
        result = analyzer.generate_fix_summary(resolves)
        assert "MedFix 2" in result


class TestEstimateEffortEdgeCases:
    def test_not_a_list_raises(self, analyzer):
        with pytest.raises(ValueError, match="Expected list"):
            analyzer.estimate_effort("not-a-list")

    def test_bad_resolve_defaults_to_complex(self, analyzer):
        """Resolve with bad attributes defaults to complex."""
        bad_fix = type("FakeFix", (), {})()  # No confidence or fixed_code
        result = analyzer.estimate_effort([bad_fix])
        assert "Complex resolves:** 1" in result

    def test_mixed_complexity(self, analyzer):
        """Mix of simple, moderate, and complex fixes."""
        resolves = [
            make_fix(confidence=0.9, fixed_code="x=1"),  # simple: high conf, short code
            make_fix(confidence=0.6, fixed_code="x" * 50),  # moderate: >0.5 conf
            make_fix(confidence=0.3, fixed_code="x" * 300),  # complex: <0.5 conf
        ]
        result = analyzer.estimate_effort(resolves)
        assert "Basic resolves:** 1" in result
        assert "Moderate resolves:** 1" in result
        assert "Complex resolves:** 1" in result
        # 5 + 15 + 30 = 50 minutes = 0h 50m
        assert "0h 50m" in result

    def test_recommendations_all_present(self, analyzer):
        resolves = [
            make_fix(confidence=0.9, fixed_code="x"),
            make_fix(confidence=0.6, fixed_code="x" * 50),
            make_fix(confidence=0.3, fixed_code="x" * 300),
        ]
        result = analyzer.estimate_effort(resolves)
        assert "quick wins" in result
        assert "moderate-confidence" in result
        assert "extra time" in result
        assert "Test each" in result
        assert "small batches" in result

    def test_only_simple_fixes_recommendations(self, analyzer):
        resolves = [make_fix(confidence=0.9, fixed_code="x")]
        result = analyzer.estimate_effort(resolves)
        assert "quick wins" in result
        # Should not have moderate or complex recommendations
        assert "extra time" not in result

    def test_hours_calculation(self, analyzer):
        """Many fixes produce hours estimate."""
        # 20 complex fixes: 20 * 30 = 600 minutes = 10h 0m
        resolves = [make_fix(confidence=0.3, fixed_code="x" * 300) for _ in range(20)]
        result = analyzer.estimate_effort(resolves)
        assert "10h 0m" in result


class TestAssessRisksEdgeCases:
    def test_not_a_list_raises(self, analyzer):
        with pytest.raises(ValueError, match="Expected list"):
            analyzer.assess_risks("not-a-list")

    def test_bad_resolve_defaults_to_medium(self, analyzer):
        """Resolve with bad attributes defaults to medium risk.
        The error handler catches AttributeError and adds to medium_risk_fixes.
        But the details loop also accesses file_path/explanation, so we give
        just enough attributes for it to survive the detail display."""
        bad_fix = type("FakeFix", (), {"file_path": "unknown.py", "explanation": "unknown"})()
        # This will fail in the risk scoring loop (no confidence), defaulting to medium
        result = analyzer.assess_risks([bad_fix])
        assert "Medium Risk:** 1" in result

    def test_medium_risk_large_code(self, analyzer):
        """Large code change with decent confidence => medium risk."""
        resolves = [
            make_fix(
                confidence=0.65,
                fixed_code="x" * 250,
                file_path="utils/helper.py",
                explanation="Refactor loop",
            )
        ]
        result = analyzer.assess_risks(resolves)
        # confidence 0.65 < 0.7 => +1, code > 200 => +2, no core => +0, no security => +0 => 3 >= 2 => medium
        assert "Medium Risk:** 1" in result

    def test_security_term_in_explanation(self, analyzer):
        """Security terms in explanation increase risk."""
        resolves = [
            make_fix(
                confidence=0.9,
                file_path="utils/helper.py",
                explanation="Fix password validation",
            )
        ]
        result = analyzer.assess_risks(resolves)
        # confidence > 0.7 => +0, short code => +0, no core path => +0, "password" => +2 => medium
        assert "Medium Risk:** 1" in result

    def test_high_risk_shows_details(self, analyzer):
        """High risk fixes show file paths and explanations."""
        resolves = [
            make_fix(
                confidence=0.3,
                file_path="core/base.py",
                explanation="Fix auth token issue",
            )
        ]
        result = analyzer.assess_risks(resolves)
        assert "High-Risk Resolves" in result
        assert "core/base.py" in result
        assert "Special Precautions" in result

    def test_medium_risk_shows_details(self, analyzer):
        """Medium risk fixes show details."""
        resolves = [
            make_fix(
                confidence=0.65,
                file_path="utils/helper.py",
                explanation="Fix performance issue",
                fixed_code="x" * 250,
            )
        ]
        result = analyzer.assess_risks(resolves)
        assert "Medium-Risk Resolves" in result
        assert "utils/helper.py" in result

    def test_no_high_risk_no_special_precautions(self, analyzer):
        """No high risk means no special precautions section."""
        resolves = [make_fix(confidence=0.9, file_path="utils/helper.py", explanation="Fix typo")]
        result = analyzer.assess_risks(resolves)
        assert "Special Precautions" not in result

    def test_multiple_security_terms(self, analyzer):
        """Multiple security terms in explanation."""
        resolves = [
            make_fix(
                confidence=0.4,
                file_path="core/config.py",
                explanation="Fix security auth permission token",
            )
        ]
        result = analyzer.assess_risks(resolves)
        # conf < 0.5 => +3, core+config => +2, security+auth+permission+token => +2 => 7 => high risk
        assert "High Risk:** 1" in result


class TestAnalyzeContainer:
    @pytest.mark.asyncio
    async def test_valid_container(self, analyzer):
        """Valid container analysis returns expected structure."""
        result = await analyzer.analyze_container(
            "my-container", "Error: something went wrong\nerror: another issue"
        )
        assert result["container_context"]["container_name"] == "my-container"
        assert result["container_context"]["error_count"] == 2
        assert result["container_context"]["log_size"] > 0
        assert isinstance(result["errors"], list)
        assert isinstance(result["resolves"], list)
        assert isinstance(result["analysis"], BugAnalysisResult)
        assert result["file_mappings"] == {}

    @pytest.mark.asyncio
    async def test_invalid_container_name(self, analyzer):
        """Empty container name raises ValueError."""
        with pytest.raises(ValueError, match="Invalid container_name"):
            await analyzer.analyze_container("", "some errors")

    @pytest.mark.asyncio
    async def test_none_container_name(self, analyzer):
        """None container name raises ValueError."""
        with pytest.raises(ValueError, match="Invalid container_name"):
            await analyzer.analyze_container(None, "some errors")

    @pytest.mark.asyncio
    async def test_invalid_error_logs(self, analyzer):
        """Empty error logs raises ValueError."""
        with pytest.raises(ValueError, match="Invalid error_logs"):
            await analyzer.analyze_container("my-container", "")

    @pytest.mark.asyncio
    async def test_none_error_logs(self, analyzer):
        """None error logs raises ValueError."""
        with pytest.raises(ValueError, match="Invalid error_logs"):
            await analyzer.analyze_container("my-container", None)

    @pytest.mark.asyncio
    async def test_non_string_container_name(self, analyzer):
        """Non-string container name raises ValueError."""
        with pytest.raises(ValueError, match="Invalid container_name"):
            await analyzer.analyze_container(123, "some errors")


class TestGenerateFixes:
    @pytest.mark.asyncio
    async def test_empty_list(self, analyzer):
        """Empty bug list returns empty fixes."""
        result = await analyzer.generate_fixes([])
        assert result == []

    @pytest.mark.asyncio
    async def test_not_a_list_raises(self, analyzer):
        """Non-list input raises ValueError."""
        with pytest.raises(ValueError, match="Expected list"):
            await analyzer.generate_fixes("not-a-list")

    @pytest.mark.asyncio
    async def test_syntax_error_fix(self, analyzer):
        """Generates fix for syntax error."""
        bugs = [make_error(ErrorType.SYNTAX_ERROR, message="invalid syntax", file_path="test.py")]
        fixes = await analyzer.generate_fixes(bugs)
        assert len(fixes) == 1
        assert fixes[0].file_path == "test.py"
        assert fixes[0].confidence == 0.7
        assert "syntax" in fixes[0].explanation.lower()

    @pytest.mark.asyncio
    async def test_import_error_fix(self, analyzer):
        """Generates fix for import error."""
        bugs = [make_error(ErrorType.IMPORT_ERROR, message="No module named requests")]
        fixes = await analyzer.generate_fixes(bugs)
        assert len(fixes) == 1
        assert fixes[0].confidence == 0.8
        assert "import" in fixes[0].explanation.lower()

    @pytest.mark.asyncio
    async def test_name_error_fix(self, analyzer):
        """Generates fix for name error."""
        bugs = [make_error(ErrorType.NAME_ERROR, message="name 'x' is not defined")]
        fixes = await analyzer.generate_fixes(bugs)
        assert len(fixes) == 1
        assert fixes[0].confidence == 0.6

    @pytest.mark.asyncio
    async def test_unmapped_error_type_gets_default_fix(self, analyzer):
        """Error type not in templates gets default fix."""
        bugs = [make_error(ErrorType.RUNTIME_ERROR, message="runtime issue")]
        fixes = await analyzer.generate_fixes(bugs)
        assert len(fixes) == 1
        assert fixes[0].confidence == 0.5
        assert "Manual review" in fixes[0].test_suggestion

    @pytest.mark.asyncio
    async def test_multiple_bugs(self, analyzer):
        """Multiple bugs produce multiple fixes."""
        bugs = [
            make_error(ErrorType.SYNTAX_ERROR),
            make_error(ErrorType.IMPORT_ERROR, message="missing module"),
            make_error(ErrorType.RUNTIME_ERROR, message="crash"),
        ]
        fixes = await analyzer.generate_fixes(bugs)
        assert len(fixes) == 3

    @pytest.mark.asyncio
    async def test_non_parsed_error_skipped(self, analyzer):
        """Non-ParsedError objects are skipped."""
        bugs = [make_error(ErrorType.SYNTAX_ERROR), "not-an-error"]
        fixes = await analyzer.generate_fixes(bugs)
        assert len(fixes) == 1

    @pytest.mark.asyncio
    async def test_error_with_no_file_path(self, analyzer):
        """Error with None file_path uses default."""
        bugs = [make_error(ErrorType.SYNTAX_ERROR, file_path=None)]
        # Need to update the ParsedError's file_path to None
        bugs[0] = ParsedError(
            error_type=ErrorType.SYNTAX_ERROR,
            message="test",
            file_path=None,
            line_number=1,
            function_name=None,
            stack_trace=[],
            confidence=0.9,
        )
        fixes = await analyzer.generate_fixes(bugs)
        assert len(fixes) == 1
        assert fixes[0].file_path == "unknown.py"


class TestGenerateFixForError:
    def test_syntax_error(self, analyzer):
        error = make_error(ErrorType.SYNTAX_ERROR)
        fix = analyzer._generate_fix_for_error(error)
        assert isinstance(fix, CodeFix), "Should return a CodeFix for syntax errors"
        assert fix.confidence == 0.7
        assert "syntax" in fix.explanation.lower()
        assert fix.test_suggestion == "Run linter to verify syntax"
        assert fix.file_path == "app/main.py"

    def test_import_error(self, analyzer):
        error = make_error(ErrorType.IMPORT_ERROR, message="No module 'x'")
        fix = analyzer._generate_fix_for_error(error)
        assert isinstance(fix, CodeFix), "Should return a CodeFix for import errors"
        assert fix.confidence == 0.8
        assert "import" in fix.explanation.lower()
        assert fix.test_suggestion == "Verify dependency is installed"
        assert fix.file_path == "app/main.py"

    def test_name_error(self, analyzer):
        error = make_error(ErrorType.NAME_ERROR, message="undefined var")
        fix = analyzer._generate_fix_for_error(error)
        assert isinstance(fix, CodeFix), "Should return a CodeFix for name errors"
        assert fix.confidence == 0.6
        assert "name" in fix.explanation.lower() or "undefined" in fix.explanation.lower()
        assert fix.test_suggestion == "Add variable/function definition"

    def test_default_error_type(self, analyzer):
        error = make_error(ErrorType.KEY_ERROR, message="missing key")
        fix = analyzer._generate_fix_for_error(error)
        assert isinstance(fix, CodeFix), "Should return a CodeFix for unmapped error types"
        assert fix.confidence == 0.5
        assert "key_error" in fix.explanation.lower()
        assert "Manual review" in fix.test_suggestion

    def test_broken_error_returns_none(self, analyzer):
        """Error that raises exception returns None."""
        bad_error = type("FakeError", (), {})()  # No error_type or file_path
        fix = analyzer._generate_fix_for_error(bad_error)
        assert fix is None


class TestAnalyzeBugsAndFixesEdgeCases:
    def test_full_analysis_with_fixes(self, analyzer):
        """Full analysis with multiple errors and fixes."""
        errors = [
            make_error(ErrorType.SYNTAX_ERROR),
            make_error(ErrorType.IMPORT_ERROR, message="missing", file_path="b.py"),
        ]
        resolves = [
            make_fix(confidence=0.9, explanation="Fix syntax"),
            make_fix(confidence=0.4, explanation="Fix import"),
        ]
        result = analyzer.analyze_bugs_and_fixes(errors, resolves)
        assert isinstance(result, BugAnalysisResult)
        assert len(result.errors) == 2
        assert len(result.resolves) == 2
        assert "Root Cause Analysis" in result.root_cause_analysis
        assert "Resolve Summary" in result.fix_summary
        assert "Effort Estimation" in result.estimated_effort
        assert "Risk Assessment" in result.risk_assessment
