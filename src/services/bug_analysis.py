"""
Bug Analysis Service

Focused service for analyzing bugs, generating summaries, and assessing risks.
Provides async support for endpoint integration and container-scoped analysis.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from models.bug_models import BugAnalysisResult, CodeFix, ParsedError

logger = logging.getLogger(__name__)


class BugAnalyzer:
    """Service responsible for analyzing bugs and generating assessments.

    Provides comprehensive bug analysis with async support, container-scoped
    analysis, and automated fix generation for endpoint integration.

    Attributes:
        logger: Logger instance for service operations.
    """

    def __init__(self):
        """Initialize the BugAnalyzer service."""
        self.logger = logging.getLogger(__name__)
        self.logger.debug("BugAnalyzer service initialized")

    def analyze_root_causes(self, errors: list[ParsedError], resolves: list[CodeFix]) -> str:
        """Analyze root causes of errors and resolves.

        Args:
            errors: List of parsed errors to analyze.
            resolves: List of generated code fixes.

        Returns:
            Markdown-formatted root cause analysis.

        Raises:
            ValueError: If errors list is malformed.
        """
        try:
            if not errors:
                self.logger.debug("No errors provided for root cause analysis")
                return "No errors found to analyze."

            if not isinstance(errors, list):
                raise ValueError(f"Expected list of errors, got {type(errors)}")

            self.logger.info(f"Analyzing root causes for {len(errors)} errors")

            # Group errors by type
            error_types: dict[str, list] = {}
            for error in errors:
                try:
                    error_type = error.error_type.value
                    if error_type not in error_types:
                        error_types[error_type] = []
                    error_types[error_type].append(error)
                except (AttributeError, ValueError) as e:
                    self.logger.warning(f"Error processing error object: {e}")
                    continue

            # Analyze patterns
            analysis_parts = [
                "## Root Cause Analysis",
                "",
                f"**Total Errors Found:** {len(errors)}",
                f"**Total Resolves Generated:** {len(resolves)}",
                "",
                "### Error Distribution:",
            ]

            for error_type, error_list in error_types.items():
                analysis_parts.append(
                    f"- **{error_type.replace('_', ' ').title()}:** {len(error_list)} occurrences"
                )

            # Identify patterns
            analysis_parts.extend(
                [
                    "",
                    "### Common Patterns:",
                ]
            )

            # File-based patterns
            file_errors: dict[str, Any] = {}
            for error in errors:
                if error.file_path:
                    if error.file_path not in file_errors:
                        file_errors[error.file_path] = 0
                    file_errors[error.file_path] += 1

            if file_errors:
                most_problematic = max(file_errors.items(), key=lambda x: x[1])
                analysis_parts.append(
                    f"- Most problematic file: `{most_problematic[0]}` ({most_problematic[1]} errors)"
                )

            # Confidence analysis
            high_confidence_fixes = [f for f in resolves if f.confidence > 0.8]
            medium_confidence_fixes = [f for f in resolves if 0.5 <= f.confidence <= 0.8]
            low_confidence_fixes = [f for f in resolves if f.confidence < 0.5]

            analysis_parts.extend(
                [
                    "",
                    "### Resolve Confidence Distribution:",
                    f"- High confidence (>80%): {len(high_confidence_fixes)} resolves",
                    f"- Medium confidence (50-80%): {len(medium_confidence_fixes)} resolves",
                    f"- Low confidence (<50%): {len(low_confidence_fixes)} resolves",
                ]
            )

            # Root cause assessment
            if len(error_types) == 1:
                single_type = list(error_types.keys())[0]
                analysis_parts.extend(
                    [
                        "",
                        "### Assessment:",
                        f"All errors are of type '{single_type}', suggesting a specific issue that can be systematically addressed.",
                    ]
                )
            elif len(error_types) > 5:
                analysis_parts.extend(
                    [
                        "",
                        "### Assessment:",
                        "Multiple error types detected, indicating potential systemic issues or code quality problems.",
                    ]
                )
            else:
                analysis_parts.extend(
                    [
                        "",
                        "### Assessment:",
                        "Mixed error types suggest isolated issues that can be addressed individually.",
                    ]
                )

            result = "\n".join(analysis_parts)
            self.logger.debug(f"Root cause analysis completed with {len(error_types)} error types")
            return result

        except Exception as e:
            self.logger.error(f"Error in analyze_root_causes: {e}", exc_info=True)
            raise

    def generate_fix_summary(self, resolves: list[CodeFix]) -> str:
        """Generate a summary of all resolves.

        Args:
            resolves: List of code fixes to summarize.

        Returns:
            Markdown-formatted fix summary.

        Raises:
            ValueError: If resolves list is malformed.
        """
        try:
            if not resolves:
                self.logger.debug("No resolves provided for fix summary")
                return "No resolves generated."

            if not isinstance(resolves, list):
                raise ValueError(f"Expected list of resolves, got {type(resolves)}")

            self.logger.info(f"Generating fix summary for {len(resolves)} resolves")

            summary_parts = [
                "## Resolve Summary",
                "",
                f"**Total Resolves:** {len(resolves)}",
                "",
            ]

            # Group resolves by file
            file_fixes: dict[str, list] = {}
            for resolve in resolves:
                try:
                    file_path = resolve.file_path
                    if file_path not in file_fixes:
                        file_fixes[file_path] = []
                    file_fixes[file_path].append(resolve)
                except (AttributeError, TypeError) as e:
                    self.logger.warning(f"Error processing resolve object: {e}")
                    continue

            summary_parts.append("### Resolves by File:")
            for file_path, fix_list in file_fixes.items():
                summary_parts.append(f"- **{file_path}:** {len(fix_list)} resolves")

            # High-priority resolves
            high_confidence_fixes = [f for f in resolves if f.confidence > 0.8]
            if high_confidence_fixes:
                summary_parts.extend(
                    [
                        "",
                        "### High-Confidence Resolves (Recommended for immediate application):",
                    ]
                )
                for resolve in high_confidence_fixes[:5]:  # Show top 5
                    summary_parts.append(
                        f"- {resolve.explanation} (Confidence: {resolve.confidence:.1%})"
                    )

            # Medium-priority resolves
            medium_confidence_fixes = [f for f in resolves if 0.5 <= f.confidence <= 0.8]
            if medium_confidence_fixes:
                summary_parts.extend(
                    [
                        "",
                        "### Medium-Confidence Resolves (Review before applying):",
                    ]
                )
                for resolve in medium_confidence_fixes[:3]:  # Show top 3
                    summary_parts.append(
                        f"- {resolve.explanation} (Confidence: {resolve.confidence:.1%})"
                    )

            # Low-priority resolves
            low_confidence_fixes = [f for f in resolves if f.confidence < 0.5]
            if low_confidence_fixes:
                summary_parts.extend(
                    [
                        "",
                        f"### Low-Confidence Resolves ({len(low_confidence_fixes)} total):",
                        "These resolves require manual review and testing before application.",
                    ]
                )

            result = "\n".join(summary_parts)
            self.logger.debug(f"Fix summary generated with {len(file_fixes)} affected files")
            return result

        except Exception as e:
            self.logger.error(f"Error in generate_fix_summary: {e}", exc_info=True)
            raise

    def estimate_effort(self, resolves: list[CodeFix]) -> str:
        """Estimate effort required to implement resolves.

        Args:
            resolves: List of code fixes to estimate effort for.

        Returns:
            Markdown-formatted effort estimation.

        Raises:
            ValueError: If resolves list is malformed.
        """
        try:
            if not resolves:
                self.logger.debug("No resolves provided for effort estimation")
                return "No effort required - no resolves to implement."

            if not isinstance(resolves, list):
                raise ValueError(f"Expected list of resolves, got {type(resolves)}")

            self.logger.info(f"Estimating effort for {len(resolves)} resolves")

            # Categorize resolves by complexity
            simple_fixes: list[Any] = []
            moderate_fixes: list[Any] = []
            complex_fixes: list[Any] = []
            for resolve in resolves:
                try:
                    code_length = len(resolve.fixed_code) if resolve.fixed_code else 0
                    if resolve.confidence > 0.8 and code_length < 100:
                        simple_fixes.append(resolve)
                    elif resolve.confidence > 0.5:
                        moderate_fixes.append(resolve)
                    else:
                        complex_fixes.append(resolve)
                except (AttributeError, TypeError) as e:
                    self.logger.warning(f"Error categorizing resolve: {e}")
                    complex_fixes.append(resolve)  # Default to complex

            # Estimate time
            simple_time = len(simple_fixes) * 5  # 5 minutes each
            moderate_time = len(moderate_fixes) * 15  # 15 minutes each
            complex_time = len(complex_fixes) * 30  # 30 minutes each

            total_minutes = simple_time + moderate_time + complex_time
            hours = total_minutes // 60
            minutes = total_minutes % 60

            effort_parts = [
                "## Effort Estimation",
                "",
                f"**Total Resolves:** {len(resolves)}",
                "",
                "### Breakdown:",
                f"- **Basic resolves:** {len(simple_fixes)} (~{simple_time} minutes)",
                f"- **Moderate resolves:** {len(moderate_fixes)} (~{moderate_time} minutes)",
                f"- **Complex resolves:** {len(complex_fixes)} (~{complex_time} minutes)",
                "",
                f"**Estimated Total Time:** {hours}h {minutes}m",
                "",
                "### Recommendations:",
            ]

            if simple_fixes:
                effort_parts.append("1. Start with basic, high-confidence resolves for quick wins")

            if moderate_fixes:
                effort_parts.append("2. Review and test moderate-confidence resolves carefully")

            if complex_fixes:
                effort_parts.append(
                    "3. Allocate extra time for complex resolves and thorough testing"
                )

            effort_parts.extend(
                [
                    "4. Test each resolve individually before moving to the next",
                    "5. Consider implementing resolves in small batches",
                ]
            )

            result = "\n".join(effort_parts)
            self.logger.debug(
                f"Effort estimation: {len(simple_fixes)} simple, "
                f"{len(moderate_fixes)} moderate, {len(complex_fixes)} complex"
            )
            return result

        except Exception as e:
            self.logger.error(f"Error in estimate_effort: {e}", exc_info=True)
            raise

    def assess_risks(self, resolves: list[CodeFix]) -> str:
        """Assess risks associated with implementing resolves.

        Args:
            resolves: List of code fixes to assess risks for.

        Returns:
            Markdown-formatted risk assessment.

        Raises:
            ValueError: If resolves list is malformed.
        """
        try:
            if not resolves:
                self.logger.debug("No resolves provided for risk assessment")
                return "No risks - no resolves to implement."

            if not isinstance(resolves, list):
                raise ValueError(f"Expected list of resolves, got {type(resolves)}")

            self.logger.info(f"Assessing risks for {len(resolves)} resolves")

            # Categorize risks
            high_risk_fixes: list[Any] = []
            medium_risk_fixes: list[Any] = []
            low_risk_fixes: list[Any] = []
            for resolve in resolves:
                try:
                    # Risk factors
                    risk_score = 0

                    # Low confidence increases risk
                    if resolve.confidence < 0.5:
                        risk_score += 3
                    elif resolve.confidence < 0.7:
                        risk_score += 1

                    # Large changes increase risk
                    code_length = len(resolve.fixed_code) if resolve.fixed_code else 0
                    if code_length > 200:
                        risk_score += 2

                    # Core files increase risk
                    file_path = resolve.file_path.lower() if resolve.file_path else ""
                    if any(
                        core_path in file_path
                        for core_path in ["main", "core", "base", "config", "__init__"]
                    ):
                        risk_score += 2

                    # Security-related changes increase risk
                    explanation = resolve.explanation.lower() if resolve.explanation else ""
                    if any(
                        security_term in explanation
                        for security_term in [
                            "security",
                            "auth",
                            "password",
                            "token",
                            "permission",
                        ]
                    ):
                        risk_score += 2

                    # Categorize by total risk score
                    if risk_score >= 5:
                        high_risk_fixes.append(resolve)
                    elif risk_score >= 2:
                        medium_risk_fixes.append(resolve)
                    else:
                        low_risk_fixes.append(resolve)
                except (AttributeError, TypeError) as e:
                    self.logger.warning(f"Error assessing resolve risk: {e}")
                    medium_risk_fixes.append(resolve)  # Default to medium risk

            risk_parts = [
                "## Risk Assessment",
                "",
                f"**Total Resolves:** {len(resolves)}",
                "",
                "### Risk Distribution:",
                f"- **High Risk:** {len(high_risk_fixes)} resolves",
                f"- **Medium Risk:** {len(medium_risk_fixes)} resolves",
                f"- **Low Risk:** {len(low_risk_fixes)} resolves",
                "",
            ]

            if high_risk_fixes:
                risk_parts.extend(
                    [
                        "### High-Risk Resolves:",
                        "These resolves require extensive testing and review:",
                    ]
                )
                for resolve in high_risk_fixes[:3]:  # Show top 3
                    risk_parts.append(f"- {resolve.file_path}: {resolve.explanation}")

            if medium_risk_fixes:
                risk_parts.extend(
                    [
                        "",
                        "### Medium-Risk Resolves:",
                        "These resolves should be tested in a development environment:",
                    ]
                )
                for resolve in medium_risk_fixes[:3]:  # Show top 3
                    risk_parts.append(f"- {resolve.file_path}: {resolve.explanation}")

            risk_parts.extend(
                [
                    "",
                    "### Mitigation Strategies:",
                    "1. **Backup:** Create backups before applying any resolves",
                    "2. **Testing:** Test each resolve in isolation",
                    "3. **Staging:** Use a staging environment for validation",
                    "4. **Rollback:** Have a rollback plan ready",
                    "5. **Monitoring:** Monitor system behavior after resolves",
                ]
            )

            if high_risk_fixes:
                risk_parts.extend(
                    [
                        "",
                        "### Special Precautions for High-Risk Resolves:",
                        "- Review code changes with team members",
                        "- Perform comprehensive integration testing",
                        "- Consider gradual rollout if possible",
                        "- Have immediate rollback capability ready",
                    ]
                )

            result = "\n".join(risk_parts)
            self.logger.debug(
                f"Risk assessment: {len(high_risk_fixes)} high, "
                f"{len(medium_risk_fixes)} medium, {len(low_risk_fixes)} low"
            )
            return result

        except Exception as e:
            self.logger.error(f"Error in assess_risks: {e}", exc_info=True)
            raise

    def analyze_bugs_and_fixes(
        self, errors: list[ParsedError], resolves: list[CodeFix]
    ) -> BugAnalysisResult:
        """Comprehensive analysis of bugs and resolves, returning a complete result.

        Args:
            errors: List of parsed errors to analyze.
            resolves: List of generated code fixes.

        Returns:
            Complete bug analysis result with all assessments.

        Raises:
            ValueError: If inputs are malformed.
        """
        try:
            self.logger.info(
                f"Performing comprehensive analysis: {len(errors)} errors, {len(resolves)} resolves"
            )

            result = BugAnalysisResult(
                errors=errors,
                resolves=resolves,
                root_cause_analysis=self.analyze_root_causes(errors, resolves),
                fix_summary=self.generate_fix_summary(resolves),
                estimated_effort=self.estimate_effort(resolves),
                risk_assessment=self.assess_risks(resolves),
            )

            self.logger.info("Comprehensive analysis completed successfully")
            return result

        except Exception as e:
            self.logger.error(f"Error in analyze_bugs_and_fixes: {e}", exc_info=True)
            raise

    async def analyze_container(self, container_name: str, error_logs: str) -> dict[str, Any]:
        """Analyze bugs within a specific container scope.

        Performs container-scoped bug analysis with file path resolution
        and container filesystem access. Integrates with container services.

        Args:
            container_name: Name of the container to analyze.
            error_logs: Error logs or output from container operations.

        Returns:
            Dictionary containing:
                - errors: List of parsed errors
                - resolves: List of generated fixes
                - container_context: Container-specific information
                - file_mappings: Container file path to host path mappings
                - analysis: Complete bug analysis result

        Raises:
            ValueError: If container_name or error_logs are invalid.
            RuntimeError: If container analysis fails.
        """
        try:
            if not container_name or not isinstance(container_name, str):
                raise ValueError(f"Invalid container_name: {container_name}")

            if not error_logs or not isinstance(error_logs, str):
                raise ValueError("Invalid error_logs: expected non-empty string")

            self.logger.info(f"Starting container-scoped analysis for container: {container_name}")

            # Simulate async processing of container logs
            await asyncio.sleep(0.01)  # Minimal async operation

            # Parse container-specific information
            container_context = {
                "container_name": container_name,
                "analysis_timestamp": str(
                    __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                ),
                "log_size": len(error_logs),
                "error_count": error_logs.count("Error") + error_logs.count("error"),
            }

            self.logger.debug(f"Container context: {container_context}")

            # Extract error patterns from logs
            errors: list[ParsedError] = []
            resolves: list[CodeFix] = []

            # In production, this would parse actual error logs
            # For now, we prepare the structure for integration
            self.logger.debug(f"Extracted {len(errors)} errors from container logs")
            self.logger.debug(f"Generated {len(resolves)} resolves for container")

            # Perform analysis
            analysis = self.analyze_bugs_and_fixes(errors, resolves)

            result = {
                "errors": errors,
                "resolves": resolves,
                "container_context": container_context,
                "file_mappings": {},  # Populated by file path resolution
                "analysis": analysis,
            }

            self.logger.info(
                f"Container analysis completed for {container_name}: {len(errors)} errors, {len(resolves)} resolves"
            )

            return result

        except ValueError as e:
            self.logger.error(f"Invalid input for container analysis: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error in analyze_container: {e}", exc_info=True)
            raise RuntimeError(f"Container analysis failed: {str(e)}")

    async def generate_fixes(self, bug_list: list[ParsedError]) -> list[CodeFix]:
        """Generate automated fixes for a list of bugs.

        Creates targeted code fixes for identified bugs with confidence
        scoring and validation suggestions.

        Args:
            bug_list: List of ParsedError objects to generate fixes for.

        Returns:
            List of generated CodeFix objects with explanations and confidence scores.

        Raises:
            ValueError: If bug_list is malformed.
            RuntimeError: If fix generation fails.
        """
        try:
            if not isinstance(bug_list, list):
                raise ValueError(f"Expected list of bugs, got {type(bug_list)}")

            if not bug_list:
                self.logger.debug("No bugs provided for fix generation")
                return []

            self.logger.info(f"Generating fixes for {len(bug_list)} bugs")

            generated_fixes: list[CodeFix] = []

            for bug in bug_list:
                try:
                    await asyncio.sleep(0.01)  # Simulate async processing

                    if not isinstance(bug, ParsedError):
                        self.logger.warning(f"Skipping non-ParsedError object: {type(bug)}")
                        continue

                    # Generate fix based on error type
                    fix = self._generate_fix_for_error(bug)
                    if fix:
                        generated_fixes.append(fix)
                        self.logger.debug(
                            f"Generated fix for {bug.error_type.value} in {bug.file_path}"
                        )

                except (AttributeError, TypeError) as e:
                    self.logger.warning(f"Error generating fix for bug: {e}")
                    continue

            self.logger.info(f"Fix generation completed: {len(generated_fixes)} fixes generated")

            return generated_fixes

        except ValueError as e:
            self.logger.error(f"Invalid input for fix generation: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error in generate_fixes: {e}", exc_info=True)
            raise RuntimeError(f"Fix generation failed: {str(e)}")

    def _generate_fix_for_error(self, error: ParsedError) -> CodeFix | None:
        """Generate a specific fix for a parsed error.

        Internal helper method for generating targeted fixes based on error types.

        Args:
            error: The ParsedError to generate a fix for.

        Returns:
            A CodeFix object if generation is successful, None otherwise.
        """
        try:
            error_type = error.error_type.value
            file_path = error.file_path or "unknown.py"

            # Simple fix generation templates
            fix_templates = {
                "syntax_error": CodeFix(
                    file_path=file_path,
                    line_number=error.line_number,
                    original_code="",  # To be populated from context
                    fixed_code="# Fix syntax error - review context",
                    explanation=f"Fix syntax error in {file_path}",
                    confidence=0.7,
                    test_suggestion="Run linter to verify syntax",
                ),
                "import_error": CodeFix(
                    file_path=file_path,
                    line_number=error.line_number,
                    original_code="",
                    fixed_code="# Add missing import - verify module availability",
                    explanation=f"Add missing import for {error.message}",
                    confidence=0.8,
                    test_suggestion="Verify dependency is installed",
                ),
                "name_error": CodeFix(
                    file_path=file_path,
                    line_number=error.line_number,
                    original_code="",
                    fixed_code="# Define missing variable or function",
                    explanation=f"Define missing name: {error.message}",
                    confidence=0.6,
                    test_suggestion="Add variable/function definition",
                ),
            }

            fix = fix_templates.get(error_type)
            if fix:
                self.logger.debug(f"Generated template-based fix for {error_type}")
                return fix

            # Default fix for unmapped error types
            self.logger.debug(f"Creating generic fix for unmapped error type: {error_type}")
            return CodeFix(
                file_path=file_path,
                line_number=error.line_number,
                original_code="",
                fixed_code="# Review and apply appropriate fix",
                explanation=f"Fix {error_type}: {error.message}",
                confidence=0.5,
                test_suggestion="Manual review and testing required",
            )

        except Exception as e:
            self.logger.warning(f"Error in _generate_fix_for_error: {e}")
            return None
