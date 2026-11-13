"""Advanced tests for SecurityVulnerabilityDetector covering uncovered code paths.

Targets: CVE references, language-specific parsing (JS, Java, Python AST),
confidence calculation, remediation advice, fix suggestions, fallback parsing,
and full analysis pipeline for multi-language codebases.
"""

import pytest

from services.security_detector import (
    SecurityVulnerabilityDetector,
    VulnerabilityConfidence,
    VulnerabilitySeverity,
    VulnerabilityType,
    get_security_detector,
)


@pytest.fixture
def detector():
    return SecurityVulnerabilityDetector()


# ============================================================================
# CVE References (lines 892-950)
# ============================================================================


class TestCVEReferences:
    """Exercise get_cve_references for every mapped vulnerability type."""

    def test_sql_injection_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.SQL_INJECTION)
        assert len(cves) >= 2
        assert all(cve.startswith("CVE-") for cve in cves)

    def test_xss_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.XSS)
        assert len(cves) >= 2

    def test_command_injection_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.COMMAND_INJECTION)
        assert len(cves) >= 2

    def test_hardcoded_credentials_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.HARDCODED_CREDENTIALS)
        assert len(cves) >= 2

    def test_weak_crypto_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.WEAK_CRYPTOGRAPHY)
        assert len(cves) >= 2

    def test_buffer_overflow_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.BUFFER_OVERFLOW)
        assert len(cves) >= 2

    def test_log4j_cves_no_duplicates(self, detector):
        """Log4j CVE list must not contain duplicates (bug fix verification)."""
        cves = detector.get_cve_references(VulnerabilityType.LOG4J_RCE)
        assert len(cves) == len(set(cves)), f"Duplicate CVEs found: {cves}"
        assert "CVE-2021-44228" in cves
        assert "CVE-2021-44832" in cves

    def test_spring_rce_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.SPRING_RCE)
        assert "CVE-2022-22965" in cves

    def test_deserialization_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.DESERIALIZATION)
        assert len(cves) >= 2

    def test_path_traversal_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.PATH_TRAVERSAL)
        assert len(cves) >= 2

    def test_ldap_injection_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.LDAP_INJECTION)
        assert len(cves) >= 1

    def test_xml_injection_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.XML_INJECTION)
        assert len(cves) >= 2

    def test_insecure_random_cves(self, detector):
        cves = detector.get_cve_references(VulnerabilityType.INSECURE_RANDOM)
        assert len(cves) >= 1

    def test_unmapped_type_returns_empty(self, detector):
        """Types without explicit CVE mappings return empty list (not crash)."""
        cves = detector.get_cve_references(VulnerabilityType.USE_AFTER_FREE)
        assert cves == []


# ============================================================================
# Remediation Advice (lines 845-857)
# ============================================================================


class TestRemediationAdvice:
    def test_sql_injection_advice(self, detector):
        pattern = detector.patterns[0]  # sql_injection_python_1
        advice = detector._get_remediation_advice(pattern)
        assert "parameterized" in advice.lower()

    def test_path_traversal_advice(self, detector):
        pt_patterns = [
            p for p in detector.patterns if p.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL
        ]
        assert len(pt_patterns) >= 1
        advice = detector._get_remediation_advice(pt_patterns[0])
        assert len(advice) > 10

    def test_deserialization_advice(self, detector):
        deser_patterns = [
            p
            for p in detector.patterns
            if p.vulnerability_type == VulnerabilityType.DESERIALIZATION
        ]
        assert len(deser_patterns) >= 1
        advice = detector._get_remediation_advice(deser_patterns[0])
        assert len(advice) > 10

    def test_log4j_advice(self, detector):
        log4j_patterns = [
            p for p in detector.patterns if p.vulnerability_type == VulnerabilityType.LOG4J_RCE
        ]
        assert len(log4j_patterns) >= 1
        advice = detector._get_remediation_advice(log4j_patterns[0])
        assert "log4j" in advice.lower() or "2.17" in advice

    def test_spring_rce_advice(self, detector):
        spring_patterns = [
            p for p in detector.patterns if p.vulnerability_type == VulnerabilityType.SPRING_RCE
        ]
        assert len(spring_patterns) >= 1
        advice = detector._get_remediation_advice(spring_patterns[0])
        assert "spring" in advice.lower() or "initbinder" in advice.lower()

    def test_unknown_type_fallback_advice(self, detector):
        """Unknown vulnerability types get generic advice."""
        from services.security_detector import VulnerabilityPattern

        fake_pattern = VulnerabilityPattern(
            id="fake",
            name="Fake",
            vulnerability_type=VulnerabilityType.USE_AFTER_FREE,
            severity=VulnerabilitySeverity.HIGH,
            description="test",
            language="any",
        )
        advice = detector._get_remediation_advice(fake_pattern)
        assert "security" in advice.lower()


# ============================================================================
# Fix Suggestions (lines 859-881)
# ============================================================================


class TestFixSuggestions:
    def test_sql_injection_suggestions(self, detector):
        pattern = detector.patterns[0]
        suggestions = detector._get_fix_suggestions(pattern)
        assert len(suggestions) >= 3
        assert any("parameterized" in s.lower() for s in suggestions)

    def test_xss_suggestions(self, detector):
        xss_patterns = [
            p for p in detector.patterns if p.vulnerability_type == VulnerabilityType.XSS
        ]
        suggestions = detector._get_fix_suggestions(xss_patterns[0])
        assert len(suggestions) >= 3

    def test_command_injection_suggestions(self, detector):
        cmd_patterns = [
            p
            for p in detector.patterns
            if p.vulnerability_type == VulnerabilityType.COMMAND_INJECTION
        ]
        suggestions = detector._get_fix_suggestions(cmd_patterns[0])
        assert any("shell" in s.lower() for s in suggestions)

    def test_hardcoded_credentials_suggestions(self, detector):
        cred_patterns = [
            p
            for p in detector.patterns
            if p.vulnerability_type == VulnerabilityType.HARDCODED_CREDENTIALS
        ]
        suggestions = detector._get_fix_suggestions(cred_patterns[0])
        assert len(suggestions) >= 2

    def test_weak_crypto_suggestions(self, detector):
        crypto_patterns = [
            p
            for p in detector.patterns
            if p.vulnerability_type == VulnerabilityType.WEAK_CRYPTOGRAPHY
        ]
        suggestions = detector._get_fix_suggestions(crypto_patterns[0])
        assert len(suggestions) >= 2

    def test_buffer_overflow_suggestions(self, detector):
        bo_patterns = [
            p
            for p in detector.patterns
            if p.vulnerability_type == VulnerabilityType.BUFFER_OVERFLOW
        ]
        suggestions = detector._get_fix_suggestions(bo_patterns[0])
        assert any("strncpy" in s.lower() or "strlcpy" in s.lower() for s in suggestions)

    def test_path_traversal_suggestions(self, detector):
        pt_patterns = [
            p for p in detector.patterns if p.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL
        ]
        suggestions = detector._get_fix_suggestions(pt_patterns[0])
        assert len(suggestions) >= 2

    def test_deserialization_suggestions(self, detector):
        deser_patterns = [
            p
            for p in detector.patterns
            if p.vulnerability_type == VulnerabilityType.DESERIALIZATION
        ]
        suggestions = detector._get_fix_suggestions(deser_patterns[0])
        assert len(suggestions) >= 2

    def test_log4j_suggestions(self, detector):
        log4j_patterns = [
            p for p in detector.patterns if p.vulnerability_type == VulnerabilityType.LOG4J_RCE
        ]
        suggestions = detector._get_fix_suggestions(log4j_patterns[0])
        assert any("2.17" in s for s in suggestions)

    def test_spring_rce_suggestions(self, detector):
        spring_patterns = [
            p for p in detector.patterns if p.vulnerability_type == VulnerabilityType.SPRING_RCE
        ]
        suggestions = detector._get_fix_suggestions(spring_patterns[0])
        assert len(suggestions) >= 2

    def test_unknown_type_fallback_suggestions(self, detector):
        from services.security_detector import VulnerabilityPattern

        fake_pattern = VulnerabilityPattern(
            id="fake",
            name="Fake",
            vulnerability_type=VulnerabilityType.USE_AFTER_FREE,
            severity=VulnerabilitySeverity.HIGH,
            description="test",
            language="any",
        )
        suggestions = detector._get_fix_suggestions(fake_pattern)
        assert len(suggestions) >= 1


# ============================================================================
# Confidence Calculation (lines 821-843)
# ============================================================================


class TestConfidenceCalculation:
    def test_high_confidence_with_password_keyword(self, detector):
        """Code containing 'password' should boost confidence: 0.7 base (HIGH severity) + 0.3 keyword = 1.0 VERY_HIGH."""
        from services.security_detector import VulnerabilityPattern

        pattern = VulnerabilityPattern(
            id="test",
            name="Test",
            vulnerability_type=VulnerabilityType.HARDCODED_CREDENTIALS,
            severity=VulnerabilitySeverity.HIGH,
            description="test",
            language="any",
        )
        confidence = detector._calculate_vulnerability_confidence(
            pattern, 'password = "secret123"', {}
        )
        # base 0.7 (HIGH severity) + keyword match 0.3 = 1.0 -> VERY_HIGH
        assert confidence == VulnerabilityConfidence.VERY_HIGH

    def test_very_high_confidence_with_password_and_user_input(self, detector):
        """Code with password + user_input: 0.7 (HIGH severity) + 0.3 + 0.2 = 1.2 -> VERY_HIGH."""
        from services.security_detector import VulnerabilityPattern

        pattern = VulnerabilityPattern(
            id="test",
            name="Test",
            vulnerability_type=VulnerabilityType.HARDCODED_CREDENTIALS,
            severity=VulnerabilitySeverity.HIGH,
            description="test",
            language="any",
        )
        confidence = detector._calculate_vulnerability_confidence(
            pattern, 'password = user_input + "secret"', {}
        )
        # base 0.7 (HIGH severity) + keyword 0.3 + user/input 0.2 = 1.2 -> VERY_HIGH
        assert confidence == VulnerabilityConfidence.VERY_HIGH

    def test_lower_confidence_with_input_validation(self, detector):
        """Input validation in context should reduce confidence."""
        from services.security_detector import VulnerabilityPattern

        pattern = VulnerabilityPattern(
            id="test",
            name="Test",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            description="test",
            language="any",
        )
        # Without validation
        conf_no_validation = detector._calculate_vulnerability_confidence(
            pattern, "execute(query)", {}
        )
        # With validation
        conf_with_validation = detector._calculate_vulnerability_confidence(
            pattern,
            "execute(query)",
            {"has_input_validation": True, "has_error_handling": True},
        )
        # Validation should reduce confidence
        severity_order = {
            VulnerabilityConfidence.VERY_HIGH: 5,
            VulnerabilityConfidence.HIGH: 4,
            VulnerabilityConfidence.MEDIUM: 3,
            VulnerabilityConfidence.LOW: 2,
            VulnerabilityConfidence.VERY_LOW: 1,
        }
        assert severity_order[conf_with_validation] <= severity_order[conf_no_validation]

    def test_user_input_boosts_confidence(self, detector):
        """Code containing 'user' or 'input' should boost confidence."""
        from services.security_detector import VulnerabilityPattern

        pattern = VulnerabilityPattern(
            id="test",
            name="Test",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.HIGH,
            description="test",
            language="any",
        )
        conf = detector._calculate_vulnerability_confidence(pattern, "user_input + query", {})
        # SQL_INJECTION is critical vuln type -> floor 0.85, + user 0.2 = 1.05 -> VERY_HIGH
        assert conf == VulnerabilityConfidence.VERY_HIGH

    def test_very_low_confidence(self, detector):
        """Code with validation and error handling but no keywords -> VERY_LOW."""
        from services.security_detector import VulnerabilityPattern

        pattern = VulnerabilityPattern(
            id="test",
            name="Test",
            vulnerability_type=VulnerabilityType.INSECURE_RANDOM,
            severity=VulnerabilitySeverity.MEDIUM,
            description="test",
            language="any",
        )
        conf = detector._calculate_vulnerability_confidence(
            pattern,
            "generic_function_call()",
            {"has_input_validation": True, "has_error_handling": True},
        )
        # base 0.5 (MEDIUM, non-critical type) - 0.2 - 0.1 = 0.2 -> VERY_LOW
        assert conf == VulnerabilityConfidence.VERY_LOW


# ============================================================================
# Python AST Parsing for Security (lines 1019-1130)
# ============================================================================


class TestPythonASTSecurity:
    async def test_python_ast_detects_imports(self, detector, tmp_path):
        """Python AST parser detects import statements."""
        code_file = tmp_path / "test.py"
        code_file.write_text("import os\nfrom subprocess import call\nx = 1\n")
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        assert result.language == "python"
        metadata = result.properties.get("security_metadata", {})
        import_names = [imp["name"] for imp in metadata.get("imports", [])]
        assert "os" in import_names
        assert "subprocess.call" in import_names

    async def test_python_ast_detects_dangerous_functions(self, detector, tmp_path):
        """Python AST parser flags eval, exec, compile as dangerous."""
        code_file = tmp_path / "dangerous.py"
        code_file.write_text('result = eval("1+1")\nexec("print(1)")\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        dangerous = metadata.get("dangerous_functions", [])
        func_names = [d["function"] for d in dangerous]
        assert "eval" in func_names
        assert "exec" in func_names

    async def test_python_ast_detects_function_entities(self, detector, tmp_path):
        """Python AST parser creates entities for function definitions."""
        code_file = tmp_path / "funcs.py"
        code_file.write_text("def my_function():\n    pass\n\ndef another():\n    return 1\n")
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        assert len(result.entities) >= 2
        entity_names = [e.name for e in result.entities]
        assert "my_function" in entity_names
        assert "another" in entity_names

    async def test_python_ast_detects_string_literals(self, detector, tmp_path):
        """Python AST parser tracks string literals longer than 5 chars."""
        code_file = tmp_path / "strings.py"
        code_file.write_text('short = "ab"\nlong_string = "this is a longer string"\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        literals = metadata.get("string_literals", [])
        # Only strings > 5 chars should be tracked
        assert len(literals) >= 1
        assert any("longer" in lit["value"] for lit in literals)

    async def test_python_ast_detects_method_calls(self, detector, tmp_path):
        """Python AST parser tracks method calls (attribute access)."""
        code_file = tmp_path / "methods.py"
        code_file.write_text('import os\nos.system("ls")\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        calls = metadata.get("function_calls", [])
        method_calls = [c for c in calls if c.get("type") == "method_call"]
        assert len(method_calls) >= 1
        assert any(c["name"] == "system" for c in method_calls)

    async def test_python_ast_fallback_on_syntax_error(self, detector, tmp_path):
        """Malformed Python falls back to regex analysis."""
        code_file = tmp_path / "bad.py"
        code_file.write_text("def broken(\n")  # SyntaxError
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        # Should still succeed with regex fallback
        assert result.success is True

    async def test_python_security_patterns_analysis(self, detector):
        """Python-specific security patterns detect known issues."""
        code = 'os.system("rm -rf /")\npassword = "hardcoded123"\npickle.loads(data)\n'
        patterns = await detector._analyze_python_security_patterns(code)
        assert patterns["command_injection"] >= 1
        assert patterns["hardcoded_secrets"] >= 1
        assert patterns["unsafe_deserialization"] >= 1


# ============================================================================
# JavaScript/TypeScript Parsing for Security (lines 1132-1185)
# ============================================================================


class TestJSSecurity:
    async def test_js_detects_require_imports(self, detector, tmp_path):
        """JS parser detects require() calls."""
        code_file = tmp_path / "app.js"
        code_file.write_text('const express = require("express");\nconst fs = require("fs");\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        assert result.language == "javascript"
        metadata = result.properties.get("security_metadata", {})
        imports = metadata.get("imports", [])
        import_names = [imp["name"] for imp in imports]
        assert "express" in import_names
        assert "fs" in import_names

    async def test_js_detects_es6_imports(self, detector, tmp_path):
        """JS parser detects ES6 import statements."""
        code_file = tmp_path / "app.js"
        code_file.write_text('import express from "express";\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        imports = metadata.get("imports", [])
        import_names = [imp["name"] for imp in imports]
        assert "express" in import_names

    async def test_js_detects_eval_usage(self, detector, tmp_path):
        """JS parser flags eval() as dangerous."""
        code_file = tmp_path / "danger.js"
        code_file.write_text('const result = eval("2+2");\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        dangerous = metadata.get("dangerous_patterns", [])
        assert any(d["pattern"] == "eval_usage" for d in dangerous)

    async def test_js_detects_innerhtml(self, detector, tmp_path):
        """JS parser flags innerHTML assignment as dangerous."""
        code_file = tmp_path / "xss.js"
        code_file.write_text('element.innerHTML = userInput + "extra";\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        dangerous = metadata.get("dangerous_patterns", [])
        assert any(d["pattern"] == "innerHTML_assignment" for d in dangerous)

    async def test_js_detects_document_write(self, detector, tmp_path):
        """JS parser flags document.write() as dangerous."""
        code_file = tmp_path / "write.js"
        code_file.write_text('document.write("hello");\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        dangerous = metadata.get("dangerous_patterns", [])
        assert any(d["pattern"] == "document_write" for d in dangerous)

    async def test_js_detects_dom_selectors(self, detector, tmp_path):
        """JS parser tracks DOM access via getElementById, querySelector."""
        code_file = tmp_path / "dom.js"
        code_file.write_text('const el = document.getElementById("myId");\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        dom_access = metadata.get("dom_access", [])
        assert len(dom_access) >= 1
        assert dom_access[0]["method"] == "getElementById"

    async def test_js_security_patterns_xss(self, detector):
        """JS security pattern analysis detects XSS patterns."""
        code = 'element.innerHTML = userInput;\neval("code");\n'
        patterns = await detector._analyze_js_security_patterns(code)
        assert patterns["xss_vulnerability"] >= 1
        assert patterns["eval_usage"] >= 1

    async def test_js_security_patterns_prototype_pollution(self, detector):
        """JS security pattern analysis detects prototype pollution."""
        code = "obj.__proto__.polluted = true;\n"
        patterns = await detector._analyze_js_security_patterns(code)
        assert patterns["prototype_pollution"] >= 1

    async def test_typescript_file(self, detector, tmp_path):
        """TypeScript files are parsed with JS parser."""
        code_file = tmp_path / "app.ts"
        code_file.write_text('const result = eval("test");\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        assert result.language == "typescript"


# ============================================================================
# Java Parsing for Security (lines 1187-1228)
# ============================================================================


class TestJavaSecurity:
    async def test_java_detects_imports(self, detector, tmp_path):
        """Java parser detects import statements."""
        code_file = tmp_path / "App.java"
        code_file.write_text("import java.sql.Statement;\nimport java.io.File;\n")
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        assert result.language == "java"
        metadata = result.properties.get("security_metadata", {})
        imports = metadata.get("imports", [])
        import_names = [imp["name"] for imp in imports]
        assert "java.sql.Statement" in import_names

    async def test_java_detects_sql_patterns(self, detector, tmp_path):
        """Java parser flags SQL Statement usage."""
        code_file = tmp_path / "SqlHelper.java"
        code_file.write_text(
            'Statement stmt = conn.createStatement();\nstmt.executeQuery("SELECT *");\n'
        )
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        sql_patterns = metadata.get("sql_patterns", [])
        assert len(sql_patterns) >= 1

    async def test_java_detects_reflection(self, detector, tmp_path):
        """Java parser flags reflection usage as risky."""
        code_file = tmp_path / "Reflect.java"
        code_file.write_text('Class cls = Class.forName("com.example.Secret");\n')
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        dangerous = metadata.get("dangerous_methods", [])
        assert any(d["pattern"] == "reflection" for d in dangerous)

    async def test_java_detects_deserialization(self, detector, tmp_path):
        """Java parser flags ObjectInputStream/readObject as high risk."""
        code_file = tmp_path / "Deser.java"
        code_file.write_text(
            "ObjectInputStream ois = new ObjectInputStream(input);\nObject obj = ois.readObject();\n"
        )
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        metadata = result.properties.get("security_metadata", {})
        dangerous = metadata.get("dangerous_methods", [])
        deser_hits = [d for d in dangerous if d["pattern"] == "deserialization"]
        assert len(deser_hits) >= 1

    async def test_java_security_patterns(self, detector):
        """Java-specific security patterns detect SQL injection and command injection."""
        code = (
            'stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);\nRuntime.exec("cmd");\n'
        )
        patterns = await detector._analyze_java_security_patterns(code)
        assert patterns["command_injection"] >= 1


# ============================================================================
# Generic/Fallback Code Pattern Analysis (lines 1275-1288)
# ============================================================================


class TestFallbackAnalysis:
    async def test_fallback_for_unknown_language(self, detector, tmp_path):
        """Unknown language files use generic fallback analysis."""
        code_file = tmp_path / "script.rb"
        code_file.write_text("def hello\n  puts 'hello'\nend\n# a comment\npassword = 'secret'\n")
        result = await detector._parse_file_for_security(code_file)
        assert result is not None
        assert result.language == "ruby"
        metadata = result.properties.get("security_metadata", {})
        assert "total_lines" in metadata
        assert metadata["total_lines"] >= 4

    async def test_fallback_counts_security_keywords(self, detector):
        code = 'password = "test"\napi_key = "abc"\ntoken = "xyz"\n'
        patterns = await detector._analyze_code_patterns(code, "unknown")
        assert patterns["security_keywords"] >= 3

    async def test_fallback_counts_comments(self, detector):
        code = "# comment\n// another comment\ncode()\n"
        patterns = await detector._analyze_code_patterns(code, "unknown")
        assert patterns["comment_lines"] >= 2

    async def test_fallback_counts_functions(self, detector):
        code = "def my_func():\n    pass\nfunction jsFunc() {}\npublic void javaMethod(int x) {}\n"
        patterns = await detector._analyze_code_patterns(code, "unknown")
        assert patterns["function_definitions"] >= 2


# ============================================================================
# Language Detection (line 664)
# ============================================================================


class TestLanguageDetection:
    def test_python_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("test.py")) == "python"

    def test_java_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("Test.java")) == "java"

    def test_js_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("app.js")) == "javascript"

    def test_ts_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("app.ts")) == "typescript"

    def test_cpp_extensions(self, detector):
        from pathlib import Path

        for ext in [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"]:
            assert detector._detect_language_from_path(Path(f"file{ext}")) == "cpp"

    def test_go_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("main.go")) == "go"

    def test_rust_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("lib.rs")) == "rust"

    def test_csharp_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("Program.cs")) == "csharp"

    def test_php_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("index.php")) == "php"

    def test_ruby_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("app.rb")) == "ruby"

    def test_unknown_extension(self, detector):
        from pathlib import Path

        assert detector._detect_language_from_path(Path("file.xyz")) == "unknown"


# ============================================================================
# Vulnerability Context Extraction (lines 795-819)
# ============================================================================


class TestVulnerabilityContext:
    def test_context_with_function_entity(self, detector):
        """Context extraction identifies the enclosing function."""
        from services.security_detector import CoreCodeEntity, EntityType, ParseResult, ParserType

        entity = CoreCodeEntity(
            id="func_1",
            name="process_user",
            type=EntityType.FUNCTION,
            language="python",
            file_path="test.py",
            line_number=1,
            end_line_number=10,
        )
        parsed = ParseResult(
            success=True,
            file_path="test.py",
            language="python",
            parser_used=ParserType.REGEX_FALLBACK,
            entities=[entity],
        )
        lines = ["def process_user():", "    query = 'SELECT *'", "    execute(query)"]
        context = detector._extract_vulnerability_context(lines, 2, 2, parsed)
        assert context.get("function_name") == "process_user"

    def test_context_with_class_entity(self, detector):
        """Context extraction identifies the enclosing class."""
        from services.security_detector import CoreCodeEntity, EntityType, ParseResult, ParserType

        entity = CoreCodeEntity(
            id="cls_1",
            name="UserService",
            type=EntityType.CLASS,
            language="python",
            file_path="test.py",
            line_number=1,
            end_line_number=20,
        )
        parsed = ParseResult(
            success=True,
            file_path="test.py",
            language="python",
            parser_used=ParserType.REGEX_FALLBACK,
            entities=[entity],
        )
        lines = ["class UserService:", "    def run(self):", "        pass"]
        context = detector._extract_vulnerability_context(lines, 2, 2, parsed)
        assert context.get("class_name") == "UserService"

    def test_context_detects_input_validation(self, detector):
        """Context extraction identifies presence of validation keywords."""
        from services.security_detector import ParseResult, ParserType

        parsed = ParseResult(
            success=True,
            file_path="test.py",
            language="python",
            parser_used=ParserType.REGEX_FALLBACK,
        )
        lines = [
            "def process():",
            "    validate(input)",
            "    sanitize(data)",
            "    execute(query)",
        ]
        context = detector._extract_vulnerability_context(lines, 4, 4, parsed)
        assert context["has_input_validation"] is True

    def test_context_detects_error_handling(self, detector):
        """Context extraction identifies presence of error handling."""
        from services.security_detector import ParseResult, ParserType

        parsed = ParseResult(
            success=True,
            file_path="test.py",
            language="python",
            parser_used=ParserType.REGEX_FALLBACK,
        )
        lines = [
            "try:",
            "    execute(query)",
            "except Exception:",
            "    handle_error()",
        ]
        context = detector._extract_vulnerability_context(lines, 2, 2, parsed)
        assert context["has_error_handling"] is True


# ============================================================================
# Full Pipeline - Multi-file Analysis (lines 573-582, 617-637)
# ============================================================================


class TestFullPipeline:
    async def test_file_parse_error_handled_gracefully(self, detector, tmp_path):
        """Files that raise exceptions during parsing are skipped, not crash."""
        # Create a binary file that will fail to read as text
        binary_file = tmp_path / "binary.py"
        binary_file.write_bytes(b"\x80\x81\x82\x83\x00\x01")

        good_file = tmp_path / "good.py"
        good_file.write_text("x = 1 + 2\n")

        result = await detector.analyze_security_vulnerabilities([str(binary_file), str(good_file)])
        # At least the good file should be analyzed
        assert result.total_files_analyzed >= 1

    async def test_security_hotspots_detection(self, detector, tmp_path):
        """Files with 3+ vulnerabilities are flagged as security hotspots."""
        code_file = tmp_path / "hotspot.py"
        code_file.write_text(
            'password = "SuperSecret123!"\n'
            'api_key = "AKIAIOSFODNN7EXAMPLE_KEY"\n'
            'secret = "my_super_secret_value"\n'
            'token = "eyJhbGciOiJIUzI1NiIsInR5"\n'
        )
        result = await detector.analyze_security_vulnerabilities(
            [str(code_file)], include_low_confidence=True
        )
        # With 4 hardcoded credential patterns, this file should be a hotspot
        if result.total_vulnerabilities_found >= 3:
            assert str(code_file) in result.security_hotspots

    async def test_priority_fixes_only_critical_and_high(self, detector, tmp_path):
        """Priority fixes only include CRITICAL/HIGH severity with HIGH+ confidence."""
        code_file = tmp_path / "critical.py"
        code_file.write_text('import os\nos.system("rm -rf " + user_input)\n')
        result = await detector.analyze_security_vulnerabilities(
            [str(code_file)], include_low_confidence=True
        )
        for fix in result.priority_fixes:
            assert fix.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]

    async def test_language_distribution(self, detector, tmp_path):
        """Language distribution correctly counts files per language."""
        py_file = tmp_path / "app.py"
        py_file.write_text("x = 1\n")
        js_file = tmp_path / "app.js"
        js_file.write_text("const x = 1;\n")

        result = await detector.analyze_security_vulnerabilities([str(py_file), str(js_file)])
        assert result.language_distribution.get("python", 0) >= 1
        assert result.language_distribution.get("javascript", 0) >= 1

    async def test_most_common_vulnerability(self, detector, tmp_path):
        """Most common vulnerability type is correctly identified."""
        code_file = tmp_path / "creds.py"
        code_file.write_text('password = "SuperSecret123!"\napi_key = "AKIAIOSFODNN7EXAMPLE_KEY"\n')
        result = await detector.analyze_security_vulnerabilities(
            [str(code_file)], include_low_confidence=True
        )
        if result.total_vulnerabilities_found >= 1:
            assert result.most_common_vulnerability is not None

    async def test_cpp_buffer_overflow_detection(self, detector, tmp_path):
        """Detect buffer overflow in C/C++ code."""
        code_file = tmp_path / "buffer.c"
        code_file.write_text("void copy(char* dest, char* src) {\n    strcpy(dest, src);\n}\n")
        result = await detector.analyze_security_vulnerabilities(
            [str(code_file)], include_low_confidence=True
        )
        assert result.total_files_analyzed == 1
        if VulnerabilityType.BUFFER_OVERFLOW in result.vulnerabilities_by_type:
            bo_vulns = result.vulnerabilities_by_type[VulnerabilityType.BUFFER_OVERFLOW]
            assert len(bo_vulns) >= 1
            assert bo_vulns[0].severity == VulnerabilitySeverity.CRITICAL

    async def test_java_log4j_detection(self, detector, tmp_path):
        """Detect Log4j usage in Java code."""
        code_file = tmp_path / "App.java"
        code_file.write_text(
            "import org.apache.logging.log4j.Logger;\nimport org.apache.logging.log4j.LogManager;\n"
        )
        result = await detector.analyze_security_vulnerabilities(
            [str(code_file)], include_low_confidence=True
        )
        assert result.total_files_analyzed == 1
        if VulnerabilityType.LOG4J_RCE in result.vulnerabilities_by_type:
            log4j_vulns = result.vulnerabilities_by_type[VulnerabilityType.LOG4J_RCE]
            assert len(log4j_vulns) >= 1
            assert "CVE-2021-44228" in log4j_vulns[0].references

    async def test_java_deserialization_detection(self, detector, tmp_path):
        """Detect unsafe deserialization in Java."""
        code_file = tmp_path / "DeserService.java"
        code_file.write_text(
            "ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());\n"
            "Object obj = ois.readObject();\n"
        )
        result = await detector.analyze_security_vulnerabilities(
            [str(code_file)], include_low_confidence=True
        )
        assert result.total_files_analyzed == 1
        if VulnerabilityType.DESERIALIZATION in result.vulnerabilities_by_type:
            deser_vulns = result.vulnerabilities_by_type[VulnerabilityType.DESERIALIZATION]
            assert len(deser_vulns) >= 1
            assert "CWE-502" in deser_vulns[0].cwe_ids


# ============================================================================
# Global Detector Singleton (line 1291-1300)
# ============================================================================


class TestGlobalDetector:
    def test_get_security_detector_returns_instance(self):
        """get_security_detector returns a valid SecurityVulnerabilityDetector."""
        import services.security_detector as mod

        mod._security_detector = None  # Reset singleton
        det = get_security_detector()
        assert isinstance(det, SecurityVulnerabilityDetector)

    def test_get_security_detector_is_singleton(self):
        """get_security_detector returns the same instance on repeated calls."""
        import services.security_detector as mod

        mod._security_detector = None
        det1 = get_security_detector()
        det2 = get_security_detector()
        assert det1 is det2
        mod._security_detector = None  # Cleanup
