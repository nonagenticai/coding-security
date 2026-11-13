"""False-positive filters applied after the engine merge (services.finding_filters).

Every case below is a real line from a real scan (openplanner f404106) unless
marked otherwise; the must-NOT-suppress cases are the controls that prove each
rule is narrower than "drop everything".
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from services.finding_filters import (
    REASON_ASSERT_IN_TESTS,
    REASON_CREDENTIAL_LABEL,
    REASON_INLINE,
    REASON_OBJECT_ID,
    REASON_SQL_CONSTANT,
    REASON_TEST_DOWNGRADE,
    apply_finding_filters,
    extract_literal_values,
    is_credential_label,
    is_object_id,
    is_test_path,
    source_key,
    sql_interpolates_only_constants,
    statement_span,
)
from services.secrets_scanner import severity_for_detector
from services.security_detector import (
    SecurityAnalysisResult,
    SecurityVulnerabilityDetector,
    VulnerabilityConfidence,
    VulnerabilityMatch,
    VulnerabilitySeverity,
    VulnerabilityType,
)

ROOT = "/repo"


def _match(
    line: int,
    *,
    path: str = "/repo/app/db.py",
    vtype: VulnerabilityType = VulnerabilityType.SQL_INJECTION,
    rule: str = "sql_injection_python_1",
    engine: str = "pattern",
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    snippet: str = "",
    line_end: int | None = None,
) -> VulnerabilityMatch:
    return VulnerabilityMatch(
        id=f"{rule}_{path}_{line}",
        vulnerability_type=vtype,
        severity=severity,
        confidence=VulnerabilityConfidence.MEDIUM,
        file_path=path,
        language="python",
        line_start=line,
        line_end=line if line_end is None else line_end,
        pattern_id=rule,
        code_snippet=snippet,
        engine=engine,
    )


def _run(code: str, *matches: VulnerabilityMatch, path: str = "/repo/app/db.py"):
    return apply_finding_filters(list(matches), {source_key(path): code}, ROOT)


def _cred(line: int = 1, rule: str = "hardcoded_password_1", engine: str = "pattern", **kw):
    return _match(
        line, vtype=VulnerabilityType.HARDCODED_CREDENTIALS, rule=rule, engine=engine, **kw
    )


# ---------------------------------------------------------------- 1. inline markers


class TestInlineSuppression:
    def test_single_line_noqa_and_nosec(self):
        code = 'db.execute(f"DELETE FROM {table}")  # noqa: S608  # nosec B608 - names from the registry\n'
        kept, counts = _run(code, _match(1))
        assert kept == []
        assert counts == {REASON_INLINE: 1}

    def test_multiline_marker_on_second_line(self):
        code = (
            "db.execute(\n"
            '    f"UPDATE {table} SET {nonce_column} = ? WHERE rowid = ?",  # noqa: S608  # nosec B608 - fixed list\n'
            "    (a, b),\n"
            ")\n"
        )
        kept, counts = _run(code, _match(1))
        assert kept == []
        assert counts == {REASON_INLINE: 1}

    def test_multiline_span_ignores_brackets_inside_strings(self):
        # The string's own "(" must not keep the span open past the call.
        code = (
            "db.execute(\n"
            '    f"CREATE TABLE {t} (id INTEGER PRIMARY KEY CHECK (id = 1), "\n'
            ")\n"
            "x = 1  # nosec\n"
        )
        assert statement_span(code.split("\n"), _match(1)) == (1, 3)
        kept, counts = _run(code, _match(1))
        assert len(kept) == 1
        assert REASON_INLINE not in counts

    def test_credential_constant_with_s105(self):
        code = 'CLIENT_SECRET_BASIC = "client_secret_basic"  # noqa: S105  # nosec B105 - a method name\n'
        kept, counts = _run(code, _cred())
        assert kept == []
        assert counts == {REASON_INLINE: 1}

    def test_marker_for_another_category_does_not_suppress(self):
        # nosec B105 is a credentials waiver; it says nothing about SQL.
        code = 'db.execute(f"SELECT {x}")  # nosec B105\n'
        kept, counts = _run(code, _match(1))
        assert len(kept) == 1
        assert counts == {}

    def test_bare_nosec_suppresses_any_category(self):
        code = 'db.execute(f"SELECT {x}")  # nosec\n'
        kept, _ = _run(code, _match(1))
        assert kept == []

    def test_bare_noqa_does_not_suppress(self):
        code = 'db.execute(f"SELECT {x}")  # noqa\n'
        kept, _ = _run(code, _match(1))
        assert len(kept) == 1

    def test_allowlist_secret_only_for_credentials(self):
        code = 'token = "abcdefghijklmnop0123"  # pragma: allowlist secret\n'
        kept, counts = _run(code, _cred(), _match(1))
        assert [k.vulnerability_type for k in kept] == [VulnerabilityType.SQL_INJECTION]
        assert counts == {REASON_INLINE: 1}

    def test_noqa_s310_suppresses_semgrep_urllib(self):
        code = "with urllib.request.urlopen(  # noqa: S310  # nosec B310\n    url, timeout=1\n):\n"
        f = _match(
            1,
            vtype=VulnerabilityType.INFORMATION_DISCLOSURE,
            rule="python.lang.security.audit.dynamic-urllib-use-detected",
            engine="semgrep",
            severity=VulnerabilitySeverity.MEDIUM,
        )
        kept, _ = _run(code, f)
        assert kept == []

    def test_noqa_s314_suppresses_xml(self):
        code = "root = ET.fromstring(drawio.build())  # noqa: S314 - our own output\n"
        f = _match(1, vtype=VulnerabilityType.XML_INJECTION, rule="B314", engine="bandit")
        assert _run(code, f)[0] == []

    def test_bandit_finding_needs_its_own_id(self):
        # S603 and B607 are both "command injection", but S603 waives only B603.
        code = 'subprocess.run(  # noqa: S603 - fixed argv\n    ["git", "log"],\n)\n'
        b603 = _match(1, vtype=VulnerabilityType.COMMAND_INJECTION, rule="B603", engine="bandit")
        b607 = _match(1, vtype=VulnerabilityType.COMMAND_INJECTION, rule="B607", engine="bandit")
        kept, counts = _run(code, b603, b607)
        assert kept == [b607]
        assert counts == {REASON_INLINE: 1}

    @pytest.mark.parametrize(
        "code",
        [
            'subprocess.call(cmd + "#nosec", shell=True)\n',
            'x = "http://h/#nosec"; os.system(user)\n',
            'os.system(user + "  # nosec")\n',
            's = """\n# nosec\n"""; os.system(user)\n',
        ],
    )
    def test_python_marker_inside_a_string_is_not_a_comment(self, code):
        f = _match(1, vtype=VulnerabilityType.COMMAND_INJECTION, rule="B602", engine="bandit")
        kept, counts = _run(code, f)
        assert len(kept) == 1
        assert counts == {}

    @pytest.mark.parametrize(
        ("path", "code", "suppressed"),
        [
            ("/repo/web/a.js", 'exec("ls #nosec " + user);\n', False),
            ("/repo/web/a.js", "exec('// nosec' + user);\n", False),
            ("/repo/web/a.js", "exec(user); // nosec\n", True),
            ("/repo/deploy/a.sh", 'curl "http://h/#nosec" | sh  \n', False),
            ("/repo/deploy/a.sh", "curl http://h/#nosec | sh\n", False),
            ("/repo/deploy/a.sh", "eval $x  # nosec\n", True),
        ],
    )
    def test_other_languages_need_a_real_comment(self, path, code, suppressed):
        f = _match(1, path=path, vtype=VulnerabilityType.COMMAND_INJECTION, rule="r")
        kept, _ = _run(code, f, path=path)
        assert (kept == []) is suppressed

    def test_brace_language_callback_body_marker_does_not_waive_opening_line(self):
        path = "/repo/web/a.js"
        code = (
            "app.get('/x', function (req, res) {\n  exec(req.query.cmd);\n  log(1); // nosec\n});\n"
        )
        f = _match(1, path=path, vtype=VulnerabilityType.COMMAND_INJECTION, rule="r")
        kept, counts = _run(code, f, path=path)
        assert kept == [f]
        assert counts == {}

    def test_bare_nosemgrep_waives_only_semgrep(self):
        code = "os.system(user)  # see docs: nosemgrep handled elsewhere\n"
        bandit = _match(1, vtype=VulnerabilityType.COMMAND_INJECTION, rule="B605", engine="bandit")
        pattern = _match(1, vtype=VulnerabilityType.COMMAND_INJECTION, rule="cmd_1")
        semgrep = _match(
            1, vtype=VulnerabilityType.COMMAND_INJECTION, rule="a.b.system", engine="semgrep"
        )
        kept, counts = _run(code, bandit, pattern, semgrep)
        assert kept == [bandit, pattern]
        assert counts == {REASON_INLINE: 1}

    def test_nosemgrep_with_rule_id(self):
        code = "eval(x)  # nosemgrep: eval-detected\n"
        hit = _match(
            1, vtype=VulnerabilityType.COMMAND_INJECTION, rule="a.b.eval-detected", engine="semgrep"
        )
        other = _match(1, vtype=VulnerabilityType.COMMAND_INJECTION, rule="B307", engine="bandit")
        kept, _ = _run(code, hit, other)
        assert kept == [other]


# ---------------------------------------------------------------- 2. test paths


class TestTestPaths:
    @pytest.mark.parametrize(
        "path",
        [
            "/repo/tests/a.py",
            "/repo/pkg/test/a.py",
            "/repo/e2e/pages.ts",
            "/repo/src/__tests__/x.js",
            "/repo/testdata/x.go",
            "/repo/tests/fixtures/x.yaml",
            "/repo/tests/spec/x.rb",
            "/repo/tests/test_x.py",
            "/repo/tests/unit/x_test.py",
            "/repo/app/x_test.go",
            "/repo/app/conftest.py",
            "/repo/web/a.test.tsx",
            "/repo/web/a.spec.mjs",
        ],
    )
    def test_is_test_path(self, path):
        assert is_test_path(path, ROOT)

    @pytest.mark.parametrize(
        "path",
        [
            "/repo/app/db.py",
            "/repo/app/testing.py",
            "/repo/app/contest.py",
            # Production code whose name merely looks test-ish (audit 2026-11-04).
            "/repo/app/ab_test.py",
            "/repo/app/load_test.py",
            "/repo/api/specs/h.py",
            "/repo/app/fixtures/x.py",
            "/repo/spec/x.rb",
            # Audit 2: test_*.py outside a test dir is production code.
            "/repo/src/test_executor.py",
            "/repo/app/test_x.py",
        ],
    )
    def test_is_not_test_path(self, path):
        assert not is_test_path(path, ROOT)

    def test_only_segments_below_root_count(self):
        assert not is_test_path("/tmp/tests/repo/app/db.py", "/tmp/tests/repo")

    def test_b101_in_tests_is_dropped(self):
        f = _match(
            1,
            path="/repo/tests/test_a.py",
            vtype=VulnerabilityType.INFORMATION_DISCLOSURE,
            rule="B101",
            engine="bandit",
            severity=VulnerabilitySeverity.LOW,
        )
        kept, counts = _run("assert x\n", f, path="/repo/tests/test_a.py")
        assert kept == []
        assert counts == {REASON_ASSERT_IN_TESTS: 1}

    def test_b101_outside_tests_is_kept(self):
        f = _match(1, vtype=VulnerabilityType.INFORMATION_DISCLOSURE, rule="B101", engine="bandit")
        assert len(_run("assert x\n", f)[0]) == 1

    def test_other_test_findings_downgraded(self):
        path = "/repo/e2e/pages.ts"
        f = _match(
            1, path=path, vtype=VulnerabilityType.PATH_TRAVERSAL, rule="path_traversal_generic_1"
        )
        kept, counts = _run("readFileSync(file, 'utf8')\n", f, path=path)
        assert [k.severity for k in kept] == [VulnerabilitySeverity.LOW]
        assert counts == {REASON_TEST_DOWNGRADE: 1}

    def test_real_provider_secret_in_tests_keeps_severity(self):
        path = "/repo/tests/test_a.py"
        token = "ghp_" + "a1B2c3D4e5" * 4  # built at runtime, not a real token
        f = _cred(path=path, snippet=token)
        kept, counts = _run(f'GH = "{token}"\n', f, path=path)
        assert [k.severity for k in kept] == [VulnerabilitySeverity.HIGH]
        assert counts == {}

    def test_detect_secrets_aws_key_in_tests_keeps_severity(self):
        path = "/repo/tests/test_a.py"
        f = _cred(
            path=path,
            rule="detect-secrets:AWS Access Key",
            engine="detect-secrets",
            severity=VulnerabilitySeverity.CRITICAL,
        )
        kept, _ = _run('k = "AKIA..."\n', f, path=path)
        assert [k.severity for k in kept] == [VulnerabilitySeverity.CRITICAL]

    def test_bare_pem_header_in_tests_is_downgraded(self):
        path = "/repo/tests/test_tls.py"
        # PEM markers are assembled at runtime so the repo's own gitleaks gate
        # does not flag this fixture (same reason as the ghp_ token above).
        begin = "-----BEGIN " + "PRIVATE KEY-----"
        end = "-----END " + "PRIVATE KEY-----"
        code = f'KEY = "{begin}\\nMIIE\\n{end}\\n"\n'
        f = _cred(
            path=path,
            rule="detect-secrets:Private Key",
            engine="detect-secrets",
            severity=VulnerabilitySeverity.CRITICAL,
        )
        kept, counts = _run(code, f, path=path)
        assert [k.severity for k in kept] == [VulnerabilitySeverity.LOW]
        assert counts == {REASON_TEST_DOWNGRADE: 1}

    def test_pem_with_key_material_in_tests_keeps_severity(self):
        path = "/repo/tests/test_tls.py"
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 2
        begin = "-----BEGIN " + "PRIVATE KEY-----"
        end = "-----END " + "PRIVATE KEY-----"
        code = f'KEY = """{begin}\n{body}\n{end}"""\n'
        f = _cred(
            path=path,
            rule="detect-secrets:Private Key",
            engine="detect-secrets",
            severity=VulnerabilitySeverity.CRITICAL,
        )
        kept, counts = _run(code, f, path=path)
        assert [k.severity for k in kept] == [VulnerabilitySeverity.CRITICAL]
        assert counts == {}


# ---------------------------------------------------------------- 3. credential labels


class TestCredentialLabels:
    @pytest.mark.parametrize(
        "line",
        [
            'CLIENT_SECRET_BASIC = "client_secret_basic"',
            'PRIVATE_KEY_JWT = "private_key_jwt"',
            'StaffAction.UPDATE_PASSWORD: "UPDATE_PASSWORD",',
            '"sms_api_key": "admin.form.error.sms_api_key",',
            'Permission.STAFF_RESET_PASSWORD: "authz.permission.staff_reset_password",',
            'password = "${DB_PASSWORD}"',
            'token: "{{ vault_token }}"',
            'password = "%(password)s"',
            'token: "{{ .Values.pw }}"',
        ],
    )
    def test_suppressed(self, line):
        kept, counts = _run(line + "\n", _cred())
        assert kept == []
        assert counts == {REASON_CREDENTIAL_LABEL: 1}

    @pytest.mark.parametrize(
        "line",
        [
            'password = "hunter2hunter2"',
            "KC_BOOTSTRAP_ADMIN_PASSWORD: admin",
            # Assembled at runtime: a literal sk_live token trips the repo's own
            # gitleaks gate. The filter still sees the whole string.
            'api_key = "sk_' + 'live_abcdefghijklmnop"',
            'password = "${A}hunter2"',
            # Template references that carry a default ship the default (audit).
            "DB_PASSWORD=${DB_PASSWORD:-Pr0dS3cret!2024}",
            'password = "${DB_PASSWORD-hunter2xyz}"',
            'password = "${DB_PASSWORD:=hunter2xyz}"',
            'password = "{{ .Values.pw | default \\"hunter2xyz\\" }}"',
            'password = "{{ default \\"hunter2xyz\\" .Values.pw }}"',
            # Every literal on the line must be a label, not just the first.
            'AUTH = {"method": "client_secret_basic", "password": "Tr0ub4dor&3xyz"}',
            # Plausible passwords that happen to be identifier-shaped, or empty.
            'DB_PASSWORD = "postgres_password"',
            'password = ""',
            'password = "password"',
            'password = "super-secret-password"',
            'password = "my.secret"',
        ],
    )
    def test_kept(self, line):
        kept, counts = _run(line + "\n", _cred())
        assert len(kept) == 1
        assert counts == {}

    def test_applies_to_detect_secrets_keyword_and_bandit(self):
        code = 'PRIVATE_KEY_JWT = "private_key_jwt"\n'
        ds = _cred(rule="detect-secrets:Secret Keyword", engine="detect-secrets")
        bd = _cred(rule="B105", engine="bandit")
        kept, counts = _run(code, ds, bd)
        assert kept == []
        assert counts == {REASON_CREDENTIAL_LABEL: 2}

    def test_not_applied_to_provider_detectors(self):
        code = 'PRIVATE_KEY_JWT = "private_key_jwt"\n'
        f = _cred(rule="detect-secrets:Slack Token", engine="detect-secrets")
        assert len(_run(code, f)[0]) == 1

    def test_comparison_uses_the_literal_not_an_assignment(self):
        assert extract_literal_values('assert first.client_secret == "first"') == [(None, "first")]
        assert not is_credential_label("first")

    def test_every_assigned_value_is_collected(self):
        assert extract_literal_values('AUTH = {"method": "a_secret", "password": "x"}') == [
            ("method", "a_secret"),
            ("password", "x"),
        ]

    def test_label_value_rules(self):
        assert is_credential_label("admin.form.error.sms_api_key")
        assert not is_credential_label("admin")  # no credential word
        assert not is_credential_label("secret_2")  # digit
        assert not is_credential_label("my secret")  # space
        assert not is_credential_label("password")  # single word: weak password
        assert not is_credential_label("super-secret-password")  # dash phrase
        assert not is_credential_label("")  # empty is not a label
        # Enum style needs the assigned name: the value must contain its last component.
        assert is_credential_label("UPDATE_PASSWORD", "StaffAction.UPDATE_PASSWORD")
        assert is_credential_label("private_key_jwt", "PRIVATE_KEY_JWT")
        assert not is_credential_label("UPDATE_PASSWORD")
        assert not is_credential_label("postgres_password", "DB_PASSWORD")
        assert not is_credential_label("my.secret", "password")  # one dot is not a key path


# ---------------------------------------------------------------- 5. object ids


class TestObjectIds:
    @pytest.mark.parametrize("value", ["5eff0e2eb10162499bc9f932", "627c0663e98eca854178bba6"])
    def test_object_id(self, value):
        assert is_object_id(value)

    @pytest.mark.parametrize(
        "value",
        [
            "ffffffffb10162499bc9f932",  # 2106: future
            "00000000b10162499bc9f932",  # 1970: before 2009
            "5EFF0E2EB10162499BC9F932",  # upper case
            "5eff0e2eb10162499bc9f9",  # 22 chars
        ],
    )
    def test_not_object_id(self, value):
        assert not is_object_id(value)

    def _hex(self, line: str):
        f = _cred(rule="detect-secrets:Hex High Entropy String", engine="detect-secrets")
        return _run(line + "\n", f)

    @pytest.mark.parametrize(
        "line",
        [
            '"id": "5eff0e2eb10162499bc9f932",',
            '"_id": "627c0663e98eca854178bba6"',
            'flow_uuid = "627c0663e98eca854178bba6"',
            '"activityId": "627c0663e98eca854178bba6", "parentId": "5eff0e2eb10162499bc9f932"',
            'USER_ID = "5eff0e2eb10162499bc9f932"',
        ],
    )
    def test_id_named_object_ids_suppressed(self, line):
        kept, counts = self._hex(line)
        assert kept == []
        assert counts == {REASON_OBJECT_ID: 1}

    @pytest.mark.parametrize(
        "line",
        [
            'COMMIT = "ce5602a8f4e1b2c3d4e5f60718293a4b5c6d7e8f"',
            'DOCKER_KEY = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"',
            'paid = "ce5602a8f4e1b2c3d4e5f60718293a4b5c6d7e8f"',
            # Audit 2026-11-04: an id NAME alone, or an ObjectId SHAPE alone, proves nothing.
            'session_id = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"',
            '"id": "870f51ff287b41be84648412901e0402",',
            'API_SECRET = "5f2b8c1d9e3a4b7c6d8e9f01"',
            'c.login(user_id="5f2b8c1d9e3a4b7c6d8e9f01", "9f86d081884c7d659a2feaa0c55ad015")',
            # Unnamed ObjectIds (Webex flow tuples) are kept, at detect-secrets' MEDIUM.
            '("GlobalErrorHandling", "OnGlobalError", "627c0663e98eca854178bba6", "x"),',
        ],
    )
    def test_other_hex_kept(self, line):
        assert len(self._hex(line)[0]) == 1


# ---------------------------------------------------------------- 6. SQL constants


class TestSqlConstantInterpolation:
    """Constants are PROVEN from the module AST, never guessed from a name."""

    _MODULE = (
        'META_TABLE = "configuration_package"\n'
        "LIMIT = 50\n"
        'COLS = ("id", "name")\n'
        'KINDS = frozenset({"a", "b"})\n'
    )

    @pytest.mark.parametrize(
        "stmt",
        [
            'cursor.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")',
            'db.execute(\n    f"CREATE TABLE {META_TABLE} (id INTEGER PRIMARY KEY CHECK (id = 1), "\n    "format INTEGER NOT NULL)"\n)',
            'rows = db.execute(f"SELECT * FROM {META_TABLE} LIMIT {LIMIT}").fetchall()',
            'db.execute(f"SELECT {COLS} FROM t WHERE k IN {KINDS} LIMIT {len(xs)}")',
        ],
    )
    def test_constant(self, stmt):
        code = self._MODULE + stmt + "\n"
        assert sql_interpolates_only_constants(stmt, code)
        kept, counts = _run(code, _match(5))
        assert kept == []
        assert counts == {REASON_SQL_CONSTANT: 1}

    @pytest.mark.parametrize(
        "stmt",
        [
            'return [str(r[1]) for r in db.execute(f"PRAGMA {schema}.table_info({table})").fetchall()]',
            'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            'cursor.execute(f"SELECT * FROM {META_TABLE} WHERE " + where)',
            'cursor.execute(f"SELECT {obj.TABLE}")',
            'cursor.execute(f"SELECT {str(x)}")',
            "cursor.execute(query)",
            # Audit 2026-11-04: attributes are never proven constant.
            'cur.execute(f"SELECT * FROM {self.TABLE} WHERE x={int(n)}")',
            'cur.execute(f"SELECT * FROM {cls.TABLE}")',
            # Two executes: the second is a concatenation.
            'cur.execute(f"SELECT {COLS} FROM t"); cur.execute("x" + user)',
        ],
    )
    def test_not_constant(self, stmt):
        code = self._MODULE + stmt + "\n"
        assert not sql_interpolates_only_constants(stmt, code)
        assert len(_run(code, _match(5))[0]) == 1

    @pytest.mark.parametrize(
        "code",
        [
            # An UPPER-CASE name is not a constant: it is assigned from the request.
            'ID = request.args["id"]\ncur.execute(f"SELECT * FROM t WHERE id = {ID}")\n',
            # Assigned twice at module level.
            'T = "a"\nT = input()\ncur.execute(f"SELECT * FROM {T}")\n',
            # Rebound inside a function via `global`.
            'T = "a"\ndef f():\n    global T\n    T = input()\ncur.execute(f"SELECT * FROM {T}")\n',
            # Shadowed by a parameter of the enclosing function.
            'T = "a"\ndef f(T):\n    cur.execute(f"SELECT * FROM {T}")\n',
            # Imported from another module: not chased, not proven.
            'from app.names import T\ncur.execute(f"SELECT * FROM {T}")\n',
            # Only assigned inside a function, not at module level.
            'def f():\n    T = "a"\n    cur.execute(f"SELECT * FROM {T}")\n',
            # A non-literal value.
            'T = "a" + suffix\ncur.execute(f"SELECT * FROM {T}")\n',
            # The builtins are rebound, so int()/len() prove nothing.
            'int = str\ncur.execute(f"SELECT * FROM t WHERE id={int(user)}")\n',
            'def len(x):\n    return x\ncur.execute(f"SELECT {len(user)}")\n',
            'from x import float\ncur.execute(f"SELECT {float(user)}")\n',
            # The file does not parse: nothing can be proven.
            'T = "a"\ndef (:\ncur.execute(f"SELECT * FROM {T}")\n',
        ],
    )
    def test_not_proven_from_the_module(self, code):
        lines = code.split("\n")
        line = next(i for i, text in enumerate(lines, 1) if "execute(" in text)
        kept, counts = _run(code, _match(line))
        assert len(kept) == 1
        assert counts == {}

    def test_indented_statement(self):
        code = 'T = "t"\ndef f():\n    with x:\n        db.execute(f"DELETE FROM {T}")\n'
        assert _run(code, _match(4))[0] == []


# ---------------------------------------------------------------- 4. detect-secrets severity


class TestDetectSecretsSeverity:
    @pytest.mark.parametrize("t", ["AWS Access Key", "Private Key"])
    def test_critical(self, t):
        assert severity_for_detector(t) == VulnerabilitySeverity.CRITICAL

    @pytest.mark.parametrize(
        "t",
        [
            "GitHub Token",
            "Slack Token",
            "Stripe Access Key",
            "JSON Web Token",
            "OpenAI Token",
            "Unknown New Detector",
        ],
    )
    def test_high(self, t):
        assert severity_for_detector(t) == VulnerabilitySeverity.HIGH

    @pytest.mark.parametrize(
        "t",
        [
            "Secret Keyword",
            "Hex High Entropy String",
            "Base64 High Entropy String",
            "Basic Auth Credentials",
        ],
    )
    def test_medium(self, t):
        assert severity_for_detector(t) == VulnerabilitySeverity.MEDIUM


# ---------------------------------------------------------------- counts reach the result


class TestCountsAreExposed:
    def test_unknown_file_gets_path_rules_only(self):
        # No contents -> no content rule may fire (it could not be checked).
        f = _match(1, path="/repo/app/other.py")
        kept, counts = apply_finding_filters([f], {}, ROOT)
        assert kept == [f]
        assert counts == {}

    async def test_detector_result_carries_suppressed_findings(self, tmp_path):
        app = tmp_path / "app"
        app.mkdir()
        src = app / "db.py"
        src.write_text(
            "def wipe(db, table):\n"
            '    db.execute(f"DELETE FROM {table}")  # noqa: S608  # nosec B608 - registry names\n'
            '    db.execute(f"DELETE FROM {table}")\n'
        )
        detector = SecurityVulnerabilityDetector()
        result = await detector.analyze_security_vulnerabilities([str(src)])
        sql = result.vulnerabilities_by_type.get(VulnerabilityType.SQL_INJECTION, [])
        # The unmarked line is still reported; the marked one is suppressed AND counted.
        assert [m.line_start for m in sql if m.engine == "pattern"] == [3]
        assert result.suppressed_findings.get(REASON_INLINE, 0) >= 1

    async def test_scan_result_and_api_model_carry_suppressed_findings(self):
        from models.container_models import ContainerInfo
        from routers.security._common import _convert_result_to_model
        from services.security_scan_service import SecurityScanService

        analysis = SecurityAnalysisResult(
            total_files_analyzed=1,
            total_vulnerabilities_found=0,
            analysis_time_seconds=0.0,
            suppressed_findings={REASON_INLINE: 2, REASON_TEST_DOWNGRADE: 1},
        )
        assert _convert_result_to_model(analysis).suppressed_findings == {
            REASON_INLINE: 2,
            REASON_TEST_DOWNGRADE: 1,
        }
        info = ContainerInfo(
            container_name="c",
            api_endpoint="x",
            codebase_path=os.sep + "repo",
            repo_url="x",
            branch="main",
            status="running",
        )
        result = await SecurityScanService()._assemble_scan_result(
            analysis, info, datetime.now(UTC)
        )
        assert result.suppressed_findings == {REASON_INLINE: 2, REASON_TEST_DOWNGRADE: 1}
        assert result.model_dump()["suppressed_findings"] == {
            REASON_INLINE: 2,
            REASON_TEST_DOWNGRADE: 1,
        }


# ---------------------------------------------------------------- audit 2 (2026-11-04)


class TestSecondAuditFalseNegatives:
    """Every case here was DROPPED by 0fa351c and is a real vulnerability (or,
    for the controls, a label that must still be suppressed)."""

    # 1 + 3: credential_label -- equality with the name, every literal, source only.
    @pytest.mark.parametrize(
        ("path", "line"),
        [
            ("/repo/app/c.py", 'password = "postgres_password"'),
            ("/repo/app/c.py", 'password = "my_password"'),
            # The exact openplanner line is a credential LABEL (see
            # TestEnumValueLabels); it was a kept finding before that rule.
            ("/repo/app/c.yaml", "POSTGRES_PASSWORD: postgres_password"),
            ("/repo/app/c.yaml", 'password: "${DB_PASSWORD}"'),
            ("/repo/app/s.py", 'SECRET_KEY = "secret_key" if DEBUG else "pr0d-s3cr3t-9x"'),
            (
                "/repo/app/s.py",
                'AUTH = {"method": "client_secret_basic", "password": "Tr0ub4dor&3xyz"}',
            ),
            ("/repo/app/s.py", 'PASSWORD_KEY = "password_key"; login("admin", "hunter2")'),
            ("/repo/app/s.js", 'const token = mode ? "auth.token.key" : "hunter2hunter2";'),
            # 4: template refs carrying a value.
            ("/repo/app/c.py", 'password = "{{ \\"hunter2\\" }}"'),
            ("/repo/app/c.py", "password = '{{ coalesce .pw \"hunter2\" }}'"),
            ("/repo/app/c.py", "password = '{{ .pw | or \"x\" }}'"),
            ("/repo/app/c.py", "password = '$(echo hunter2)'"),
        ],
    )
    def test_credential_kept(self, path, line):
        ds = _cred(rule="detect-secrets:Secret Keyword", engine="detect-secrets", path=path)
        kept, counts = _run(line + "\n", ds, path=path)
        assert kept == [ds]
        assert counts == {}

    @pytest.mark.parametrize(
        "line",
        [
            'PRIVATE_KEY_JWT = "private_key_jwt"',
            'StaffAction.UPDATE_PASSWORD: "UPDATE_PASSWORD",',
            '"sms_api_key": "admin.form.error.sms_api_key",',
            'ClientAuth.CLIENT_SECRET_BASIC: "admin.idp.auth.client_secret_basic",',
            'AUTH_METHOD_KEY = "auth:method:key"',
            # The exact openplanner false positive (632d0f56 simulator_routes.py:57).
            'PlayOutcome.NO_SECRET: "simulator_no_secret",',
            'PlayOutcome.NO_SECRET: "simulator-no-secret",',
        ],
    )
    def test_credential_label_still_suppressed(self, line):
        kept, counts = _run(line + "\n", _cred(rule="B105", engine="bandit"))
        assert kept == []
        assert counts == {REASON_CREDENTIAL_LABEL: 1}


class TestEnumValueLabels:
    """The enum-value rule is narrow: only a dotted/attribute key ending in a
    credential word, with an identifier-shaped value, is a label. Everything
    that could be a real secret must stay a finding."""

    @pytest.mark.parametrize(
        "line",
        [
            # Plain/quoted keys are config or data, not enum labels.
            '{"password": "hunter2hunter2"}',
            '{"api_key": "abc123"}',
            '{"secret": "s3cr3tToken"}',
            'NO_SECRET: "simulator_no_secret"',
            # Assignment, not a mapping entry.
            'PlayOutcome.NO_SECRET = "simulator_no_secret"',
            # Digits or symbols in the value: a real secret shape.
            'PlayOutcome.NO_SECRET = "Sup3rS3cret!"',
            'PlayOutcome.NO_SECRET: "hunter2hunter2"',
            'PlayOutcome.NO_SECRET: "simulator_secret_2"',
            'PlayOutcome.NO_SECRET: "simulator secret"',
            # A dotted key that does not end in a credential word.
            'PlayOutcome.LABEL: "simulator_no_secret"',
            # Provider token shapes.
            'SecretKind.AWS_KEY: "AKIAIOSFODNN7EXAMPLE"',
            'SecretKind.GITHUB_TOKEN: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
        ],
    )
    def test_real_secret_shapes_stay_findings(self, line):
        kept, counts = _run(line + "\n", _cred(rule="B105", engine="bandit"))
        assert kept != []
        assert REASON_CREDENTIAL_LABEL not in counts

    def test_the_exact_openplanner_line_is_suppressed(self):
        """631d0f56 app/admin/simulator_routes.py:57 reported HIGH before the
        enum-value rule; it is a label mapping, not a secret."""
        line = 'PlayOutcome.NO_SECRET: "simulator_no_secret",'
        finding = _cred(rule="hardcoded_password_1", engine="pattern")
        kept, counts = _run(line + "\n", finding)
        assert kept == []
        assert counts == {REASON_CREDENTIAL_LABEL: 1}

    def test_multiline_call_secret_on_a_later_line_is_kept(self):
        code = 'db = connect(token_name="auth.token.key",\n           password="hunter2")\n'
        f = _cred(rule="B106", engine="bandit")
        kept, _ = _run(code, f)
        assert kept == [f]

    def test_label_rule_is_equality_not_containment(self):
        assert not is_credential_label("my_password", "password")
        assert not is_credential_label("simulator_no_secret", "PlayOutcome.NO_SECRET")
        assert is_credential_label("auth:method:key", "AUTH_METHOD_KEY")

    # 2: marker span.
    def test_semgrep_range_counts_markers_on_line_start_only_js(self):
        path = "/repo/web/x.js"
        code = "app.get('/', (req,res) => {\n  res.send(req.query.x);\n  other(); // nosec\n});\n"
        f = _match(
            1, path=path, vtype=VulnerabilityType.XSS, rule="a.xss", engine="semgrep", line_end=4
        )
        kept, counts = _run(code, f, path=path)
        assert kept == [f]
        assert counts == {}

    def test_semgrep_python_marker_on_a_later_line_waives_nothing(self):
        code = "subprocess.call(\n    cmd,  # nosec\n    shell=True,\n)\n"
        f = _match(
            1,
            vtype=VulnerabilityType.COMMAND_INJECTION,
            rule="a.subprocess-shell-true",
            engine="semgrep",
            line_end=4,
        )
        kept, _ = _run(code, f)
        assert kept == [f]

    def test_line_end_does_not_widen_the_span_for_other_engines(self):
        path = "/repo/web/x.js"
        code = "eval(req.query.x);\nfoo(); // nosec\n"
        f = _match(
            1, path=path, vtype=VulnerabilityType.COMMAND_INJECTION, rule="js_eval", line_end=2
        )
        kept, _ = _run(code, f, path=path)
        assert kept == [f]

    def test_marker_inside_a_multiline_js_template_literal_is_not_a_comment(self):
        path = "/repo/web/x.js"
        code = "db.query(`\n  SELECT * FROM u WHERE n = '${req.query.n}' // nosec\n`);\n"
        f = _match(2, path=path, rule="sql_injection_js")
        kept, _ = _run(code, f, path=path)
        assert kept == [f]

    # 7: unparseable Python has no comments.
    def test_untokenizable_python_markers_waive_nothing(self):
        code = 'x = (\ny = """\nos.system(c)  # nosec\n'
        f = _match(3, vtype=VulnerabilityType.COMMAND_INJECTION, rule="B605", engine="bandit")
        kept, _ = _run(code, f)
        assert kept == [f]

    # 5: object ids.
    @pytest.mark.parametrize(
        "line",
        [
            'const ownerId = "65a1b2c3d4e5f60718293a4b", token = '
            "`9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`;",
            '{owner_id: "65a1b2c3d4e5f60718293a4b", token: 9f86d081884c7d659a2feaa0c55ad015}',
            'client_secret_id = "65a1b2c3d4e5f60718293a4b"',
            'api_key_id = "65a1b2c3d4e5f60718293a4b"',
            'token_id = "65a1b2c3d4e5f60718293a4b"',
        ],
    )
    def test_object_id_kept(self, line):
        f = _cred(rule="detect-secrets:Hex High Entropy String", engine="detect-secrets")
        kept, counts = _run(line + "\n", f)
        assert kept == [f]
        assert counts == {}

    # 6: dynamic module bindings disable the SQL constant rule.
    @pytest.mark.parametrize(
        "extra",
        [
            "from evil import *\n",
            'globals()["TABLE"] = input()\n',
            'vars()["TABLE"] = input()\n',
            'setattr(sys.modules[__name__], "TABLE", input())\n',
        ],
    )
    def test_sql_constant_rule_off_with_dynamic_bindings(self, extra):
        code = 'TABLE = "users"\n' + extra + 'cur.execute(f"select * from {TABLE}")\n'
        f = _match(3)
        kept, counts = _run(code, f)
        assert kept == [f]
        assert counts == {}

    @pytest.mark.parametrize(
        "line",
        [
            'if password == "Sup3rS3cret!":',
            'elif token != "f00dBabe_99x":',
            'while secret == "hunter2hunter2":',
            'check = lambda password="hunter2": password',
            'handler = {"k": 1} if pw == "Sup3rS3cret!" else None',
            'case "S3cr3t!x":',
        ],
    )
    def test_comparison_before_colon_is_not_a_mapping_key(self, line):
        f = _cred(rule="B105", engine="bandit")
        kept, counts = _run(line + "\n", f)
        assert kept == [f]
        assert counts == {}

    @pytest.mark.parametrize(
        "line",
        ['    "secret_set": True,', '{"password_hint": None, "token_ttl": 3}'],
    )
    def test_dict_keys_still_count_as_keys(self, line):
        f = _cred(rule="B105", engine="bandit")
        kept, counts = _run(line + "\n", f)
        assert kept == []
        assert counts == {REASON_CREDENTIAL_LABEL: 1}

    def test_js_ternary_secret_is_not_a_mapping_key(self):
        path = "/repo/web/a.js"
        f = _cred(path=path)
        kept, counts = _run('const pw = cond ? "S3cr3t!x" : null;\n', f, path=path)
        assert kept == [f]
        assert counts == {}

    def test_dict_key_with_value_on_next_line_is_kept(self):
        code = 'CREDS = {\n    "password":\n        "hunter2",\n}\n'
        f = _cred(line=2, rule="B105", engine="bandit")
        kept, counts = _run(code, f)
        assert kept == [f]
        assert counts == {}

    @pytest.mark.parametrize(
        "code",
        [
            'COLS = ["id"]\nCOLS.append(u)\ncur.execute(f"select {COLS} from t")\n',
            'COLS = {"id"}\nCOLS.add(u)\ncur.execute(f"select {COLS} from t")\n',
            'import sys\nCOLS = "id"\nsys.modules[__name__].COLS = u\n'
            'cur.execute(f"select {COLS} from t")\n',
            'COLS = "id"\nexec("COLS = " + repr(u))\ncur.execute(f"select {COLS} from t")\n',
            'import importlib\nCOLS = "id"\n'
            'setattr(importlib.import_module(__name__), "COLS", u)\n'
            'cur.execute(f"select {COLS} from t")\n',
        ],
    )
    def test_mutable_or_dynamically_rebound_constants_keep_sql_finding(self, code):
        n = code.count("\n")
        f = _match(n)
        kept, counts = _run(code, f)
        assert kept == [f]
        assert counts == {}

    def test_tuple_and_frozenset_constants_still_suppress(self):
        code = (
            'COLS = ("id", "name")\nTABLES = frozenset({"a", "b"})\n'
            'cur.execute(f"select {COLS} from {TABLES}")\n'
        )
        f = _match(3)
        kept, counts = _run(code, f)
        assert kept == []
        assert counts == {REASON_SQL_CONSTANT: 1}

    def test_setattr_on_an_ordinary_object_keeps_the_constant_rule(self):
        code = (
            'TIMEOUT = 5\nsetattr(context, "x", 1)\n'
            'cur.execute(f"PRAGMA busy_timeout={int(TIMEOUT)}")\n'
        )
        f = _match(3)
        kept, counts = _run(code, f)
        assert kept == []
        assert counts == {REASON_SQL_CONSTANT: 1}


# ---------------------------------------------------------------- dotenv placeholders


class TestDotenvPlaceholders:
    """New .env scanning must not turn committed placeholders into HIGH findings,
    and must not hide a real secret in the same file."""

    @pytest.mark.parametrize(
        ("path", "line"),
        [
            ("/repo/app/.env", "API_KEY=api_key"),
            ("/repo/app/.env", 'API_KEY="your-api-key-here"'),
            ("/repo/app/.env", "DB_PASSWORD=${DB_PASSWORD}"),
            ("/repo/app/.env", "DB_PASSWORD="),
            ("/repo/app/.env.example", "SECRET_KEY=changeme"),
            ("/repo/app/.env.local", "TOKEN=<your-token>"),
            ("/repo/app/config/.env.production", "POSTGRES_PASSWORD=postgres_password"),
        ],
    )
    def test_placeholder_is_suppressed(self, path, line):
        ds = _cred(rule="detect-secrets:Secret Keyword", engine="detect-secrets", path=path)
        kept, counts = _run(line + "\n", ds, path=path)
        assert kept == []
        assert counts == {REASON_CREDENTIAL_LABEL: 1}

    @pytest.mark.parametrize(
        ("path", "line"),
        [
            ("/repo/app/.env", "DB_PASSWORD=hunter2"),
            ("/repo/app/.env", 'API_KEY="sk_live_51H8xQ2"'),
            ("/repo/app/.env", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            ("/repo/app/.env", "SMTP_PASSWORD=correct-horse-battery-staple"),
            ("/repo/app/.env.local", "API_KEY=9f3c2b7a1e"),
        ],
    )
    def test_real_secret_kept_at_full_severity(self, path, line):
        ds = _cred(
            rule="detect-secrets:Secret Keyword",
            engine="detect-secrets",
            path=path,
            severity=VulnerabilitySeverity.HIGH,
        )
        kept, counts = _run(line + "\n", ds, path=path)
        assert kept == [ds]
        assert kept[0].severity == VulnerabilitySeverity.HIGH
        assert counts == {}

    def test_non_dotenv_config_is_unchanged(self):
        """The dotenv exception must not weaken the config-file rule."""
        path = "/repo/app/c.yaml"
        f = _cred(rule="detect-secrets:Secret Keyword", engine="detect-secrets", path=path)
        kept, counts = _run("POSTGRES_PASSWORD: postgres_password\n", f, path=path)
        assert kept == [f]
        assert counts == {}
