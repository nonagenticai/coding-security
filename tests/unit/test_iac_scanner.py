"""Tests for the IaC / misconfiguration scanner (trivy config mode).

trivy is installed in the Docker image (alongside the image-CVE scanner) but is
NOT present in the CI uv venv, so these tests drive the parse/map/scan logic via
canned `trivy config` JSON + monkeypatched subprocess (CLI-agnostic). The single
live-CLI test is gated on availability so it runs locally / in-pod but skips in
CI.
"""

import json
import time
from pathlib import Path

import pytest

from services.iac_scanner import (
    IaCScanner,
    _find_chart_root,
    _is_cloudformation,
    _is_compose_file,
    _is_iac_file,
    _is_terraform,
    _is_yaml,
)
from services.scanner_errors import ScannerExecutionError, ScannerPartialRunError
from services.security_detector import (
    VulnerabilityConfidence,
    VulnerabilitySeverity,
    VulnerabilityType,
)

# Stored as *.txt (not "Dockerfile*") so the gitops upstream-ref CI guard — which
# scans Dockerfile-prefixed files for bare docker.io refs — ignores it. The live
# test copies its content to a tmp file named "Dockerfile" for trivy's detection.
FIXTURE_DOCKERFILE = Path(__file__).parent.parent / "fixtures" / "insecure_dockerfile.txt"


def _misconfig(
    *,
    avd_id="AVD-DS-0002",
    title="Image user should not be 'root'",
    message="Specify at least 1 USER command in Dockerfile with non-root user as argument",
    severity="HIGH",
    status="FAIL",
    start_line=1,
    end_line=1,
    content="FROM ubuntu:latest",
    resolution="Add 'USER <non root user name>' line to the Dockerfile",
    references=("https://avd.aquasec.com/misconfig/ds002",),
    primary_url="https://avd.aquasec.com/misconfig/avd-ds-0002",
):
    mc = {
        "Type": "Dockerfile Security Check",
        "ID": avd_id.split("-")[-1],
        "AVDID": avd_id,
        "Title": title,
        "Description": "Running containers with 'root' user can lead to a container escape situation.",
        "Message": message,
        "Severity": severity,
        "Status": status,
        "Resolution": resolution,
        "References": list(references),
        "PrimaryURL": primary_url,
        "CauseMetadata": {
            "Provider": "Dockerfile",
            "Service": "general",
            "StartLine": start_line,
            "EndLine": end_line,
            "Code": {"Lines": [{"Number": start_line, "Content": content, "IsCause": True}]},
        },
    }
    return mc


def _payload(misconfigs, target="Dockerfile"):
    # Real `trivy config --format json` reports always carry SchemaVersion (R216
    # validates it: a dict without it is wrong-shape output, i.e. failed).
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": target,
                    "Class": "config",
                    "Type": "dockerfile",
                    "Misconfigurations": misconfigs,
                }
            ],
        }
    )


@pytest.fixture
def scanner():
    return IaCScanner()


class TestIsIaCFile:
    @pytest.mark.parametrize(
        "path",
        [
            "Dockerfile",
            "/app/Dockerfile",
            "Containerfile",
            "service.dockerfile",
            "main.tf",
            "infra.tofu",
            "deployment.yaml",
            "values.yml",
        ],
    )
    def test_accepts_iac_files(self, path):
        assert _is_iac_file(path) is True

    @pytest.mark.parametrize("path", ["app.py", "index.js", "README.md", "data.json", "go.mod"])
    def test_rejects_non_iac_files(self, path):
        assert _is_iac_file(path) is False


class TestParseMap:
    def test_root_user_high_misconfig(self, scanner):
        matches = scanner._parse_trivy_config_json(_payload([_misconfig()]))
        assert len(matches) == 1
        m = matches[0]
        # "root" keyword -> privilege escalation classification.
        assert m.vulnerability_type == VulnerabilityType.PRIVILEGE_ESCALATION
        assert m.severity == VulnerabilitySeverity.HIGH
        assert m.confidence == VulnerabilityConfidence.HIGH
        assert m.language == "dockerfile"
        assert m.pattern_id == "AVD-DS-0002"
        assert m.code_snippet == "FROM ubuntu:latest"
        assert m.remediation_advice.startswith("Add 'USER")
        assert m.file_path == "Dockerfile"
        assert m.line_start == 1
        # PrimaryURL is prepended to references.
        assert m.references[0] == "https://avd.aquasec.com/misconfig/avd-ds-0002"

    def test_fail_only_filter(self, scanner):
        """PASS checks are listed by trivy but must never count as findings."""
        matches = scanner._parse_trivy_config_json(
            _payload(
                [
                    _misconfig(status="PASS"),
                    _misconfig(avd_id="AVD-DS-0001", title="':latest' tag used", status="FAIL"),
                ]
            )
        )
        assert len(matches) == 1
        assert matches[0].pattern_id == "AVD-DS-0001"

    @pytest.mark.parametrize(
        "sev,expected",
        [
            ("CRITICAL", VulnerabilitySeverity.CRITICAL),
            ("HIGH", VulnerabilitySeverity.HIGH),
            ("MEDIUM", VulnerabilitySeverity.MEDIUM),
            ("LOW", VulnerabilitySeverity.LOW),
            ("UNKNOWN", VulnerabilitySeverity.MEDIUM),  # default
        ],
    )
    def test_severity_map(self, scanner, sev, expected):
        matches = scanner._parse_trivy_config_json(_payload([_misconfig(severity=sev)]))
        assert matches[0].severity == expected

    def test_generic_misconfig_is_information_disclosure(self, scanner):
        matches = scanner._parse_trivy_config_json(
            _payload(
                [
                    _misconfig(
                        avd_id="AVD-DS-0001",
                        title="Specify a tag in the 'FROM' statement for image",
                    )
                ]
            )
        )
        assert matches[0].vulnerability_type == VulnerabilityType.INFORMATION_DISCLOSURE

    def test_privileged_keyword_classification(self, scanner):
        matches = scanner._parse_trivy_config_json(
            _payload(
                [
                    _misconfig(
                        avd_id="AVD-KSV-0017",
                        title="Privileged container",
                        message="Container should not be privileged",
                    )
                ],
                target="pod.yaml",
            )
        )
        assert matches[0].vulnerability_type == VulnerabilityType.PRIVILEGE_ESCALATION
        assert matches[0].language == "kubernetes"

    def test_parse_empty_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_trivy_config_json("")

    def test_parse_malformed_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_trivy_config_json("{not json")

    def test_parse_non_dict_output(self, scanner):
        # R216: not a report object -> the engine FAILED, never "no findings".
        with pytest.raises(ScannerExecutionError):
            scanner._parse_trivy_config_json("[1, 2, 3]")

    def test_no_results_empty(self, scanner):
        # DELIBERATELY CHANGED (fail-open fix): a report with no Results is not
        # a clean scan — trivy emits exactly this shape (rc 0) for a target it
        # did not analyse (compose file, malformed manifest). With no target to
        # prove the absence benign, the check is fail-closed -> partial run.
        with pytest.raises(ScannerPartialRunError):
            scanner._parse_trivy_config_json(json.dumps({"Results": []}))

    def test_results_without_misconfigurations(self, scanner):
        payload = json.dumps({"Results": [{"Target": "Dockerfile", "Class": "config"}]})
        assert scanner._parse_trivy_config_json(payload) == []

    def test_missing_directive_gets_no_invented_line(self, scanner):
        # DS-0002 (no USER directive) is a whole-file check: trivy emits no
        # CauseMetadata, so there is no line to report. 0 means "no line" and
        # must stay 0 — never a synthesised anchor such as the file's last line.
        mc = _misconfig()
        del mc["CauseMetadata"]
        matches = scanner._parse_trivy_config_json(
            _payload([mc]), fallback_path="/workspace/repo/dev/check/Dockerfile"
        )
        assert len(matches) == 1
        assert matches[0].line_start == 0
        assert matches[0].line_end == 0
        assert matches[0].code_snippet == ""


class TestResultHonesty:
    """A trivy report with no Results is NOT proof of a clean target.

    Measured with trivy v0.69.3: a malformed manifest exits 0 with `Results`
    omitted — the same shape as a clean report. The gate is deliberately NARROW
    (a false `degraded` is also a failure): only target classes trivy always
    reports on degrade. Parsed YAML trivy ignores (`kustomization.yaml`), Helm
    chart roots, empty/comment-only Dockerfiles and resource-less CloudFormation
    templates stay clean."""

    def test_no_results_on_dockerfile_is_partial(self, scanner, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu:22.04\n")
        with pytest.raises(ScannerPartialRunError):
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2}), fallback_path=str(df)
            )

    @pytest.mark.parametrize(
        "body",
        ["", "# syntax=docker/dockerfile:1\n", "\n# only a comment\n\n"],
        ids=["empty", "parser-directive", "comment-only"],
    )
    def test_no_results_on_trivial_dockerfile_is_clean(self, scanner, tmp_path, body):
        # Measured: an empty / comment-only Dockerfile legitimately yields no
        # Results — it must not be a permanent degrade.
        df = tmp_path / "Dockerfile"
        df.write_text(body)
        assert (
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2}), fallback_path=str(df)
            )
            == []
        )

    def test_empty_results_on_terraform_dir_is_partial(self, scanner, tmp_path):
        module = tmp_path / "infra"
        module.mkdir()
        (module / "main.tf").write_text('resource "null_resource" "x" {}\n')
        with pytest.raises(ScannerPartialRunError):
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2, "Results": []}),
                fallback_path=str(module),
                base_dir=str(module),
            )

    def test_no_results_on_helm_chart_root_is_clean(self, scanner, tmp_path):
        # Measured: an empty chart, or one whose only template renders nothing
        # (`{{- if .Values.enabled }}` + enabled:false), yields no Results. A
        # Helm chart root must be skipped by the gate (only Terraform dirs are
        # expected to report).
        chart = tmp_path / "chart"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: c\nversion: 0.1.0\n")
        tmpl = chart / "templates" / "pod.yaml"
        tmpl.write_text("kind: Pod\n")
        assert (
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2}),
                fallback_path=str(tmpl),
                base_dir=str(chart),
            )
            == []
        )

    def test_misconf_summary_is_a_genuine_clean(self, scanner, tmp_path):
        # A Terraform module / Dockerfile that legitimately has zero
        # misconfigurations carries a Result with MisconfSummary -> clean.
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu:22.04\nUSER app\n")
        payload = json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "Dockerfile",
                        "Class": "config",
                        "Type": "dockerfile",
                        "MisconfSummary": {"Successes": 27, "Failures": 0},
                    }
                ],
            }
        )
        assert scanner._parse_trivy_config_json(payload, fallback_path=str(df)) == []

    def test_no_results_on_plain_yaml_is_skipped_not_degraded(self, scanner, tmp_path):
        # Parsed YAML trivy ignores: absence of Results is expected.
        plain = tmp_path / "config.yaml"
        plain.write_text("retries: 3\n")
        assert (
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2}), fallback_path=str(plain)
            )
            == []
        )

    def test_no_results_on_kustomization_is_clean(self, scanner, tmp_path):
        # MEASURED: `kind: Kustomization` yields rc 0 with no Results. YAML is
        # NOT in the gate by kind/apiVersion, or every kustomize repo would
        # carry a permanent false `degraded`.
        kustomization = tmp_path / "kustomization.yaml"
        kustomization.write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "resources:\n"
            "  - deployment.yaml\n"
        )
        assert (
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2}), fallback_path=str(kustomization)
            )
            == []
        )

    def test_no_results_on_deployment_yaml_is_clean(self, scanner, tmp_path):
        # A parsed k8s manifest trivy ignores is clean; only OUR parse failure
        # puts YAML in the gate.
        manifest = tmp_path / "deployment.yaml"
        manifest.write_text("apiVersion: apps/v1\nkind: Deployment\n")
        assert (
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2}), fallback_path=str(manifest)
            )
            == []
        )

    def test_no_results_on_malformed_yaml_is_partial(self, scanner, tmp_path):
        broken = tmp_path / "deployment.yaml"
        broken.write_text("apiVersion: [\n")
        with pytest.raises(ScannerPartialRunError):
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2}), fallback_path=str(broken)
            )

    def test_no_results_on_empty_cfn_json_is_clean(self, scanner, tmp_path):
        # Measured: `AWSTemplateFormatVersion` without `Resources` legitimately
        # yields nothing — it must not degrade.
        cfn = tmp_path / "stack.json"
        cfn.write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09"}))
        assert (
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2}), fallback_path=str(cfn)
            )
            == []
        )

    def test_no_results_on_cfn_json_with_resources_is_partial(self, scanner, tmp_path):
        cfn = tmp_path / "stack.json"
        cfn.write_text(
            json.dumps(
                {
                    "AWSTemplateFormatVersion": "2010-09-09",
                    "Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}},
                }
            )
        )
        with pytest.raises(ScannerPartialRunError):
            scanner._parse_trivy_config_json(
                json.dumps({"SchemaVersion": 2}), fallback_path=str(cfn)
            )


class TestScanOrchestration:
    async def test_unavailable_returns_empty(self):
        scanner = IaCScanner()
        scanner.trivy_available = False
        assert await scanner.scan(["Dockerfile"]) == []
        assert scanner.is_available() is False

    async def test_no_iac_targets_returns_empty(self):
        scanner = IaCScanner()
        scanner.trivy_available = True
        # Only source files -> nothing for trivy config -> no CLI invocation.
        assert await scanner.scan(["/app/main.py", "/app/index.js"]) == []

    async def test_scan_filters_to_iac_and_parses(self, monkeypatch):
        scanner = IaCScanner()
        scanner.trivy_available = True

        invoked: list[tuple] = []

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (_payload([_misconfig()]).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            invoked.append(cmd)
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        # mix of a source file (skipped) and a Dockerfile (scanned)
        matches = await scanner.scan(["/app/main.py", "/app/Dockerfile"])
        assert len(matches) == 1
        assert matches[0].vulnerability_type == VulnerabilityType.PRIVILEGE_ESCALATION
        # exactly ONE trivy invocation (the .py was filtered out)
        assert len(invoked) == 1
        cmd = invoked[0]
        assert "config" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert "/app/Dockerfile" in cmd
        assert "/app/main.py" not in cmd

    async def test_scan_attributes_garbage_relative_target_to_scanned_file(self, monkeypatch):
        # End-to-end for the 2026-11-05 defect: the CLI reports a relative
        # Target that no longer matches anything, and the finding must still
        # carry the absolute path the scanner actually read.
        scanner = IaCScanner()
        scanner.trivy_available = True

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                payload = _payload([_misconfig()], target="../../../../app/Dockerfile")
                return (payload.encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        matches = await scanner.scan(["/workspace/repo/dev/check/Dockerfile"])
        assert [m.file_path for m in matches] == ["/workspace/repo/dev/check/Dockerfile"]

    async def test_scan_dedupes_repeated_targets(self, monkeypatch):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked: list[tuple] = []

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (_payload([]).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            invoked.append(cmd)
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        await scanner.scan(["/app/Dockerfile", "/app/Dockerfile"])
        assert len(invoked) == 1

    async def test_mixed_clean_and_unparsed_targets_degrade_with_partial_findings(
        self, monkeypatch, tmp_path
    ):
        # One target is genuinely clean (Result + MisconfSummary), one has a
        # finding, and one returns no Results at all. The run must DEGRADE and
        # keep the findings the analysed targets produced — never report the
        # mixed run as ok, and never discard what was found.
        scanner = IaCScanner()
        scanner.trivy_available = True
        clean = tmp_path / "clean" / "Dockerfile"
        finding = tmp_path / "finding" / "Dockerfile"
        unparsed = tmp_path / "broken" / "Dockerfile"
        for path in (clean, finding, unparsed):
            path.parent.mkdir()
            path.write_text("FROM ubuntu:22.04\n")

        clean_report = json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": str(clean),
                        "Class": "config",
                        "Type": "dockerfile",
                        "MisconfSummary": {"Successes": 27, "Failures": 0},
                    }
                ],
            }
        )

        class _FakeProc:
            returncode = 0

            def __init__(self, payload: bytes):
                self._payload = payload

            async def communicate(self):
                return (self._payload, b"")

        async def _fake_exec(*cmd, **kwargs):
            target = cmd[-1]
            if target == str(clean):
                return _FakeProc(clean_report.encode())
            if target == str(finding):
                return _FakeProc(_payload([_misconfig()], target=str(finding)).encode())
            return _FakeProc(json.dumps({"SchemaVersion": 2}).encode())

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        with pytest.raises(ScannerPartialRunError) as excinfo:
            await scanner.scan([str(clean), str(finding), str(unparsed)])
        assert [m.file_path for m in excinfo.value.partial_findings] == [str(finding)]

    def test_is_available_uses_which(self, monkeypatch):
        import services.iac_scanner as mod

        monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/local/bin/trivy")
        assert IaCScanner().is_available() is True

    def test_is_unavailable_when_which_returns_none(self, monkeypatch):
        import services.iac_scanner as mod

        monkeypatch.setattr(mod.shutil, "which", lambda name: None)
        assert IaCScanner().is_available() is False


class TestIsTerraform:
    @pytest.mark.parametrize("path", ["main.tf", "/infra/variables.tf", "modules/db.tofu"])
    def test_accepts_terraform(self, path):
        assert _is_terraform(path) is True

    @pytest.mark.parametrize("path", ["Dockerfile", "/app/deployment.yaml", "values.yml", "app.py"])
    def test_rejects_non_terraform(self, path):
        assert _is_terraform(path) is False


class TestTerraformPerDirectory:
    """v2: Terraform scanned per-directory (module-aware); Dockerfile/YAML per-file."""

    def _recording_exec(self, monkeypatch, payload_target="main.tf"):
        invoked: list[tuple] = []

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (_payload([_misconfig()], target=payload_target).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            invoked.append(cmd)
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        return invoked

    async def test_terraform_scanned_per_directory(self, monkeypatch):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        await scanner.scan(["/infra/main.tf", "/infra/variables.tf", "/other/db.tf"])
        # Two unique module dirs -> exactly two invocations, each targeting a DIR.
        assert len(invoked) == 2
        scanned = {cmd[-1] for cmd in invoked}
        assert scanned == {"/infra", "/other"}
        # No .tf FILE is passed directly to trivy.
        for cmd in invoked:
            assert not cmd[-1].endswith(".tf")

    async def test_terraform_and_dockerfile_mixed(self, monkeypatch):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        await scanner.scan(["/infra/main.tf", "/app/Dockerfile"])
        targets = {cmd[-1] for cmd in invoked}
        # Dockerfile scanned per-FILE; Terraform scanned per-DIR.
        assert targets == {"/app/Dockerfile", "/infra"}

    async def test_terraform_same_dir_deduped(self, monkeypatch):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        await scanner.scan(["/infra/main.tf", "/infra/variables.tf", "/infra/outputs.tf"])
        # One module dir -> ONE invocation (a net reduction vs per-file v1).
        assert len(invoked) == 1
        assert invoked[0][-1] == "/infra"

    def test_dir_mode_resolves_relative_target_to_absolute(self, scanner):
        # trivy reports Target relative to the scanned dir in module mode.
        matches = scanner._parse_trivy_config_json(
            _payload([_misconfig()], target="main.tf"), base_dir="/infra"
        )
        assert len(matches) == 1
        assert matches[0].file_path == "/infra/main.tf"

    def test_dir_mode_leaves_absolute_target_unchanged(self, scanner):
        matches = scanner._parse_trivy_config_json(
            _payload([_misconfig()], target="/infra/main.tf"), base_dir="/infra"
        )
        assert len(matches) == 1
        assert matches[0].file_path == "/infra/main.tf"

    def test_file_mode_target_unchanged(self, scanner):
        # No base_dir and no fallback (direct parser use) -> Target used as-is.
        matches = scanner._parse_trivy_config_json(
            _payload([_misconfig()], target="/app/Dockerfile")
        )
        assert len(matches) == 1
        assert matches[0].file_path == "/app/Dockerfile"

    def test_file_mode_relative_target_uses_scanned_path(self, scanner):
        # Live 2026-11-05: trivy reported Target "../../../../app/Dockerfile"
        # for the file <repo>/dev/check/Dockerfile. That relative Target names
        # a path that does not exist; the file we handed trivy is the truth.
        matches = scanner._parse_trivy_config_json(
            _payload([_misconfig()], target="../../../../app/Dockerfile"),
            fallback_path="/workspace/repo/dev/check/Dockerfile",
        )
        assert len(matches) == 1
        assert matches[0].file_path == "/workspace/repo/dev/check/Dockerfile"

    def test_file_mode_absolute_target_wins_over_fallback(self, scanner):
        # An absolute Target is trivy's own resolution — keep it.
        matches = scanner._parse_trivy_config_json(
            _payload([_misconfig()], target="/app/Dockerfile"),
            fallback_path="/workspace/repo/Dockerfile",
        )
        assert len(matches) == 1
        assert matches[0].file_path == "/app/Dockerfile"

    def test_dir_mode_still_wins_over_fallback(self, scanner):
        # Directory mode is unchanged: relative Target resolves against
        # base_dir, never against the directory fallback.
        matches = scanner._parse_trivy_config_json(
            _payload([_misconfig()], target="main.tf"),
            fallback_path="/infra",
            base_dir="/infra",
        )
        assert len(matches) == 1
        assert matches[0].file_path == "/infra/main.tf"


class TestIsYaml:
    @pytest.mark.parametrize("path", ["deployment.yaml", "/chart/values.yml", "Chart.yaml"])
    def test_accepts_yaml(self, path):
        assert _is_yaml(path) is True

    @pytest.mark.parametrize("path", ["main.tf", "Dockerfile", "app.py", "config.json"])
    def test_rejects_non_yaml(self, path):
        assert _is_yaml(path) is False


class TestFindChartRoot:
    """v3: a YAML maps to its Helm chart root (outermost ancestor dir with a
    Chart.yaml), or None when it is a standalone manifest. Filesystem-based."""

    def test_no_chart_returns_none(self, tmp_path):
        manifest = tmp_path / "k8s" / "deployment.yaml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("kind: Deployment\n")
        assert _find_chart_root(str(manifest)) is None

    def test_template_maps_to_chart_root(self, tmp_path):
        chart = tmp_path / "mychart"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: mychart\nversion: 0.1.0\n")
        tmpl = chart / "templates" / "deployment.yaml"
        tmpl.write_text("kind: Deployment\n")
        assert _find_chart_root(str(tmpl)) == str(chart)

    def test_chart_yaml_itself_maps_to_chart_root(self, tmp_path):
        chart = tmp_path / "mychart"
        chart.mkdir()
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: mychart\nversion: 0.1.0\n")
        (chart / "values.yaml").write_text("replicas: 1\n")
        assert _find_chart_root(str(chart / "values.yaml")) == str(chart)

    def test_subchart_template_maps_to_outermost_umbrella(self, tmp_path):
        umbrella = tmp_path / "umbrella"
        (umbrella / "charts" / "sub" / "templates").mkdir(parents=True)
        (umbrella / "Chart.yaml").write_text("apiVersion: v2\nname: umbrella\nversion: 0.1.0\n")
        (umbrella / "charts" / "sub" / "Chart.yaml").write_text(
            "apiVersion: v2\nname: sub\nversion: 0.1.0\n"
        )
        tmpl = umbrella / "charts" / "sub" / "templates" / "pod.yaml"
        tmpl.write_text("kind: Pod\n")
        # Outermost Chart.yaml wins -> the umbrella is scanned once (rendering
        # covers the subchart), not parent+subchart twice.
        assert _find_chart_root(str(tmpl)) == str(umbrella)

    def test_walk_is_bounded(self, tmp_path):
        # Chart.yaml far above the cap is NOT found (bounded walk; never reaches
        # the filesystem root).
        deep = tmp_path / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "h" / "i" / "j"
        deep.mkdir(parents=True)
        (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: x\nversion: 0.1.0\n")
        manifest = deep / "deployment.yaml"
        manifest.write_text("kind: Deployment\n")
        assert _find_chart_root(str(manifest), max_levels=2) is None


class TestHelmChartPerDirectory:
    """v3: Helm-chart YAML scanned per chart-root dir (rendered); standalone
    YAML still per-file; Terraform/Dockerfile unchanged. Chart detection is
    filesystem-based, so real chart dirs are built under tmp_path."""

    def _recording_exec(self, monkeypatch):
        invoked: list[tuple] = []

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (_payload([_misconfig()]).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            invoked.append(cmd)
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        return invoked

    @staticmethod
    def _make_chart(root: Path, name: str = "mychart") -> Path:
        chart = root / name
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text(f"apiVersion: v2\nname: {name}\nversion: 0.1.0\n")
        (chart / "values.yaml").write_text("replicas: 1\n")
        return chart

    async def test_helm_chart_scanned_per_chart_root(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        chart = self._make_chart(tmp_path)
        tmpl = chart / "templates" / "deployment.yaml"
        tmpl.write_text("kind: Deployment\n")
        await scanner.scan([str(tmpl)])
        # The chart ROOT dir is scanned, NOT the template file.
        assert len(invoked) == 1
        assert invoked[0][-1] == str(chart)

    async def test_helm_chart_deduped(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        chart = self._make_chart(tmp_path)
        (chart / "templates" / "a.yaml").write_text("kind: Pod\n")
        (chart / "templates" / "b.yaml").write_text("kind: Service\n")
        await scanner.scan(
            [str(chart / "templates" / "a.yaml"), str(chart / "templates" / "b.yaml")]
        )
        # Two templates in one chart -> ONE invocation (the chart root).
        assert len(invoked) == 1
        assert invoked[0][-1] == str(chart)

    async def test_chart_yaml_and_values_map_to_chart_root(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        chart = self._make_chart(tmp_path)
        await scanner.scan([str(chart / "Chart.yaml"), str(chart / "values.yaml")])
        assert len(invoked) == 1
        assert invoked[0][-1] == str(chart)

    async def test_standalone_yaml_still_per_file(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        manifest = tmp_path / "k8s" / "deployment.yaml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("kind: Deployment\n")
        await scanner.scan([str(manifest)])
        # No Chart.yaml ancestor -> per-FILE (unchanged behaviour).
        assert len(invoked) == 1
        assert invoked[0][-1] == str(manifest)

    async def test_helm_terraform_dockerfile_mixed(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        chart = self._make_chart(tmp_path)
        tmpl = chart / "templates" / "deployment.yaml"
        tmpl.write_text("kind: Deployment\n")
        tf = tmp_path / "infra" / "main.tf"
        tf.parent.mkdir(parents=True)
        tf.write_text("# tf\n")
        df = tmp_path / "app" / "Dockerfile"
        df.parent.mkdir(parents=True)
        df.write_text("FROM ubuntu:22.04\n")
        await scanner.scan([str(tmpl), str(tf), str(df)])
        targets = {cmd[-1] for cmd in invoked}
        # Dockerfile per-file; Terraform per parent-dir; Helm per chart-root.
        assert targets == {str(df), str(tf.parent), str(chart)}


class TestIsCloudFormation:
    """v4: a *.json is an IaC target ONLY when its content is a CloudFormation
    template (content-sniffed, not extension-based). Filesystem-based."""

    def test_format_version_marker_is_cfn(self, tmp_path):
        f = tmp_path / "stack.json"
        f.write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}))
        assert _is_cloudformation(str(f)) is True

    def test_resources_with_aws_type_is_cfn(self, tmp_path):
        # No format version, but a Resources map with an AWS:: Type -> CFN.
        f = tmp_path / "template.json"
        f.write_text(
            json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}})
        )
        assert _is_cloudformation(str(f)) is True

    @pytest.mark.parametrize("prefix", ["Custom::", "Alexa::"])
    def test_resources_with_custom_or_alexa_type_is_cfn(self, tmp_path, prefix):
        f = tmp_path / "template.json"
        f.write_text(json.dumps({"Resources": {"R": {"Type": f"{prefix}Thing"}}}))
        assert _is_cloudformation(str(f)) is True

    def test_package_json_is_not_cfn(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"name": "app", "version": "1.0.0", "dependencies": {"x": "^1"}}))
        assert _is_cloudformation(str(f)) is False

    def test_tsconfig_is_not_cfn(self, tmp_path):
        f = tmp_path / "tsconfig.json"
        f.write_text(json.dumps({"compilerOptions": {"strict": True}}))
        assert _is_cloudformation(str(f)) is False

    def test_resources_without_aws_type_is_not_cfn(self, tmp_path):
        # A Resources key that is not CFN-shaped (no AWS::/Custom::/Alexa:: Type).
        f = tmp_path / "data.json"
        f.write_text(json.dumps({"Resources": {"a": {"Type": "MyApp::Thing"}}}))
        assert _is_cloudformation(str(f)) is False

    def test_json_array_is_not_cfn(self, tmp_path):
        f = tmp_path / "list.json"
        f.write_text(json.dumps([1, 2, 3]))
        assert _is_cloudformation(str(f)) is False

    def test_malformed_json_is_not_cfn(self, tmp_path):
        f = tmp_path / "broken.json"
        f.write_text('{"Resources": {')
        assert _is_cloudformation(str(f)) is False

    def test_non_json_suffix_is_not_cfn(self, tmp_path):
        # CFN-shaped content but a .yaml suffix -> handled by the YAML path, not here.
        f = tmp_path / "stack.yaml"
        f.write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09"}))
        assert _is_cloudformation(str(f)) is False

    def test_oversize_json_is_not_cfn(self, tmp_path, monkeypatch):
        import services.iac_scanner as mod

        f = tmp_path / "huge.json"
        f.write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09"}))
        monkeypatch.setattr(mod, "_MAX_CFN_BYTES", 1)
        assert _is_cloudformation(str(f)) is False

    def test_missing_file_is_not_cfn(self, tmp_path):
        assert _is_cloudformation(str(tmp_path / "nope.json")) is False


class TestCloudFormationPerFile:
    """v4: a content-sniffed CloudFormation *.json is scanned PER-FILE (it is a
    single self-contained template); a non-CFN *.json is ignored. Detection is
    filesystem-based, so real files are built under tmp_path."""

    def _recording_exec(self, monkeypatch):
        invoked: list[tuple] = []

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (_payload([_misconfig()]).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            invoked.append(cmd)
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        return invoked

    @staticmethod
    def _cfn(path: Path) -> Path:
        path.write_text(
            json.dumps(
                {
                    "AWSTemplateFormatVersion": "2010-09-09",
                    "Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}},
                }
            )
        )
        return path

    async def test_cfn_json_scanned_per_file(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        cfn = self._cfn(tmp_path / "stack.json")
        await scanner.scan([str(cfn)])
        # The CFN file itself is the target (per-file, NOT a directory).
        assert len(invoked) == 1
        assert invoked[0][-1] == str(cfn)

    async def test_non_cfn_json_ignored(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "app", "dependencies": {}}))
        assert await scanner.scan([str(pkg)]) == []
        # A non-CFN .json triggers NO trivy invocation.
        assert len(invoked) == 0

    async def test_cfn_mixed_with_dockerfile_terraform_helm(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        invoked = self._recording_exec(monkeypatch)
        cfn = self._cfn(tmp_path / "stack.json")
        df = tmp_path / "app" / "Dockerfile"
        df.parent.mkdir(parents=True)
        df.write_text("FROM ubuntu:22.04\n")
        tf = tmp_path / "infra" / "main.tf"
        tf.parent.mkdir(parents=True)
        tf.write_text("# tf\n")
        chart = tmp_path / "mychart"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: mychart\nversion: 0.1.0\n")
        tmpl = chart / "templates" / "pod.yaml"
        tmpl.write_text("kind: Pod\n")
        await scanner.scan([str(cfn), str(df), str(tf), str(tmpl)])
        targets = {cmd[-1] for cmd in invoked}
        # CFN + Dockerfile per-FILE; Terraform per parent-dir; Helm per chart-root.
        assert targets == {str(cfn), str(df), str(tf.parent), str(chart)}

    async def test_cfn_finding_language_is_cloudformation(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        cfn = self._cfn(tmp_path / "stack.json")

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (_payload([_misconfig()], target=str(cfn)).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        matches = await scanner.scan([str(cfn)])
        assert len(matches) == 1
        assert matches[0].language == "cloudformation"


class TestIsComposeFile:
    """Compose is classified by NAME, before the trivy partitioning."""

    @pytest.mark.parametrize(
        "path",
        [
            "docker-compose.yml",
            "docker-compose.yaml",
            "/app/docker-compose.override.yml",
            "docker-compose.prod.yaml",
            "compose.yml",
            "/srv/compose.yaml",
            # MEASURED miss before this fix: an override was not matched, fell
            # through to trivy and a `privileged: true` override read CLEAN.
            "compose.override.yaml",
            "/deep/path/compose.override.yml",
            "compose.prod.yml",
            "compose-dev.yaml",
            "compose_test.yml",
            # `<something>-compose.yml` at any depth.
            "my-compose.yml",
            "dev-compose.yaml",
            "/charts/x/dev-compose.yml",
            "DOCKER-COMPOSE.YML",
        ],
    )
    def test_accepts_compose(self, path):
        assert _is_compose_file(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            "config.yaml",
            "docker-compose.txt",
            "compose.yml.bak",
            "composer.yaml",  # prefix boundary: PHP composer, not compose
            "composer.json",
            "composefoo.yml",
            "Dockerfile",
        ],
    )
    def test_rejects_non_compose(self, path):
        assert _is_compose_file(path) is False


class TestComposeParsing:
    """Compose files are parsed in-process with PyYAML.

    trivy config does not analyse them at all (measured: rc 0, `Results`
    omitted), so a `privileged: true` service read CLEAN before this parser.
    """

    PRIVILEGED = """\
services:
  app:
    image: nginx:latest
    privileged: true
"""

    DOCKER_SOCK_SHORT = """\
services:
  app:
    image: docker:cli
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
"""

    DOCKER_SOCK_LONG = """\
services:
  app:
    image: docker:cli
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
"""

    HOST_BIND = """\
services:
  app:
    image: nginx:latest
    volumes:
      - /etc/passwd:/etc/passwd:ro
      - ./data:/data
      - named:/named
      - /container-only
"""

    def _findings(self, tmp_path, body, name="docker-compose.yml", env=None):
        target = tmp_path / name
        target.write_text(body)
        return IaCScanner()._parse_compose_manifest(body, str(target), env=env)

    def test_privileged_is_critical(self, tmp_path):
        matches = self._findings(tmp_path, self.PRIVILEGED)
        assert len(matches) == 1
        m = matches[0]
        assert m.engine == "trivy-iac"
        assert m.pattern_id == "COMPOSE-PRIVILEGED"
        assert m.vulnerability_type == VulnerabilityType.PRIVILEGE_ESCALATION
        assert m.severity == VulnerabilitySeverity.CRITICAL
        assert m.language == "docker-compose"
        assert m.line_start == 4
        target = str(tmp_path / "docker-compose.yml")
        # The service is part of the id so two flow-style services on one line
        # stay distinct through the detector's report merge.
        assert m.id == f"trivy_config_COMPOSE-PRIVILEGED_app_{target}_4"

    @pytest.mark.parametrize(
        "body",
        [
            # MEASURED false positive: `privileged` as DATA under environment /
            # build.args must never fire — only the service-level flag counts.
            'services:\n  app:\n    environment:\n      privileged: "true"\n',
            "services:\n  app:\n    build:\n      args:\n        privileged: true\n",
            "services:\n  app:\n    environment:\n      privileged: true\n",
        ],
        ids=["env-string", "build-arg-bool", "env-bool"],
    )
    def test_privileged_outside_service_level_does_not_fire(self, tmp_path, body):
        assert self._findings(tmp_path, body) == []

    def test_network_mode_host_is_high(self, tmp_path):
        matches = self._findings(tmp_path, "services:\n  app:\n    network_mode: host\n")
        assert [m.pattern_id for m in matches] == ["COMPOSE-NETWORK-HOST"]
        assert matches[0].vulnerability_type == VulnerabilityType.PRIVILEGE_ESCALATION
        assert matches[0].severity == VulnerabilitySeverity.HIGH
        assert matches[0].line_start == 3

    def test_pid_host_is_high(self, tmp_path):
        matches = self._findings(tmp_path, "services:\n  app:\n    pid: host\n")
        assert [m.pattern_id for m in matches] == ["COMPOSE-PID-HOST"]
        assert matches[0].vulnerability_type == VulnerabilityType.PRIVILEGE_ESCALATION
        assert matches[0].severity == VulnerabilitySeverity.HIGH
        assert matches[0].line_start == 3

    @pytest.mark.parametrize("capability", ["SYS_ADMIN", "ALL", "sys_admin"])
    def test_dangerous_cap_add_is_critical(self, tmp_path, capability):
        body = f"services:\n  app:\n    cap_add:\n      - {capability}\n"
        matches = self._findings(tmp_path, body)
        assert [m.pattern_id for m in matches] == ["COMPOSE-CAP-ADD"]
        assert matches[0].vulnerability_type == VulnerabilityType.PRIVILEGE_ESCALATION
        assert matches[0].severity == VulnerabilitySeverity.CRITICAL
        assert matches[0].line_start == 4

    def test_safe_cap_add_does_not_fire(self, tmp_path):
        body = "services:\n  app:\n    cap_add:\n      - NET_BIND_SERVICE\n"
        assert self._findings(tmp_path, body) == []

    def test_cap_add_scalar_is_detected(self, tmp_path):
        body = "services:\n  app:\n    cap_add: SYS_ADMIN\n"
        matches = self._findings(tmp_path, body)
        assert [m.pattern_id for m in matches] == ["COMPOSE-CAP-ADD"]
        assert matches[0].severity == VulnerabilitySeverity.CRITICAL

    MERGE_KEY = """\
x-h: &h {privileged: true, network_mode: host, cap_add: [SYS_ADMIN]}
services:
  app:
    <<: *h
"""

    def test_merge_key_anchor_is_expanded(self, tmp_path):
        # MEASURED false negative: PyYAML `compose` nodes were walked without
        # resolving `<<`, so `docker compose config` applied all three of these
        # and the scanner reported CLEAN.
        matches = self._findings(tmp_path, self.MERGE_KEY)
        assert sorted(m.pattern_id for m in matches) == [
            "COMPOSE-CAP-ADD",
            "COMPOSE-NETWORK-HOST",
            "COMPOSE-PRIVILEGED",
        ]
        assert {m.line_start for m in matches} == {1}  # the anchor definition
        assert all("app" in m.id for m in matches)

    def test_merge_key_explicit_key_overrides_anchor(self, tmp_path):
        body = """\
x-h: &h {privileged: true, network_mode: host}
services:
  app:
    <<: *h
    privileged: false
"""
        matches = self._findings(tmp_path, body)
        # docker compose: the explicit `privileged: false` wins over the merge.
        assert [m.pattern_id for m in matches] == ["COMPOSE-NETWORK-HOST"]

    SERVICES_MERGE = """\
x-svcs: &svcs
  app:
    privileged: true
services:
  <<: *svcs
"""

    @staticmethod
    def _dag_compose(n: int) -> str:
        """A binary merge DAG: each anchor merges the previous one and a0."""
        lines = ["x-a0: &a0 {image: base, privileged: true}"]
        for i in range(1, n):
            lines.append(f"x-a{i}: &a{i} {{<<: [*a{i - 1}, *a0]}}")
        lines += ["services:", "  app:", f"    <<: *a{n - 1}"]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _chain_compose(depth: int) -> str:
        """A linear chain of `depth` anchors, to exceed the merge-depth budget."""
        lines = ["x-a0: &a0 {image: base}"]
        for i in range(1, depth):
            lines.append(f"x-a{i}: &a{i} {{<<: *a{i - 1}}}")
        lines += ["services:", "  app:", f"    <<: *a{depth - 1}"]
        return "\n".join(lines) + "\n"

    @pytest.mark.parametrize(
        ("body", "env", "expected"),
        [
            # `${VAR:-default}` with VAR unset -> the default decides.
            (
                "services:\n  app:\n    privileged: ${IAC_SCAN_PRIV:-true}\n",
                {},
                "COMPOSE-PRIVILEGED",
            ),
            # `${VAR:-false}` -> false -> clean.
            (
                "services:\n  app:\n    privileged: ${IAC_SCAN_PRIV:-false}\n",
                {},
                None,
            ),
            # `-` (without the colon) also supplies a default when unset.
            (
                "services:\n  app:\n    privileged: ${IAC_SCAN_PRIV-true}\n",
                {},
                "COMPOSE-PRIVILEGED",
            ),
            # A variable set in the environment wins over the default.
            (
                "services:\n  app:\n    privileged: ${IAC_SCAN_PRIV:-true}\n",
                {"IAC_SCAN_PRIV": "false"},
                None,
            ),
            # Bare `$VAR` form.
            (
                "services:\n  app:\n    privileged: $IAC_SCAN_PRIV\n",
                {"IAC_SCAN_PRIV": "true"},
                "COMPOSE-PRIVILEGED",
            ),
            # Interpolation applies to the other security keys too.
            (
                "services:\n  app:\n    network_mode: ${IAC_SCAN_MODE:-host}\n",
                {},
                "COMPOSE-NETWORK-HOST",
            ),
            (
                "services:\n  app:\n    pid: ${IAC_SCAN_PID:-host}\n",
                {},
                "COMPOSE-PID-HOST",
            ),
            (
                "services:\n  app:\n    cap_add:\n      - ${IAC_SCAN_CAP:-SYS_ADMIN}\n",
                {},
                "COMPOSE-CAP-ADD",
            ),
        ],
    )
    def test_interpolation_is_expanded(self, tmp_path, body, env, expected):
        matches = self._findings(tmp_path, body, env=env)
        assert [m.pattern_id for m in matches] == ([expected] if expected else [])

    def test_interpolation_in_volume_source(self, tmp_path):
        body = (
            "services:\n  app:\n    volumes:\n"
            "      - ${IAC_SCAN_SOCK:-/var/run/docker.sock}:/var/run/docker.sock\n"
        )
        matches = self._findings(tmp_path, body, env={})
        assert [m.pattern_id for m in matches] == ["COMPOSE-DOCKER-SOCK"]

    def test_unresolved_interpolation_degrades(self, tmp_path):
        body = "services:\n  app:\n    privileged: ${IAC_SCAN_UNSET}\n"
        with pytest.raises(ScannerPartialRunError) as excinfo:
            self._findings(tmp_path, body, env={})
        message = str(excinfo.value)
        assert "UNCHECKED" in message
        assert "privileged" in message
        assert "IAC_SCAN_UNSET" in message

    def test_interpolation_reads_process_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("IAC_SCAN_PRIV", "false")
        body = "services:\n  app:\n    privileged: ${IAC_SCAN_PRIV:-true}\n"
        target = tmp_path / "docker-compose.yml"
        target.write_text(body)
        assert IaCScanner()._scan_compose(str(target)) == []

    def test_extends_degrades(self, tmp_path):
        body = (
            "services:\n  app:\n    image: nginx\n"
            "    extends:\n      file: base.yml\n      service: base\n"
        )
        with pytest.raises(ScannerPartialRunError) as excinfo:
            self._findings(tmp_path, body, env={})
        message = str(excinfo.value)
        assert "'extends'" in message
        assert "app" in message

    def test_top_level_extends_degrades(self, tmp_path):
        body = "extends:\n  file: base.yml\nservices:\n  app:\n    image: nginx\n"
        with pytest.raises(ScannerPartialRunError) as excinfo:
            self._findings(tmp_path, body, env={})
        assert "'extends'" in str(excinfo.value)

    def test_top_level_include_degrades(self, tmp_path):
        body = "include:\n  - other.yml\nservices:\n  app:\n    image: nginx\n"
        with pytest.raises(ScannerPartialRunError) as excinfo:
            self._findings(tmp_path, body, env={})
        assert "'include'" in str(excinfo.value)

    @pytest.mark.parametrize(
        "line",
        [
            "    privileged: {enabled: true}\n",
            "    network_mode: [host]\n",
            "    pid: {host: true}\n",
            "    cap_add: {SYS_ADMIN: true}\n",
            "    privileged: maybe\n",
        ],
        ids=["privileged-mapping", "network-sequence", "pid-mapping", "cap-mapping", "not-a-bool"],
    )
    def test_non_evaluable_value_degrades(self, tmp_path, line):
        body = "services:\n  app:\n" + line
        with pytest.raises(ScannerPartialRunError) as excinfo:
            self._findings(tmp_path, body, env={})
        assert "cannot be checked" in str(excinfo.value)

    def test_services_level_merge_is_expanded(self, tmp_path):
        # MEASURED false negative: iterating services.value raw sees only the
        # `<<` key, so the merged (docker-compose-applied) service read CLEAN.
        matches = self._findings(tmp_path, self.SERVICES_MERGE)
        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]
        assert "app" in matches[0].id

    def test_large_merge_dag_resolves_within_time_bound(self, tmp_path):
        # 36 anchors, ~70 merge sources: memoisation must keep it linear.
        body = self._dag_compose(36)
        start = time.perf_counter()
        matches = self._findings(tmp_path, body)
        elapsed = time.perf_counter() - start
        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]
        assert elapsed < 2.0, f"36-anchor merge DAG took {elapsed:.2f}s"

    def test_over_budget_merge_degrades_with_reason(self, tmp_path):
        target = tmp_path / "docker-compose.yml"
        target.write_text(self._chain_compose(80))  # depth 80 > 64
        with pytest.raises(ScannerPartialRunError) as excinfo:
            IaCScanner()._scan_compose(str(target))
        message = str(excinfo.value)
        assert "merge budget" in message
        assert str(target) in message
        assert "partially checked" in message

    def test_recursion_error_from_yaml_compose_degrades(self, monkeypatch, tmp_path):
        import services.iac_scanner as mod

        target = tmp_path / "docker-compose.yml"
        target.write_text("services: {}\n")

        def _boom(_text):
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(mod.yaml, "compose", _boom)
        with pytest.raises(ScannerPartialRunError) as excinfo:
            IaCScanner()._scan_compose(str(target))
        assert "too deeply nested to parse" in str(excinfo.value)
        assert str(target) in str(excinfo.value)

    def test_recursion_error_during_merge_walk_degrades(self, monkeypatch, tmp_path):
        import services.iac_scanner as mod

        target = tmp_path / "docker-compose.yml"
        target.write_text("services:\n  app:\n    privileged: true\n")

        def _boom(*_args, **_kwargs):
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(mod, "_mapping_entries", _boom)
        with pytest.raises(ScannerPartialRunError) as excinfo:
            IaCScanner()._scan_compose(str(target))
        assert "too deeply nested to resolve" in str(excinfo.value)

    def test_merge_key_sequence_earlier_mapping_wins(self, tmp_path):
        body = """\
x-a: &a {privileged: true}
x-b: &b {privileged: false}
services:
  app:
    <<: [*a, *b]
"""
        matches = self._findings(tmp_path, body)
        # YAML merge rules: the earlier mapping in the sequence wins.
        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]

    def test_two_flow_style_services_are_both_reported(self, tmp_path):
        # Both `privileged` keys sit on line 1. Dedupe is keyed by
        # (pattern, service, line) so the second service is not collapsed.
        body = "services: {a: {image: x, privileged: true}, b: {image: y, privileged: true}}\n"
        matches = self._findings(tmp_path, body)
        assert [m.pattern_id for m in matches] == [
            "COMPOSE-PRIVILEGED",
            "COMPOSE-PRIVILEGED",
        ]
        assert {m.line_start for m in matches} == {1}

    def test_docker_sock_short_syntax(self, tmp_path):
        matches = self._findings(tmp_path, self.DOCKER_SOCK_SHORT)
        assert [m.pattern_id for m in matches] == ["COMPOSE-DOCKER-SOCK"]
        assert matches[0].vulnerability_type == VulnerabilityType.PRIVILEGE_ESCALATION
        assert matches[0].severity == VulnerabilitySeverity.CRITICAL
        assert matches[0].line_start == 5

    def test_docker_sock_long_syntax(self, tmp_path):
        matches = self._findings(tmp_path, self.DOCKER_SOCK_LONG)
        assert [m.pattern_id for m in matches] == ["COMPOSE-DOCKER-SOCK"]
        assert matches[0].severity == VulnerabilitySeverity.CRITICAL
        assert matches[0].line_start == 6  # the `source:` line

    def test_host_bind_is_high(self, tmp_path):
        matches = self._findings(tmp_path, self.HOST_BIND)
        # Only the absolute host source is flagged: relative `./data`, a named
        # volume and a container-only path are not host binds.
        assert [m.pattern_id for m in matches] == ["COMPOSE-HOST-BIND"]
        assert matches[0].vulnerability_type == VulnerabilityType.INFORMATION_DISCLOSURE
        assert matches[0].severity == VulnerabilitySeverity.HIGH
        assert matches[0].line_start == 5

    def test_container_socket_path_is_not_a_host_socket_mount(self, tmp_path):
        # A named volume mounted AT the socket path is not the host socket.
        body = "services:\n  app:\n    volumes:\n      - data:/var/run/docker.sock\n"
        assert self._findings(tmp_path, body) == []

    def test_malformed_compose_raises_partial_run(self, tmp_path):
        target = tmp_path / "docker-compose.yml"
        target.write_text("services: [\n")
        with pytest.raises(ScannerPartialRunError):
            IaCScanner()._scan_compose(str(target))

    def test_non_mapping_compose_raises_partial_run(self, tmp_path):
        target = tmp_path / "compose.yml"
        target.write_text("- just\n- a list\n")
        with pytest.raises(ScannerPartialRunError):
            IaCScanner()._scan_compose(str(target))

    async def test_scan_parses_compose_in_process_and_never_calls_trivy(
        self, monkeypatch, tmp_path
    ):
        scanner = IaCScanner()
        scanner.trivy_available = True
        target = tmp_path / "docker-compose.yml"
        target.write_text(self.PRIVILEGED)

        invoked: list[tuple] = []

        async def _fake_exec(*cmd, **kwargs):
            invoked.append(cmd)
            raise AssertionError("trivy must not be invoked for a compose file")

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        matches = await scanner.scan([str(target)])
        assert invoked == []
        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]

    async def test_scan_malformed_compose_degrades(self, monkeypatch, tmp_path):
        scanner = IaCScanner()
        scanner.trivy_available = True
        target = tmp_path / "docker-compose.yml"
        target.write_text("services: [\n")

        async def _fake_exec(*cmd, **kwargs):
            raise AssertionError("trivy must not be invoked for a compose file")

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        with pytest.raises(ScannerPartialRunError):
            await scanner.scan([str(target)])

    async def test_over_budget_compose_degrades_and_keeps_other_findings(
        self, monkeypatch, tmp_path
    ):
        # The compose file exceeds the merge budget -> DEGRADED, but the Dockerfile
        # finding collected earlier in the same scan is retained.
        scanner = IaCScanner()
        scanner.trivy_available = True
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu:22.04\n")
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(self._chain_compose(80))

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (_payload([_misconfig()], target=str(df)).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        with pytest.raises(ScannerPartialRunError) as excinfo:
            await scanner.scan([str(df), str(compose)])
        assert "merge budget" in str(excinfo.value)
        assert str(compose) in str(excinfo.value)
        assert [m.file_path for m in excinfo.value.partial_findings] == [str(df)]

    async def test_scan_matches_compose_override(self, monkeypatch, tmp_path):
        # MEASURED miss: compose.override.yaml fell through to trivy (no
        # Results) and its `privileged: true` read CLEAN.
        scanner = IaCScanner()
        scanner.trivy_available = True
        target = tmp_path / "compose.override.yaml"
        target.write_text(self.PRIVILEGED)

        invoked: list[tuple] = []

        async def _fake_exec(*cmd, **kwargs):
            invoked.append(cmd)
            raise AssertionError("trivy must not be invoked for a compose file")

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        matches = await scanner.scan([str(target)])
        assert invoked == []
        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]

    async def test_scan_empty_helm_chart_with_no_results_stays_clean(self, monkeypatch, tmp_path):
        # MEASURED: an empty chart / a template that renders nothing yields no
        # Results. The chart root is skipped by the honesty gate.
        scanner = IaCScanner()
        scanner.trivy_available = True
        chart = tmp_path / "chart"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: c\nversion: 0.1.0\n")
        values = chart / "values.yaml"
        values.write_text("enabled: false\n")

        class _FakeProc:
            returncode = 0

            async def communicate(self):
                return (json.dumps({"SchemaVersion": 2}).encode(), b"")

        async def _fake_exec(*cmd, **kwargs):
            return _FakeProc()

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        assert await scanner.scan([str(values)]) == []

    async def test_scan_compose_wins_over_chart_yaml_ancestor(self, monkeypatch, tmp_path):
        # MEASURED false negative: a repo-root Chart.yaml made
        # dev/docker-compose.yml map to the chart root; trivy scanned the chart,
        # returned no Results and the privileged compose read CLEAN. Compose
        # classification must win over the Helm-chart mapping.
        scanner = IaCScanner()
        scanner.trivy_available = True
        (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: repo\nversion: 0.1.0\n")
        dev = tmp_path / "dev"
        dev.mkdir()
        compose = dev / "docker-compose.yml"
        compose.write_text(self.PRIVILEGED)

        invoked: list[tuple] = []

        async def _fake_exec(*cmd, **kwargs):
            invoked.append(cmd)
            raise AssertionError("trivy must not be invoked for a compose file")

        monkeypatch.setattr("utils.subprocess_runner.asyncio.create_subprocess_exec", _fake_exec)
        matches = await scanner.scan([str(compose)])
        assert invoked == []
        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]
        assert matches[0].file_path == str(compose)


@pytest.mark.skipif(
    not IaCScanner().is_available(),
    reason="trivy CLI not installed (present in the image; absent in the CI venv)",
)
class TestIaCLive:
    """Real-CLI proof against the vendored insecure Dockerfile — runs locally / in-pod."""

    async def test_live_detects_dockerfile_misconfig(self, tmp_path):
        scanner = IaCScanner()
        # Copy the fixture to a file named "Dockerfile" so trivy detects the type.
        df = tmp_path / "Dockerfile"
        df.write_text(FIXTURE_DOCKERFILE.read_text())
        matches = await scanner.scan([str(df)])
        assert len(matches) >= 1
        # at least one HIGH or CRITICAL misconfig (the root-user / latest-tag pair)
        assert any(
            m.severity in (VulnerabilitySeverity.HIGH, VulnerabilitySeverity.CRITICAL)
            for m in matches
        )

    async def test_live_hardened_dockerfile_fewer_findings(self, tmp_path):
        scanner = IaCScanner()
        hardened_dir = tmp_path / "hardened"
        hardened_dir.mkdir()
        (hardened_dir / "Dockerfile").write_text(
            'FROM ubuntu:22.04\nRUN useradd -m appuser\nUSER appuser\nCMD ["/bin/true"]\n'
        )
        hardened = await scanner.scan([str(hardened_dir / "Dockerfile")])

        insecure_dir = tmp_path / "insecure"
        insecure_dir.mkdir()
        (insecure_dir / "Dockerfile").write_text(FIXTURE_DOCKERFILE.read_text())
        insecure = await scanner.scan([str(insecure_dir / "Dockerfile")])

        assert len(hardened) < len(insecure)

    async def test_live_terraform_module_scanned_per_directory(self, tmp_path):
        """A multi-file Terraform module is scanned as a directory: trivy resolves
        the variable declared in variables.tf and consumed in main.tf, and the
        finding attributes back to an absolute path inside the module dir."""
        scanner = IaCScanner()
        module = tmp_path / "infra"
        module.mkdir()
        (module / "variables.tf").write_text(
            'variable "ingress_cidr" {\n  type    = string\n  default = "0.0.0.0/0"\n}\n'
        )
        (module / "main.tf").write_text(
            'resource "aws_security_group" "open" {\n'
            '  name = "open"\n'
            "  ingress {\n"
            "    from_port   = 0\n"
            "    to_port     = 0\n"
            '    protocol    = "-1"\n'
            "    cidr_blocks = [var.ingress_cidr]\n"
            "  }\n"
            "}\n"
        )
        # Passing only main.tf triggers DIR mode on its parent, so variables.tf
        # is resolved too (single-file mode could not see the variable).
        matches = await scanner.scan([str(module / "main.tf")])
        assert isinstance(matches, list)
        # Findings attribute to absolute paths inside the scanned module dir.
        for m in matches:
            assert Path(m.file_path).is_absolute()
            assert str(module) in m.file_path

    async def test_live_helm_chart_rendered_and_scanned(self, tmp_path):
        """A Helm chart is scanned at its chart root: trivy renders the Go-
        templated `templates/*.yaml` against values.yaml and scans the result —
        coverage per-file mode cannot produce (the raw template is not valid
        YAML). Passing only a template path triggers chart-root mode."""
        scanner = IaCScanner()
        chart = tmp_path / "insecure-chart"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: insecure-chart\nversion: 0.1.0\n")
        (chart / "values.yaml").write_text("privileged: true\n")
        # A Go-templated pod manifest — NOT valid standalone YAML; only renders
        # at the chart root against values.yaml.
        (chart / "templates" / "pod.yaml").write_text(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            "  name: app\n"
            "spec:\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: nginx:latest\n"
            "      securityContext:\n"
            "        privileged: {{ .Values.privileged }}\n"
            "        runAsNonRoot: false\n"
        )
        matches = await scanner.scan([str(chart / "templates" / "pod.yaml")])
        assert isinstance(matches, list)
        # Findings attribute to absolute paths inside the scanned chart dir.
        for m in matches:
            assert Path(m.file_path).is_absolute()
            assert str(chart) in m.file_path

    async def test_live_cloudformation_json_detected_and_scanned(self, tmp_path):
        """A CloudFormation template authored in JSON is content-sniffed and
        scanned per-file: trivy detects the CFN type and reports the open-ingress
        security group. Coverage impossible pre-v4 (a *.json was never an IaC
        target). A sibling package.json is ignored (not a CFN template)."""
        scanner = IaCScanner()
        cfn = tmp_path / "stack.json"
        cfn.write_text(
            json.dumps(
                {
                    "AWSTemplateFormatVersion": "2010-09-09",
                    "Resources": {
                        "OpenSG": {
                            "Type": "AWS::EC2::SecurityGroup",
                            "Properties": {
                                "GroupDescription": "open to the world",
                                "SecurityGroupIngress": [
                                    {
                                        "IpProtocol": "tcp",
                                        "FromPort": 22,
                                        "ToPort": 22,
                                        "CidrIp": "0.0.0.0/0",
                                    }
                                ],
                            },
                        }
                    },
                }
            )
        )
        # A non-CFN JSON alongside it must NOT be scanned.
        (tmp_path / "package.json").write_text(json.dumps({"name": "app", "dependencies": {}}))
        matches = await scanner.scan([str(cfn), str(tmp_path / "package.json")])
        assert isinstance(matches, list)
        assert len(matches) >= 1
        for m in matches:
            # Findings attribute to the CFN template, never the package.json.
            assert m.file_path == str(cfn)
            assert m.language == "cloudformation"
        assert any(
            m.severity in (VulnerabilitySeverity.HIGH, VulnerabilitySeverity.CRITICAL)
            for m in matches
        )


class TestComposeIncludeResolution:
    """`include:` / `extends.file` are resolved inside the workspace: the
    referenced files are added to the compose scan set and checked once.
    Remote, missing, cyclic and out-of-workspace references stay UNCHECKED."""

    @staticmethod
    def _scanner() -> IaCScanner:
        scanner = IaCScanner()
        scanner.trivy_available = True
        return scanner

    @pytest.mark.asyncio
    async def test_included_file_with_privileged_service_is_reported(self, tmp_path):
        base = tmp_path / "base.yml"
        base.write_text("services:\n  leaked:\n    image: nginx\n    privileged: true\n")
        main = tmp_path / "docker-compose.yml"
        main.write_text("include:\n  - base.yml\nservices:\n  app:\n    image: nginx\n")

        matches = await self._scanner().scan([str(main)])

        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]
        assert matches[0].file_path == str(base)
        assert matches[0].line_start == 4

    @pytest.mark.asyncio
    async def test_mapping_path_list_includes_are_resolved(self, tmp_path):
        """The exact openplanner compose.yaml shape: include is a list holding
        a mapping whose `path` is itself a LIST of two files."""
        (tmp_path / "docker-compose.yml").write_text("services:\n  app:\n    image: nginx\n")
        (tmp_path / "dev").mkdir()
        (tmp_path / "dev" / "compose.dev.yml").write_text(
            "services:\n  dev:\n    image: nginx\n    privileged: true\n"
        )
        main = tmp_path / "compose.yaml"
        main.write_text(
            "include:\n  - path:\n      - docker-compose.yml\n      - dev/compose.dev.yml\n"
        )

        matches = await self._scanner().scan([str(main)])

        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]
        assert matches[0].file_path == str(tmp_path / "dev" / "compose.dev.yml")

    @pytest.mark.asyncio
    async def test_include_cycle_degrades(self, tmp_path):
        main = tmp_path / "docker-compose.yml"
        other = tmp_path / "other.yml"
        main.write_text("include:\n  - other.yml\nservices:\n  app:\n    image: nginx\n")
        other.write_text("include:\n  - docker-compose.yml\nservices:\n  base:\n    image: nginx\n")

        with pytest.raises(ScannerPartialRunError):
            await self._scanner().scan([str(main)])

    @pytest.mark.asyncio
    async def test_missing_include_degrades(self, tmp_path):
        main = tmp_path / "docker-compose.yml"
        main.write_text("include:\n  - missing.yml\nservices:\n  app:\n    image: nginx\n")

        with pytest.raises(ScannerPartialRunError) as excinfo:
            await self._scanner().scan([str(main)])
        assert "UNCHECKED" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_remote_include_degrades(self, tmp_path):
        main = tmp_path / "docker-compose.yml"
        main.write_text(
            "include:\n  - https://example.com/compose.yml\nservices:\n  app:\n    image: nginx\n"
        )

        with pytest.raises(ScannerPartialRunError):
            await self._scanner().scan([str(main)])

    @pytest.mark.asyncio
    async def test_extends_file_in_repo_is_scanned(self, tmp_path):
        base = tmp_path / "base.yml"
        base.write_text("services:\n  base:\n    image: nginx\n    privileged: true\n")
        main = tmp_path / "docker-compose.yml"
        main.write_text(
            "services:\n  app:\n    extends:\n      file: base.yml\n      service: base\n"
        )

        matches = await self._scanner().scan([str(main)])

        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]

    @pytest.mark.asyncio
    async def test_included_file_scanned_once_when_also_a_target(self, tmp_path):
        base = tmp_path / "docker-compose.base.yml"
        base.write_text("services:\n  leaked:\n    image: nginx\n    privileged: true\n")
        main = tmp_path / "docker-compose.yml"
        main.write_text(
            "include:\n  - docker-compose.base.yml\nservices:\n  app:\n    image: nginx\n"
        )

        matches = await self._scanner().scan([str(main), str(base)])

        assert [m.pattern_id for m in matches] == ["COMPOSE-PRIVILEGED"]
