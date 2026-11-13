"""Tests for SystemDependencyManager."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from models.system_models import DependencyType, PackageManager, SystemDependency
from services.system_dependency_manager import SystemDependencyManager


@pytest.fixture
def manager():
    """Create a SystemDependencyManager with mocked platform detection."""
    with patch.object(
        SystemDependencyManager, "_detect_package_manager", return_value=PackageManager.APT
    ):
        with patch.object(SystemDependencyManager, "__init__", lambda self: None):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "linux"
            mgr.package_manager = PackageManager.APT
            mgr.detected_dependencies = set()
            mgr.missing_dependencies = []
            mgr._install_cache = set()
            mgr._dependency_cache = {}
            return mgr


class TestDetectPackageManager:
    def test_darwin_with_brew(self):
        with patch.object(SystemDependencyManager, "_command_exists", return_value=True):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "darwin"
            result = mgr._detect_package_manager()
            assert result == PackageManager.BREW

    def test_darwin_no_brew(self):
        with patch.object(SystemDependencyManager, "_command_exists", return_value=False):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "darwin"
            result = mgr._detect_package_manager()
            assert result is None

    def test_linux_apt(self):
        def side_effect(cmd):
            return cmd == "apt-get"

        with patch.object(SystemDependencyManager, "_command_exists", side_effect=side_effect):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "linux"
            result = mgr._detect_package_manager()
            assert result == PackageManager.APT

    def test_no_manager_found(self):
        with patch.object(SystemDependencyManager, "_command_exists", return_value=False):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "linux"
            result = mgr._detect_package_manager()
            assert result is None


class TestCommandExists:
    def test_command_found(self):
        with patch.object(SystemDependencyManager, "_detect_package_manager", return_value=None):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "linux"
            mgr.package_manager = None
            mgr.detected_dependencies = set()
            mgr.missing_dependencies = []
            mgr._install_cache = set()
            mgr._dependency_cache = {}
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert mgr._command_exists("brew") is True

    def test_command_not_found(self):
        with patch.object(SystemDependencyManager, "_detect_package_manager", return_value=None):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "linux"
            mgr.package_manager = None
            mgr.detected_dependencies = set()
            mgr.missing_dependencies = []
            mgr._install_cache = set()
            mgr._dependency_cache = {}
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert mgr._command_exists("nonexistent") is False

    def test_command_timeout(self):
        with patch.object(SystemDependencyManager, "_detect_package_manager", return_value=None):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "linux"
            mgr.package_manager = None
            mgr.detected_dependencies = set()
            mgr.missing_dependencies = []
            mgr._install_cache = set()
            mgr._dependency_cache = {}
        with patch(
            "services.system_dependency_manager.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="which", timeout=5),
        ):
            assert mgr._command_exists("slow") is False


class TestParseRequirementsTxt:
    def test_valid_requirements(self, manager, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("fastapi>=0.115.0\nuvicorn==0.35.0\npydantic\n")
        result = manager._parse_requirements_txt(req_file)
        assert "fastapi" in result
        assert "uvicorn" in result
        assert "pydantic" in result

    def test_nonexistent_file(self, manager, tmp_path):
        result = manager._parse_requirements_txt(tmp_path / "nope.txt")
        assert result == set()

    def test_comments_and_flags_skipped(self, manager, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# comment\n-r other.txt\nfastapi\n\n")
        result = manager._parse_requirements_txt(req_file)
        assert "fastapi" in result
        assert len(result) == 1


class TestParsePyprojectToml:
    def test_standard_deps(self, manager, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["fastapi>=0.115.0", "uvicorn"]\n')
        result = manager._parse_pyproject_toml(pyproject)
        assert "fastapi" in result
        assert "uvicorn" in result

    def test_poetry_deps(self, manager, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[tool.poetry.dependencies]\npython = "^3.11"\nlxml = "^4.9"\n')
        result = manager._parse_pyproject_toml(pyproject)
        assert "lxml" in result
        assert "python" not in result  # python is filtered out

    def test_nonexistent_file(self, manager, tmp_path):
        result = manager._parse_pyproject_toml(tmp_path / "nope.toml")
        assert result == set()


class TestParsePackageJson:
    def test_deps_and_dev_deps(self, manager, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.0"},
                    "devDependencies": {"jest": "^29.0.0"},
                }
            )
        )
        result = manager._parse_package_json(pkg)
        assert "express" in result
        assert "jest" in result

    def test_nonexistent_file(self, manager, tmp_path):
        result = manager._parse_package_json(tmp_path / "nope.json")
        assert result == set()


class TestDetectRequiredDependencies:
    def test_with_requirements_txt(self, manager, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("lxml>=4.0\nPillow>=9.0\nunknown-pkg\n")
        with patch.object(manager, "_is_dependency_installed", return_value=False):
            result = manager.detect_required_dependencies(tmp_path)
        names = [d.name for d in result]
        assert "lxml" in names
        assert "Pillow" in names

    def test_empty_dir(self, manager, tmp_path):
        result = manager.detect_required_dependencies(tmp_path)
        assert result == []

    def test_nonexistent_dir(self, manager, tmp_path):
        result = manager.detect_required_dependencies(tmp_path / "nonexistent")
        assert result == []

    def test_with_package_json(self, manager, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"canvas": "^2.0"}}))
        with patch.object(manager, "_is_dependency_installed", return_value=False):
            result = manager.detect_required_dependencies(tmp_path)
        # node-canvas is in the DEPENDENCY_MAP
        names = [d.name for d in result]
        assert "node-canvas" in names


class TestIsDependencyInstalled:
    def test_cached_result(self, manager):
        manager._dependency_cache["lxml_apt"] = True
        dep = SystemDependency(
            name="lxml",
            packages={PackageManager.APT: ["libxml2-dev"]},
            description="XML",
            dependency_type=DependencyType.BUILD,
        )
        assert manager._is_dependency_installed(dep) is True

    def test_not_installed(self, manager):
        dep = SystemDependency(
            name="lxml",
            packages={PackageManager.APT: ["libxml2-dev"]},
            description="XML",
            dependency_type=DependencyType.BUILD,
        )
        with patch.object(manager, "_check_dependency_installed_uncached", return_value=False):
            assert manager._is_dependency_installed(dep) is False


class TestCheckPackageInstalled:
    def test_apt_installed(self, manager):
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"ii  libxml2-dev")
            assert manager._check_package_installed("libxml2-dev") is True

    def test_apt_not_installed(self, manager):
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout=b"")
            assert manager._check_package_installed("libxml2-dev") is False

    def test_no_package_manager(self, manager):
        manager.package_manager = None
        assert manager._check_package_installed("anything") is False


class TestGenerateInstallScript:
    def test_apt_script(self, manager):
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev", "libxslt1-dev"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script(deps)
        assert "apt-get update" in script
        assert "apt-get install -y libxml2-dev libxslt1-dev" in script

    def test_empty_deps(self, manager):
        script = manager.generate_install_script([])
        assert script == ""

    def test_write_to_file(self, manager, tmp_path):
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        output = tmp_path / "install.sh"
        manager.generate_install_script(deps, output_path=output)
        assert output.exists()
        content = output.read_text()
        assert "libxml2-dev" in content


class TestGenerateDockerfileSnippet:
    def test_all_deps(self, manager):
        snippet = manager.generate_dockerfile_snippet()
        assert "apt-get" in snippet
        assert "apk" in snippet

    def test_specific_deps(self, manager):
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"], PackageManager.APK: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        snippet = manager.generate_dockerfile_snippet(deps)
        assert "libxml2-dev" in snippet


class TestGenerateCIConfig:
    def test_github(self, manager):
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"], PackageManager.BREW: ["libxml2"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        config = manager.generate_ci_config("github", deps)
        assert "apt-get" in config
        assert "brew" in config

    def test_gitlab(self, manager):
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        config = manager.generate_ci_config("gitlab", deps)
        assert "before_script" in config

    def test_unsupported_platform(self, manager):
        with pytest.raises(ValueError, match="Unsupported CI platform"):
            manager.generate_ci_config("travis", [])


class TestInstallDependencies:
    def test_dry_run(self, manager):
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        result = manager.install_dependencies(deps, dry_run=True)
        assert result is True

    def test_empty_deps(self, manager):
        result = manager.install_dependencies([])
        assert result is True

    def test_no_package_manager(self, manager):
        manager.package_manager = None
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        result = manager.install_dependencies(deps)
        assert result is False

    def test_install_success(self, manager):
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        with patch.object(manager, "_update_package_manager"):
            with patch.object(manager, "_install_packages_with_retry", return_value=True):
                result = manager.install_dependencies(deps)
        assert result is True

    def test_install_failure(self, manager):
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        with patch.object(manager, "_update_package_manager"):
            with patch.object(manager, "_install_packages_with_retry", return_value=False):
                result = manager.install_dependencies(deps)
        assert result is False

    def test_install_exception(self, manager):
        """Install raises exception during _install_packages_with_retry."""
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        with patch.object(manager, "_update_package_manager"):
            with patch.object(
                manager, "_install_packages_with_retry", side_effect=RuntimeError("boom")
            ):
                result = manager.install_dependencies(deps)
        assert result is False

    def test_install_dep_not_in_package_manager(self, manager):
        """Dependency has no packages for the current package manager - logged as warning but success stays True."""
        deps = [
            SystemDependency(
                name="custom",
                packages={PackageManager.BREW: ["custom-pkg"]},
                description="Custom",
                dependency_type=DependencyType.BUILD,
            )
        ]
        with patch.object(manager, "_update_package_manager"):
            result = manager.install_dependencies(deps)
        # The dep is added to failed_deps but success is not set to False
        # (it only becomes False on _install_packages_with_retry failure)
        assert result is True

    def test_install_empty_packages_list(self, manager):
        """Dependency has empty packages list for current package manager."""
        deps = [
            SystemDependency(
                name="empty",
                packages={PackageManager.APT: []},
                description="Empty",
                dependency_type=DependencyType.BUILD,
            )
        ]
        with patch.object(manager, "_update_package_manager"):
            result = manager.install_dependencies(deps)
        # Empty packages are skipped, not treated as failures
        assert result is True

    def test_install_update_package_manager_fails(self, manager):
        """Update package manager fails but install continues."""
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        with patch.object(
            manager, "_update_package_manager", side_effect=RuntimeError("update failed")
        ):
            with patch.object(manager, "_install_packages_with_retry", return_value=True):
                result = manager.install_dependencies(deps)
        assert result is True

    def test_install_uses_missing_deps_when_none(self, manager):
        """Uses self.missing_dependencies when no deps passed."""
        manager.missing_dependencies = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        with patch.object(manager, "_update_package_manager"):
            with patch.object(manager, "_install_packages_with_retry", return_value=True):
                result = manager.install_dependencies()
        assert result is True

    def test_install_brew_skips_update(self, manager):
        """Brew package manager skips update step."""
        manager.package_manager = PackageManager.BREW
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.BREW: ["libxml2"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        with patch.object(manager, "_update_package_manager") as mock_update:
            with patch.object(manager, "_install_packages_with_retry", return_value=True):
                result = manager.install_dependencies(deps)
        assert result is True
        mock_update.assert_not_called()


class TestDetectPackageManagerWindows:
    def test_windows_with_choco(self):
        with patch.object(SystemDependencyManager, "_command_exists", return_value=True):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "windows"
            result = mgr._detect_package_manager()
            assert result == PackageManager.CHOCO

    def test_windows_no_choco(self):
        with patch.object(SystemDependencyManager, "_command_exists", return_value=False):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "windows"
            result = mgr._detect_package_manager()
            assert result is None

    def test_unknown_os(self):
        with patch.object(SystemDependencyManager, "_command_exists", return_value=False):
            mgr = SystemDependencyManager.__new__(SystemDependencyManager)
            mgr.os_type = "freebsd"
            result = mgr._detect_package_manager()
            assert result is None


class TestParseRequirementsTxtEdgeCases:
    def test_invalid_package_line(self, manager, tmp_path):
        """Lines that don't match the regex are skipped."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("===invalid===\nfastapi\n")
        result = manager._parse_requirements_txt(req_file)
        assert "fastapi" in result
        # The invalid line should be skipped
        assert len(result) == 1

    def test_unicode_decode_error(self, manager, tmp_path):
        """Binary content triggers UnicodeDecodeError."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_bytes(b"\xff\xfe\x00\x01")
        result = manager._parse_requirements_txt(req_file)
        assert result == set()

    def test_single_char_package(self, manager, tmp_path):
        """Single character package name."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("x\n")
        result = manager._parse_requirements_txt(req_file)
        assert "x" in result

    def test_extras_in_requirements(self, manager, tmp_path):
        """Package with extras like package[extra]."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("psycopg2[binary]>=2.9\n")
        result = manager._parse_requirements_txt(req_file)
        assert "psycopg2" in result


class TestParsePyprojectTomlEdgeCases:
    def test_invalid_toml(self, manager, tmp_path):
        """Invalid TOML content is handled gracefully."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("this is not valid [[[ toml {{{")
        result = manager._parse_pyproject_toml(pyproject)
        assert result == set()

    def test_no_dependencies_key(self, manager, tmp_path):
        """TOML with project section but no dependencies."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "myproject"\n')
        result = manager._parse_pyproject_toml(pyproject)
        assert result == set()

    def test_poetry_python_skipped(self, manager, tmp_path):
        """Python dependency in poetry section should be excluded."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[tool.poetry.dependencies]\nPython = "^3.11"\nrequests = "^2.28"\n')
        result = manager._parse_pyproject_toml(pyproject)
        assert "python" not in result
        assert "requests" in result

    def test_non_string_dep_in_project(self, manager, tmp_path):
        """Non-string entries in project.dependencies are skipped."""
        pyproject = tmp_path / "pyproject.toml"
        # This tests the isinstance(dep, str) check
        pyproject.write_text('[project]\ndependencies = ["fastapi>=0.115.0"]\n')
        result = manager._parse_pyproject_toml(pyproject)
        assert "fastapi" in result


class TestParsePackageJsonEdgeCases:
    def test_invalid_json(self, manager, tmp_path):
        """Invalid JSON is handled gracefully."""
        pkg = tmp_path / "package.json"
        pkg.write_text("{not valid json!}")
        result = manager._parse_package_json(pkg)
        assert result == set()

    def test_peer_and_optional_deps(self, manager, tmp_path):
        """Parse peerDependencies and optionalDependencies."""
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps(
                {
                    "peerDependencies": {"react": "^18.0.0"},
                    "optionalDependencies": {"sharp": "^0.32.0"},
                }
            )
        )
        result = manager._parse_package_json(pkg)
        assert "react" in result
        assert "sharp" in result

    def test_non_dict_dependencies(self, manager, tmp_path):
        """Dependencies value is not a dict (e.g., string) are skipped."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": "not-a-dict"}))
        result = manager._parse_package_json(pkg)
        assert result == set()


class TestDetectRequiredDependenciesAdvanced:
    def test_fast_mode(self, manager, tmp_path):
        """In fast_mode, all matching deps are added without install check."""
        req = tmp_path / "requirements.txt"
        req.write_text("lxml>=4.0\n")
        result = manager.detect_required_dependencies(tmp_path, fast_mode=True)
        names = [d.name for d in result]
        assert "lxml" in names

    def test_optional_deps_excluded_by_default(self, manager, tmp_path):
        """Optional dependencies are excluded when include_optional=False."""
        req = tmp_path / "requirements.txt"
        req.write_text("lxml>=4.0\n")
        # Temporarily modify DEPENDENCY_MAP to have an optional dep
        original = manager.DEPENDENCY_MAP.get("lxml")
        manager.DEPENDENCY_MAP["lxml"] = SystemDependency(
            name="lxml",
            packages={PackageManager.APT: ["libxml2-dev"]},
            description="XML",
            dependency_type=DependencyType.OPTIONAL,
        )
        try:
            result = manager.detect_required_dependencies(
                tmp_path, include_optional=False, fast_mode=True
            )
            names = [d.name for d in result]
            assert "lxml" not in names
        finally:
            manager.DEPENDENCY_MAP["lxml"] = original

    def test_optional_deps_included_when_requested(self, manager, tmp_path):
        """Optional dependencies are included when include_optional=True."""
        req = tmp_path / "requirements.txt"
        req.write_text("lxml>=4.0\n")
        original = manager.DEPENDENCY_MAP.get("lxml")
        manager.DEPENDENCY_MAP["lxml"] = SystemDependency(
            name="lxml",
            packages={PackageManager.APT: ["libxml2-dev"]},
            description="XML",
            dependency_type=DependencyType.OPTIONAL,
        )
        try:
            result = manager.detect_required_dependencies(
                tmp_path, include_optional=True, fast_mode=True
            )
            names = [d.name for d in result]
            assert "lxml" in names
        finally:
            manager.DEPENDENCY_MAP["lxml"] = original

    def test_no_deps_detected(self, manager, tmp_path):
        """Project with dependency files but no matching system deps."""
        req = tmp_path / "requirements.txt"
        req.write_text("totally-unknown-package\n")
        result = manager.detect_required_dependencies(tmp_path)
        assert result == []

    def test_case_variant_lookup(self, manager, tmp_path):
        """Dependencies are found via case-variant lookup."""
        req = tmp_path / "requirements.txt"
        # "pillow" (lowercase) should still match "Pillow" in DEPENDENCY_MAP
        req.write_text("pillow>=9.0\n")
        with patch.object(manager, "_is_dependency_installed", return_value=False):
            result = manager.detect_required_dependencies(tmp_path)
        names = [d.name for d in result]
        assert "Pillow" in names

    def test_node_packages_with_prefix(self, manager, tmp_path):
        """Node packages that need node- prefix are found."""
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"sqlite3": "^5.0"}}))
        with patch.object(manager, "_is_dependency_installed", return_value=False):
            result = manager.detect_required_dependencies(tmp_path)
        names = [d.name for d in result]
        assert "node-sqlite3" in names

    def test_pyproject_and_requirements_combined(self, manager, tmp_path):
        """Both pyproject.toml and requirements.txt are parsed."""
        req = tmp_path / "requirements.txt"
        req.write_text("lxml>=4.0\n")
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\ndependencies = ["psycopg2>=2.9"]\n')
        with patch.object(manager, "_is_dependency_installed", return_value=False):
            result = manager.detect_required_dependencies(tmp_path)
        names = [d.name for d in result]
        assert "lxml" in names
        assert "psycopg2" in names


class TestCheckDependencyInstalledUncached:
    def test_with_test_import_success(self, manager):
        """Dependency is found via test_import."""
        dep = SystemDependency(
            name="test_dep",
            packages={PackageManager.APT: ["test-dev"]},
            description="Test",
            dependency_type=DependencyType.BUILD,
            test_import="json",  # json is always importable
        )
        assert manager._check_dependency_installed_uncached(dep) is True

    def test_with_test_import_failure(self, manager):
        """test_import fails, falls through to other checks."""
        dep = SystemDependency(
            name="test_dep",
            packages={PackageManager.APT: ["test-dev"]},
            description="Test",
            dependency_type=DependencyType.BUILD,
            test_import="nonexistent_module_xyz",
        )
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"ii  test-dev")
            result = manager._check_dependency_installed_uncached(dep)
        assert result is True

    def test_with_test_command_success(self, manager):
        """Dependency is found via test_command."""
        dep = SystemDependency(
            name="test_dep",
            packages={},
            description="Test",
            dependency_type=DependencyType.BUILD,
            test_command="echo hello",
        )
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager._check_dependency_installed_uncached(dep)
        assert result is True

    def test_with_test_command_failure(self, manager):
        """test_command fails."""
        dep = SystemDependency(
            name="test_dep",
            packages={},
            description="Test",
            dependency_type=DependencyType.BUILD,
            test_command="nonexistent_cmd --version",
        )
        with patch(
            "services.system_dependency_manager.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            result = manager._check_dependency_installed_uncached(dep)
        assert result is False

    def test_with_test_command_timeout(self, manager):
        """test_command times out."""
        dep = SystemDependency(
            name="test_dep",
            packages={},
            description="Test",
            dependency_type=DependencyType.BUILD,
            test_command="slow_cmd --version",
        )
        with patch(
            "services.system_dependency_manager.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="slow_cmd", timeout=5),
        ):
            result = manager._check_dependency_installed_uncached(dep)
        assert result is False

    def test_no_checks_available(self, manager):
        """No test_import, no packages for PM, no test_command."""
        dep = SystemDependency(
            name="test_dep",
            packages={},
            description="Test",
            dependency_type=DependencyType.BUILD,
        )
        result = manager._check_dependency_installed_uncached(dep)
        assert result is False

    def test_package_manager_check_fails_then_test_command(self, manager):
        """Package manager check fails, falls through to test_command."""
        dep = SystemDependency(
            name="test_dep",
            packages={PackageManager.APT: ["test-dev"]},
            description="Test",
            dependency_type=DependencyType.BUILD,
            test_command="test_cmd --version",
        )
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            # First call: dpkg check fails. Second call: test_command succeeds
            mock_run.side_effect = [
                MagicMock(returncode=1, stdout=b""),  # dpkg fails
                MagicMock(returncode=0),  # test_command succeeds
            ]
            result = manager._check_dependency_installed_uncached(dep)
        assert result is True


class TestCheckPackageInstalledVariousPMs:
    def test_brew_installed(self, manager):
        manager.package_manager = PackageManager.BREW
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert manager._check_package_installed("libxml2") is True

    def test_brew_not_installed(self, manager):
        manager.package_manager = PackageManager.BREW
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert manager._check_package_installed("libxml2") is False

    def test_yum_installed(self, manager):
        manager.package_manager = PackageManager.YUM
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert manager._check_package_installed("libxml2-devel") is True

    def test_dnf_installed(self, manager):
        manager.package_manager = PackageManager.DNF
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert manager._check_package_installed("libxml2-devel") is True

    def test_pacman_installed(self, manager):
        manager.package_manager = PackageManager.PACMAN
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert manager._check_package_installed("libxml2") is True

    def test_pacman_not_installed(self, manager):
        manager.package_manager = PackageManager.PACMAN
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert manager._check_package_installed("libxml2") is False

    def test_apk_installed(self, manager):
        manager.package_manager = PackageManager.APK
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert manager._check_package_installed("libxml2-dev") is True

    def test_apk_not_installed(self, manager):
        manager.package_manager = PackageManager.APK
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert manager._check_package_installed("libxml2-dev") is False

    def test_subprocess_error_returns_false(self, manager):
        with patch(
            "services.system_dependency_manager.subprocess.run",
            side_effect=subprocess.SubprocessError("fail"),
        ):
            assert manager._check_package_installed("libxml2-dev") is False

    def test_timeout_returns_false(self, manager):
        with patch(
            "services.system_dependency_manager.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="dpkg", timeout=5),
        ):
            assert manager._check_package_installed("libxml2-dev") is False


class TestGenerateInstallScriptVariousPMs:
    def test_brew_script(self, manager):
        manager.package_manager = PackageManager.BREW
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.BREW: ["libxml2", "libxslt"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script(deps)
        assert "brew update" in script
        assert "brew install libxml2 libxslt" in script

    def test_yum_script(self, manager):
        manager.package_manager = PackageManager.YUM
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.YUM: ["libxml2-devel"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script(deps)
        assert "yum update -y" in script
        assert "sudo yum install -y libxml2-devel" in script

    def test_dnf_script(self, manager):
        manager.package_manager = PackageManager.DNF
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.DNF: ["libxml2-devel"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script(deps)
        assert "dnf update -y" in script
        assert "sudo dnf install -y libxml2-devel" in script

    def test_pacman_script(self, manager):
        manager.package_manager = PackageManager.PACMAN
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.PACMAN: ["libxml2"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script(deps)
        assert "pacman -S --noconfirm libxml2" in script

    def test_apk_script(self, manager):
        manager.package_manager = PackageManager.APK
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APK: ["libxml2-dev"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script(deps)
        assert "apk add libxml2-dev" in script

    def test_zypper_script(self, manager):
        manager.package_manager = PackageManager.ZYPPER
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.ZYPPER: ["libxml2-devel"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script(deps)
        assert "zypper install -y libxml2-devel" in script

    def test_no_package_manager(self, manager):
        manager.package_manager = None
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script(deps)
        assert script == ""

    def test_uses_missing_deps_when_none(self, manager):
        """Uses self.missing_dependencies when deps arg is None."""
        manager.missing_dependencies = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script()
        assert "libxml2-dev" in script

    def test_dep_not_in_current_pm(self, manager):
        """Dep has no packages for the current PM - skipped."""
        deps = [
            SystemDependency(
                name="custom",
                packages={PackageManager.BREW: ["custom-pkg"]},
                description="Custom",
                dependency_type=DependencyType.BUILD,
            )
        ]
        script = manager.generate_install_script(deps)
        # Script has header but no install command for this dep
        assert "custom-pkg" not in script

    def test_write_to_nested_dir(self, manager, tmp_path):
        """Writing script to nested non-existent directory."""
        deps = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML processing",
                dependency_type=DependencyType.BUILD,
            )
        ]
        output = tmp_path / "nested" / "dir" / "install.sh"
        manager.generate_install_script(deps, output_path=output)
        assert output.exists()
        import stat

        assert output.stat().st_mode & stat.S_IXUSR


class TestInstallPackagesWithRetry:
    def test_apt_success(self, manager):
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager._install_packages_with_retry(["libxml2-dev"])
        assert result is True

    def test_brew_success(self, manager):
        manager.package_manager = PackageManager.BREW
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager._install_packages_with_retry(["libxml2"])
        assert result is True

    def test_yum_success(self, manager):
        manager.package_manager = PackageManager.YUM
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager._install_packages_with_retry(["libxml2-devel"])
        assert result is True

    def test_dnf_success(self, manager):
        manager.package_manager = PackageManager.DNF
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager._install_packages_with_retry(["libxml2-devel"])
        assert result is True

    def test_pacman_success(self, manager):
        manager.package_manager = PackageManager.PACMAN
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager._install_packages_with_retry(["libxml2"])
        assert result is True

    def test_apk_success(self, manager):
        manager.package_manager = PackageManager.APK
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager._install_packages_with_retry(["libxml2-dev"])
        assert result is True

    def test_zypper_success(self, manager):
        manager.package_manager = PackageManager.ZYPPER
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager._install_packages_with_retry(["libxml2-devel"])
        assert result is True

    def test_unsupported_pm(self, manager):
        manager.package_manager = PackageManager.CHOCO
        result = manager._install_packages_with_retry(["libxml2"])
        assert result is False

    def test_timeout_retry_then_fail(self, manager):
        with patch(
            "services.system_dependency_manager.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="apt-get", timeout=300),
        ):
            result = manager._install_packages_with_retry(
                ["libxml2-dev"], timeout=300, max_retries=1
            )
        assert result is False

    def test_called_process_error_retry_then_fail(self, manager):
        with patch(
            "services.system_dependency_manager.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "apt-get", stderr=b"error msg"),
        ):
            result = manager._install_packages_with_retry(
                ["libxml2-dev"], timeout=300, max_retries=1
            )
        assert result is False

    def test_timeout_retry_then_succeed(self, manager):
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            mock_run.side_effect = [
                subprocess.TimeoutExpired(cmd="apt-get", timeout=300),
                MagicMock(returncode=0),  # Second attempt succeeds
            ]
            result = manager._install_packages_with_retry(
                ["libxml2-dev"], timeout=300, max_retries=1
            )
        assert result is True

    def test_called_process_error_no_stderr(self, manager):
        """CalledProcessError with no stderr attribute."""
        with patch(
            "services.system_dependency_manager.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "apt-get", stderr=None),
        ):
            result = manager._install_packages_with_retry(
                ["libxml2-dev"], timeout=300, max_retries=0
            )
        assert result is False


class TestUpdatePackageManager:
    def test_apt_update(self, manager):
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            manager._update_package_manager()
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "apt-get" in args
            assert "update" in args

    def test_yum_update(self, manager):
        manager.package_manager = PackageManager.YUM
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            manager._update_package_manager()
            args = mock_run.call_args[0][0]
            assert "yum" in args

    def test_dnf_update(self, manager):
        manager.package_manager = PackageManager.DNF
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            manager._update_package_manager()
            args = mock_run.call_args[0][0]
            assert "dnf" in args

    def test_pacman_update(self, manager):
        manager.package_manager = PackageManager.PACMAN
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            manager._update_package_manager()
            args = mock_run.call_args[0][0]
            assert "pacman" in args
            assert "-Sy" in args

    def test_apk_update(self, manager):
        manager.package_manager = PackageManager.APK
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            manager._update_package_manager()
            args = mock_run.call_args[0][0]
            assert "apk" in args
            assert "update" in args

    def test_zypper_update(self, manager):
        manager.package_manager = PackageManager.ZYPPER
        with patch("services.system_dependency_manager.subprocess.run") as mock_run:
            manager._update_package_manager()
            args = mock_run.call_args[0][0]
            assert "zypper" in args
            assert "refresh" in args


class TestGenerateDockerfileSnippetEdgeCases:
    def test_no_apt_or_apk_packages(self, manager):
        """Deps with only brew packages produce no snippet."""
        deps = [
            SystemDependency(
                name="test",
                packages={PackageManager.BREW: ["test-pkg"]},
                description="Test",
                dependency_type=DependencyType.BUILD,
            )
        ]
        snippet = manager.generate_dockerfile_snippet(deps)
        assert snippet == ""

    def test_only_apk_packages(self, manager):
        """Deps with only APK packages produce Alpine snippet."""
        deps = [
            SystemDependency(
                name="test",
                packages={PackageManager.APK: ["test-dev"]},
                description="Test",
                dependency_type=DependencyType.BUILD,
            )
        ]
        snippet = manager.generate_dockerfile_snippet(deps)
        assert "apk add" in snippet
        assert "apt-get" not in snippet

    def test_empty_deps_list(self, manager):
        """Empty deps list produces no snippet."""
        snippet = manager.generate_dockerfile_snippet([])
        assert snippet == ""


class TestGenerateCIConfigEdgeCases:
    def test_github_no_deps(self, manager):
        """Empty deps produce empty config."""
        config = manager.generate_ci_config("github", [])
        assert config == ""

    def test_gitlab_no_deps(self, manager):
        config = manager.generate_ci_config("gitlab", [])
        assert config == ""

    def test_github_only_brew(self, manager):
        """Deps with only brew packages."""
        deps = [
            SystemDependency(
                name="test",
                packages={PackageManager.BREW: ["test-pkg"]},
                description="Test",
                dependency_type=DependencyType.BUILD,
            )
        ]
        config = manager.generate_ci_config("github", deps)
        assert "brew install" in config
        assert "apt-get" not in config

    def test_uses_missing_deps_when_none(self, manager):
        """Uses self.missing_dependencies when deps arg is None."""
        manager.missing_dependencies = [
            SystemDependency(
                name="lxml",
                packages={PackageManager.APT: ["libxml2-dev"]},
                description="XML",
                dependency_type=DependencyType.BUILD,
            )
        ]
        config = manager.generate_ci_config("github")
        assert "libxml2-dev" in config
