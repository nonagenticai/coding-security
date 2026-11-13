"""#13: GET /api/security/patterns reports only languages/ecosystems that actually run.

It used to return a hardcoded 9-language list (rust, go, csharp, typescript ...)
that no in-process rule covered. Now every language is backed by a named engine.
"""

from __future__ import annotations

from unittest.mock import patch


def _patterns(test_client, tenant_headers, db_dir) -> dict:
    from config.settings import get_settings

    with patch.dict("os.environ", {"OSV_OFFLINE_DB_DIR": str(db_dir)}):
        get_settings.cache_clear()
        data = test_client.get("/api/security/patterns", headers=tenant_headers).json()
    get_settings.cache_clear()
    return data


def test_patterns_languages_are_derived_from_engines(test_client, tenant_headers, tmp_path):
    (tmp_path / "PyPI").mkdir()
    data = _patterns(test_client, tenant_headers, tmp_path)
    langs = data["supported_languages"]
    engines = data["language_engines"]
    assert sorted(engines) == langs
    assert all(engines[lang] for lang in langs)  # every claimed language names an engine
    assert {"python", "java", "javascript"} <= set(langs)
    assert "any" not in langs
    # only the baked DB dirs count: no crates.io dir -> crates.io not advertised
    assert data["dependency_ecosystems"] == {"pypi": ["osv-offline"]}


def test_every_advertised_ecosystem_key_is_accepted_by_the_selectors(
    test_client, tenant_headers, tmp_path
):
    """Round trip: what /patterns advertises, the ecosystem selectors accept (and vice versa)."""
    from typing import get_args

    from pydantic import TypeAdapter

    from models.security_api_models import DEPENDENCY_ECOSYSTEMS, Ecosystem

    for osv_dir in ("PyPI", "crates.io", "npm", "Go"):
        (tmp_path / osv_dir).mkdir()
    advertised = set(_patterns(test_client, tenant_headers, tmp_path)["dependency_ecosystems"])
    # npm / Go have a DB dir but no selector accepts them -> not advertised
    assert advertised == {"pypi", "crates.io"} == set(DEPENDENCY_ECOSYSTEMS)
    accepted = set(get_args(get_args(Ecosystem)[0]))
    assert advertised <= accepted
    for key in advertised:
        # advertised form, and OSV's spelling of it, both validate to the advertised key
        for spelling in (key, key.upper(), {"pypi": "PyPI"}.get(key, key)):
            assert TypeAdapter(Ecosystem).validate_python(spelling) == key


def test_semgrep_pack_languages_from_a_json_pack(tmp_path):
    from routers.security.vulnerabilities import _semgrep_pack_languages

    (tmp_path / "security-audit.yaml").write_text(
        '{"rules": [{"id": "r", "languages": ["rust", "js"]},'
        ' {"id": "g", "languages": ["generic"]}]}'
    )
    (tmp_path / "notes.txt").write_text(
        "languages: [java]\n"
    )  # no `rules`: not a rule pack, ignored
    assert _semgrep_pack_languages(str(tmp_path)) == {"rust", "javascript"}


def test_semgrep_pack_languages_from_a_yaml_pack(tmp_path):
    """The registry served YAML again on 2026-10-29: the same reader takes it."""
    from routers.security.vulnerabilities import _semgrep_pack_languages

    (tmp_path / "security-audit.yaml").write_text(
        "rules:\n- id: a\n  languages: [python, js]\n- id: b\n  languages:\n  - go\n  - regex\n"
    )
    assert _semgrep_pack_languages(str(tmp_path)) == {"python", "javascript", "go"}
