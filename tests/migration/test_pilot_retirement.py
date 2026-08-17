from __future__ import annotations

import ast
import hashlib
import json
import tomllib
from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = PLATFORM_ROOT / "foundation/tests/fixtures/migration/pilot-v1"
RECEIPT_PATH = FIXTURE_ROOT / "retirement.receipt.json"
PROHIBITED_NAMES = {
    "BacktestConfig",
    "run_causal_momentum_backtest",
    "Fill",
    "calculate_closed_trade",
}
HISTORICAL_CLASSIFICATION = "static_historical_evidence"
HERMETIC_REPLAY = "unavailable_not_claimed_without_separately_recorded_hermetic_environment"


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _receipt() -> dict:
    decoded = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))
    assert isinstance(decoded, dict)
    return decoded


def test_p00_cut_receipt_binds_static_historical_baseline() -> None:
    receipt = _receipt()

    assert receipt["work_package"] == "P00-CUT-01"
    assert receipt["status"] == HISTORICAL_CLASSIFICATION
    assert receipt["classification"] == HISTORICAL_CLASSIFICATION
    assert receipt["scope"] == {
        "system_root": "platform",
        "write_boundary": "platform_only",
        "legacy_repository_modified": False,
        "legacy_repository_changes_require_separate_explicit_scope": True,
    }
    assert receipt["historical_capture"] == {
        "recorded_command_versions_hashes_and_outputs": "historical_observations_only",
        "hermetic_replay": HERMETIC_REPLAY,
    }
    for key in ("capture_receipt", "capture_manifest"):
        path = PLATFORM_ROOT / receipt["basis"][key]
        assert path.is_relative_to(FIXTURE_ROOT)
        assert _sha256(path) == receipt["basis"][f"{key}_sha256"]


def test_new_platform_has_no_legacy_pilot_runtime_dependency() -> None:
    receipt = _receipt()
    authority = receipt["authority_decision"]

    assert authority["retained_role"] == "static_historical_evidence_only"
    assert authority["historical_simulation_authority"] == "backtest"
    assert authority["new_platform_must_not_import_or_execute_legacy_pilot"] is True
    assert authority["captured_outputs_are_not_canonical_backtest_evidence"] is True
    assert authority["callable_adapter_in_new_platform"] is False

    source_roots = (
        PLATFORM_ROOT / "foundation/src",
        PLATFORM_ROOT / "research-platform/src",
        PLATFORM_ROOT / "strategy-validation/src",
        PLATFORM_ROOT / "promotion-gate/src",
    )
    for root in source_roots:
        for path in root.rglob("*.py") if root.exists() else ():
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            imported = {
                name
                for node in ast.walk(tree)
                for name in (
                    [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                    if isinstance(node, ast.ImportFrom)
                    else []
                )
            }
            defined_or_used = {
                node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
            }
            assert not any(name.startswith("crypto_quant_platform") for name in imported)
            assert not PROHIBITED_NAMES.intersection(defined_or_used)

    for path in PLATFORM_ROOT.rglob("pyproject.toml"):
        if path.is_relative_to(FIXTURE_ROOT):
            continue
        try:
            project = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise AssertionError(f"invalid pyproject {path}: {error}") from error
        dependencies = project.get("project", {}).get("dependencies", [])
        scripts = project.get("project", {}).get("scripts", {})
        assert isinstance(dependencies, list)
        assert isinstance(scripts, dict)
        assert not any(
            isinstance(dependency, str)
            and "crypto-quant-pilot" in dependency.lower()
            for dependency in dependencies
        )
        assert "crypto-quant-pilot" not in {str(name).lower() for name in scripts}
        assert not any(
            isinstance(target, str) and "crypto_quant_platform" in target
            for target in scripts.values()
        )
