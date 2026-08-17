from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

FOUNDATION_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_ROOT = FOUNDATION_ROOT.parent
FIXTURE = FOUNDATION_ROOT / "tests/fixtures/architecture/p00-contract-v2.json"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssertionError(f"invalid JSON fixture {path}: {error}") from error
    assert isinstance(value, dict)
    return value


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def test_p00_contract_v2_is_a_narrow_static_legacy_clarification() -> None:
    receipt = _read_json(FIXTURE)

    assert receipt["receipt_id"] == "p00-contract-v2"
    expected_schema_version = 1
    assert receipt["schema_version"] == expected_schema_version
    assert receipt["work_package"] == "P00-CON-02"
    assert receipt["evidence_kind"] == "narrow_contract_successor_receipt"
    expected_supersession = {
        "receipt_id": "p00-contract-v1",
        "only_downstream_unblock_conditions": ["P00_LEG_01", "P00_CUT_01"],
    }
    assert receipt["supersedes"] == expected_supersession
    expected_decision = {
        "legacy_evidence_rule": (
            "existing immutable static historical capture plus retirement receipt "
            "is sufficient evidence for P00-LEG/P00-CUT"
        ),
        "hermetic_replay_rule": "not required and must not be a P00-PLAT prerequisite",
        "legacy_classification": "static_historical_evidence",
        "not_claimed": [
            "canonical_backtest_evidence",
            "callable_legacy_adapter",
            "economic_parity",
            "hermetic_replay",
        ],
    }
    assert receipt["decision"] == expected_decision
    expected_preserved_decisions = [
        "ArtifactEnvelope v1",
        "ArtifactRef",
        "Backtest public seam",
        "root workspace and lock rules",
        "ownership rules",
        "p00-contract-v1 fixture",
    ]
    assert receipt["preserves"] == expected_preserved_decisions


def test_p00_contract_v2_binds_existing_static_receipts_and_p00_v1_hash() -> None:
    receipt = _read_json(FIXTURE)
    evidence = receipt["evidence"]

    for key in (
        "p00_contract_v1",
        "static_capture_receipt",
        "static_capture_manifest",
        "retirement_receipt",
    ):
        binding = evidence[key]
        path = PLATFORM_ROOT / binding["path"]
        assert path.is_file()
        assert _sha256(path) == binding["sha256"]

    assert evidence["p00_contract_v1"]["sha256"] == (
        "sha256:aebb1be1894d739b06856e012e4343d7835fc1ed0306d8c28a4bfb1d8025b782"
    )
    for key in (
        "static_capture_receipt",
        "static_capture_manifest",
        "retirement_receipt",
    ):
        source = _read_json(PLATFORM_ROOT / evidence[key]["path"])
        assert source["status"] == evidence[key]["classification"]
        if "classification" in source:
            assert source["classification"] == evidence[key]["classification"]


def test_p00_contract_v2_records_both_owner_approvals() -> None:
    receipt = _read_json(FIXTURE)
    rule = receipt["approval_rule"]

    expected_rule = {
        "required_roles": [
            "backtest_repository_owner",
            "platform_repository_owner",
        ],
        "transition": "planned to approved only when both required roles are approved",
        "approved_record_fields": ["status", "name", "approved_at"],
        "mutable_fields": ["status", "approvals"],
    }
    assert rule == expected_rule
    assert receipt["status"] == "approved"
    expected_approvals = {
        "backtest_repository_owner": {
            "status": "approved",
            "name": "YungeG",
            "approved_at": "2026-08-17T01:23:06.083983Z",
        },
        "platform_repository_owner": {
            "status": "approved",
            "name": "YungeG",
            "approved_at": "2026-08-14T04:03:59.553705Z",
        },
    }
    assert receipt["approvals"] == expected_approvals

    rendering = (PLATFORM_ROOT / "implementation/p00-contract-v2.md").read_text(
        encoding="utf-8"
    )
    assert "Both required repository-owner approvals are recorded" in rendering
    assert "2026-08-17T01:23:06.083983Z" in rendering
    assert _sha256(FIXTURE) == (
        "sha256:5ad32e59e56e6f46904af22dafdd256d84ad6332389fd4bf0b709c8c83c2f573"
    )
    assert "All other\nP00-CON-01 decisions remain unchanged." in rendering
    assert "does not authorize runtime or Backtest seam changes" in rendering


def test_p00_contract_v2_docs_keep_replay_out_of_the_platform_gate() -> None:
    rendering = (PLATFORM_ROOT / "implementation/p00-contract-v2.md").read_text(
        encoding="utf-8"
    )
    integration = (PLATFORM_ROOT / "overall/integration-v1.md").read_text(
        encoding="utf-8"
    )
    roadmap = (PLATFORM_ROOT / "implementation/roadmap.md").read_text(
        encoding="utf-8"
    )

    assert "supersedes **only**" in rendering
    assert "Hermetic replay is not required and must not be a P00-PLAT prerequisite." in rendering
    assert "Hermetic replay is neither required nor permitted as a P00-PLAT prerequisite." in integration
    assert "P00-CON-02" in roadmap
    assert "hermetic replay is not a P00-PLAT prerequisite" in roadmap
