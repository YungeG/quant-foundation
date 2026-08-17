from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MODULE_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_ROOT = MODULE_ROOT.parent
FIXTURE = MODULE_ROOT / "tests/fixtures/architecture/p00-contract-v1.json"


def load_receipt() -> dict[str, Any]:
    try:
        decoded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssertionError(f"invalid contract fixture: {error}") from error
    assert isinstance(decoded, dict)
    return decoded


def canonical_sha256(value: object) -> str:
    source = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(source).hexdigest()}"


def test_p00_contract_identity_and_hash_vectors() -> None:
    receipt = load_receipt()
    identity = receipt["decisions"]["artifact_identity"]
    envelope = identity["artifact_envelope_v1"]
    golden = envelope["golden_vector"]
    artifact_ref = identity["artifact_ref_v1_required_from_p00_dom"]

    assert receipt["receipt_id"] == "p00-contract-v1"
    assert receipt["schema_version"] == 1
    assert receipt["work_package"] == "P00-CON-01"
    assert receipt["not_an_artifact_envelope"] is True
    assert envelope["wire_fields_in_exact_set"] == [
        "artifact_type",
        "schema_version",
        "payload",
        "content_hash",
    ]
    assert envelope["content_hash_preimage"] == [
        "artifact_type",
        "schema_version",
        "payload",
    ]

    body = {
        "artifact_type": golden["artifact_type"],
        "schema_version": golden["schema_version"],
        "payload": golden["payload"],
    }
    assert canonical_sha256(body) == golden["expected_content_hash"]
    assert (
        f"sha256:{hashlib.sha256(golden['expected_source_utf8'].encode()).hexdigest()}"
        == golden["expected_source_hash"]
    )
    assert canonical_sha256(artifact_ref["canonical_wire"]) == artifact_ref[
        "canonical_hash"
    ]


def test_p00_contract_freezes_future_backtest_boundary() -> None:
    receipt = load_receipt()
    seam = receipt["decisions"]["backtest_public_seam"]
    evidence = receipt["decisions"]["verified_evidence_and_analysis"]

    assert seam["consumer_public_root"] == "crypto_quant_backtest"
    assert seam["consumer_api"]["outcome_alias"] == (
        "BacktestPublicationOutcome = CompletedPublication | TerminalPublication"
    )
    assert seam["consumer_api"]["terminal_statuses_exact"] == [
        "BLOCKED",
        "FAILED",
        "CANCELLED",
    ]
    assert seam["consumer_api"]["prohibited_terminal_status"] == "COMPLETED"
    assert {route["artifact_type"] for route in seam["durable_terminal_evidence"]["routes"]} >= {
        "evidence_manifest",
        "canonical_publication_manifest",
        "backtest_resolution_failure",
    }
    assert evidence["derive_rule"].startswith(
        "Only BacktestCanonicalPublicationRef is accepted"
    )


def test_p00_contract_thin_slice_install_and_ownership() -> None:
    receipt = load_receipt()
    thin = receipt["decisions"]["thin_slice_and_metric_profile"]
    topology = receipt["decisions"]["clean_install_topology"]
    ownership = receipt["decisions"]["ownership_and_public_boundary"]

    assert thin["route"]["strategy_family"] == "StrategyFamily.PRECOMPUTED_TARGET"
    assert thin["route"]["input_origin"] == "InputOrigin.PRECOMPUTED_TARGET_STREAM"
    assert thin["route"]["grade"] == "development"
    assert thin["route"]["fixture_only"] is True
    assert thin["downstream_first_thin_slice"] == {
        "implemented_by": "RP-THIN-02 after P00-SEAM-01",
        "candidate_producing_backtest_trials": 4,
        "completed_trials": 3,
        "durably_blocked_trials": 1,
        "model_build_plan": None,
        "analysis_ref_per_completed_trial": True,
        "boundary_rule": "All crossings use Backtest public root only.",
        "promotion_result": {
            "decision": "needs_more_evidence",
            "shadow_spec_ref": None,
            "deployment_authorized": False,
        },
    }
    assert topology["target_python"] == ">=3.13,<3.14"
    assert topology["minimum_direct_dependencies"] == [
        "crypto-quant-backtest==0.1.0",
        "crypto-quant-domain==0.1.0",
    ]
    assert ownership["public_import_roots"] == [
        "crypto_quant_domain",
        "crypto_quant_backtest",
    ]


def test_p00_contract_preserves_archive_and_asserts_local_design() -> None:
    receipt = load_receipt()

    # These are historical receipt data, not live sibling-repository targets.
    assert isinstance(receipt["inspection_snapshot"], dict)
    assert isinstance(receipt["evidence_anchors"], list)

    context = (PLATFORM_ROOT / "CONTEXT.md").read_text(encoding="utf-8")
    overall = (PLATFORM_ROOT / "overall/design.md").read_text(encoding="utf-8")
    research = (PLATFORM_ROOT / "research-platform/design.md").read_text(
        encoding="utf-8"
    )
    validation = (PLATFORM_ROOT / "strategy-validation/design.md").read_text(
        encoding="utf-8"
    )
    roadmap = (PLATFORM_ROOT / "implementation/roadmap.md").read_text(
        encoding="utf-8"
    )

    ownership = (
        "Validation is the sole semantic owner of `SampleConsumptionRecord`, "
        "`SampleConsumptionSnapshot`, and supplied-snapshot projection semantics."
    )
    assert ownership in context
    assert ownership in validation
    assert (
        "Foundation only appends generic payload bytes idempotently; it defines "
        "neither a sample-consumption event nor a projection."
    ) in overall
    assert "SampleConsumptionRecorded" not in research

    for document in (research, validation):
        assert "BacktestFacade" in document
        assert "CanonicalEvidenceRepository" in document
        assert "BacktestGateway" not in document
        assert "AnalysisGateway" not in document
        assert "only `CompletedPublication.publication_ref` reaches `derive()`." in document
        assert (
            "Backtest alone verifies canonical bytes, manifests, retention, and hash chains"
            in document
        )

    assert "one non-package `platform/pyproject.toml` workspace coordinator" in roadmap
    assert "one root `platform/uv.lock`" in roadmap
    assert "no leaf lock is retained or treated as a Platform lock" in roadmap
    assert "historical `guard_spec`" in (PLATFORM_ROOT / "implementation/p00-contract-v1.md").read_text(encoding="utf-8")
    assert (
        "Backtest now provides BT-GAP-09 public cash-development intent/preparation, "
        "persisted request refs, executable v2 transport"
    ) in overall


def test_p00_contract_scope_and_approvals() -> None:
    receipt = load_receipt()
    scope = receipt["scope"]
    approvals = receipt["approvals"]

    assert scope["p00_con_write_set"] == [
        "foundation/tests/fixtures/architecture/p00-contract-v1.json",
        "foundation/tests/architecture/test_p00_contract.py",
    ]
    assert scope["implementation_repository"] == "platform"
    assert "runtime production code" in scope["forbidden_in_p00_con"]
    assert receipt["status"] == "approved"
    assert set(approvals) == {
        "backtest_repository_owner",
        "platform_repository_owner",
    }
    for approval in approvals.values():
        assert approval == {
            "status": "approved",
            "name": "workspace-owner",
            "approved_at": "2026-08-12T14:15:04Z",
        }
