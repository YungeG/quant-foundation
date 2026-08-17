from __future__ import annotations

import argparse
from decimal import Decimal
import json
from pathlib import Path

import yaml

from crypto_quant_core.adapters import HummingbotControllerSpec

from .backtest import BacktestConfig, run_causal_momentum_backtest
from .data import load_candles_jsonl


def run_pipeline(*, config_path: str | Path, candles_path: str | Path, output_dir: str | Path) -> dict[str, Path]:
    config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    if not isinstance(config, dict) or config.get("paper_trade") is not True:
        raise ValueError("pilot configuration must explicitly enable paper_trade")
    candles = load_candles_jsonl(candles_path)
    if candles[0].symbol != str(config["symbol"]).upper() or candles[0].interval != config["interval"]:
        raise ValueError("pilot config does not match candle identity")

    report = run_causal_momentum_backtest(
        candles,
        BacktestConfig(
            lookback=int(config["lookback"]),
            quote_budget=Decimal(str(config["quote_budget"])),
            fee_rate=Decimal(str(config["fee_rate"])),
            slippage_bps=Decimal(str(config["slippage_bps"])),
        ),
    )
    controller = HummingbotControllerSpec(
        controller_name=str(config["controller_name"]),
        connector_name=str(config["connector_name"]),
        trading_pair=str(config["trading_pair"]),
        total_amount_quote=Decimal(str(config["quote_budget"])),
        paper_trade=True,
    ).to_config()
    controller.update({
        "strategy": report["strategy"],
        "interval": config["interval"],
        "lookback": int(config["lookback"]),
    })
    readiness = {
        "schema_version": 1,
        "environment": "paper-shadow",
        "controller_valid": True,
        "backtest_complete": report["trade_count"] > 0,
        "credentials_present": False,
        "deployment_authorized": False,
        "required_next_gate": "independent backtest-auditor review",
    }

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    paths = {
        "backtest": output / "backtest.json",
        "controller": output / "hummingbot-controller.yml",
        "readiness": output / "shadow-readiness.json",
    }
    paths["backtest"].write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["controller"].write_text(yaml.safe_dump(controller, sort_keys=True), encoding="utf-8")
    paths["readiness"].write_text(json.dumps(readiness, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the offline crypto-quant pilot")
    parser.add_argument("--config", required=True)
    parser.add_argument("--candles", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    for name, path in run_pipeline(
        config_path=args.config,
        candles_path=args.candles,
        output_dir=args.output,
    ).items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()

