from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from crypto_quant_core import Candle, Fill, assert_no_lookahead, calculate_closed_trade


@dataclass(frozen=True)
class BacktestConfig:
    lookback: int
    quote_budget: Decimal
    fee_rate: Decimal
    slippage_bps: Decimal

    def __post_init__(self) -> None:
        if self.lookback < 1:
            raise ValueError("lookback must be positive")
        if self.quote_budget <= 0 or self.fee_rate < 0 or self.slippage_bps < 0:
            raise ValueError("backtest cost and budget values are invalid")


def _fee(price: Decimal, quantity: Decimal, rate: Decimal) -> Decimal:
    return price * quantity * rate


def run_causal_momentum_backtest(
    candles: tuple[Candle, ...], config: BacktestConfig
) -> dict[str, object]:
    if len(candles) < config.lookback + 2:
        raise ValueError("not enough candles for lookback plus next-bar execution")
    slippage = config.slippage_bps / Decimal("10000")
    trades: list[dict[str, str | int]] = []
    total = Decimal("0")

    for index in range(config.lookback, len(candles) - 1):
        decision_bar = candles[index]
        history = candles[index - config.lookback:index]
        assert_no_lookahead(
            decision_time_ms=decision_bar.close_time_ms,
            observed_through_ms=max(item.close_time_ms for item in (*history, decision_bar)),
        )
        average = sum((item.close for item in history), Decimal("0")) / Decimal(config.lookback)
        direction = "long" if decision_bar.close > average else "short"
        execution_bar = candles[index + 1]
        if execution_bar.open_time_ms <= decision_bar.close_time_ms:
            raise ValueError("execution must occur after the signal decision")

        if direction == "long":
            entry_side, exit_side = "buy", "sell"
            entry_price = execution_bar.open * (Decimal("1") + slippage)
            exit_price = execution_bar.close * (Decimal("1") - slippage)
        else:
            entry_side, exit_side = "sell", "buy"
            entry_price = execution_bar.open * (Decimal("1") - slippage)
            exit_price = execution_bar.close * (Decimal("1") + slippage)
        quantity = config.quote_budget / entry_price
        entry = Fill(
            execution_bar.open_time_ms,
            entry_side,
            entry_price,
            quantity,
            _fee(entry_price, quantity, config.fee_rate),
        )
        exit = Fill(
            execution_bar.close_time_ms,
            exit_side,
            exit_price,
            quantity,
            _fee(exit_price, quantity, config.fee_rate),
        )
        pnl = calculate_closed_trade(entry, exit)
        total += pnl.net_pnl
        trades.append({
            "decision_time_ms": decision_bar.close_time_ms,
            "observed_through_ms": decision_bar.close_time_ms,
            "entry_time_ms": entry.timestamp_ms,
            "exit_time_ms": exit.timestamp_ms,
            "direction": direction,
            "quantity": format(quantity, "f"),
            "gross_price_pnl": format(pnl.gross_price_pnl, "f"),
            "fees": format(pnl.fees, "f"),
            "net_pnl": format(pnl.net_pnl, "f"),
        })

    return {
        "schema_version": 1,
        "strategy": "causal_momentum_pilot_v1",
        "trade_count": len(trades),
        "net_pnl_quote": format(total, "f"),
        "deployment_authorized": False,
        "trades": trades,
    }

