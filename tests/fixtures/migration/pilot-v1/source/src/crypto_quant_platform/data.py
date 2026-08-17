from __future__ import annotations

from decimal import Decimal
import json
from pathlib import Path

from crypto_quant_core import Candle, DataIntegrityError, assert_monotonic_timestamps


def load_candles_jsonl(path: str | Path) -> tuple[Candle, ...]:
    source = Path(path)
    candles: list[Candle] = []
    try:
        for line_number, raw_line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if not raw_line.strip():
                continue
            payload = json.loads(raw_line)
            candles.append(
                Candle(
                    symbol=str(payload["symbol"]).upper(),
                    interval=str(payload["interval"]),
                    open_time_ms=int(payload["open_time_ms"]),
                    close_time_ms=int(payload["close_time_ms"]),
                    open=Decimal(str(payload["open"])),
                    high=Decimal(str(payload["high"])),
                    low=Decimal(str(payload["low"])),
                    close=Decimal(str(payload["close"])),
                    volume=Decimal(str(payload["volume"])),
                )
            )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DataIntegrityError(f"invalid candle file {source} at line {locals().get('line_number', 0)}") from exc
    if not candles:
        raise DataIntegrityError("candle file is empty")
    identity = {(candle.symbol, candle.interval) for candle in candles}
    if len(identity) != 1:
        raise DataIntegrityError("candle file mixes symbols or intervals")
    assert_monotonic_timestamps((candle.open_time_ms for candle in candles))
    for previous, current in zip(candles, candles[1:]):
        if current.open_time_ms <= previous.close_time_ms:
            raise DataIntegrityError("candle intervals overlap")
    return tuple(candles)

