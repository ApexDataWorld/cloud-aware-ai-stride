from __future__ import annotations

from pathlib import Path

from experiments.common import prepare_benchmark


def main() -> None:
    benchmark = prepare_benchmark()
    tables_dir = Path(benchmark["root"]) / "reports" / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)
    benchmark["residual_risk"].to_csv(tables_dir / "residual_risk_ranking.csv", index=False)


if __name__ == "__main__":
    main()
