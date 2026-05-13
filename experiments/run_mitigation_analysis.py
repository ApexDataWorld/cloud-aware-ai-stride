from __future__ import annotations

from pathlib import Path

from experiments.common import prepare_benchmark


def main() -> None:
    benchmark = prepare_benchmark()
    root = benchmark["root"]
    tables_dir = Path(root) / "reports" / "tables"
    tables_dir.mkdir(parents=True, exist_ok=True)
    benchmark["mitigation_mapping"].to_csv(tables_dir / "mitigation_mapping.csv", index=False)
    benchmark["mitigation_coverage"].to_csv(tables_dir / "mitigation_coverage.csv", index=False)


if __name__ == "__main__":
    main()
