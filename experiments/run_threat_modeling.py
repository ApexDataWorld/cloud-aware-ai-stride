from __future__ import annotations

from experiments.common import prepare_benchmark, run_all_reports


def main() -> None:
    benchmark = prepare_benchmark()
    run_all_reports(benchmark)


if __name__ == "__main__":
    main()
