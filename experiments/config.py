from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "processed"
RAW_DIR = ROOT / "data" / "raw"
RESULTS_DIR = ROOT / "results"
FIGURES_DIR = RESULTS_DIR / "figures"
TABLES_DIR = RESULTS_DIR / "tables"
LOGS_DIR = RESULTS_DIR / "logs"

DATASET_SIZE = 100_000
SEEDS = [7, 11, 23, 42, 99]
SCALABILITY_SIZES = [10_000, 50_000, 100_000, 250_000, 500_000]

for folder in [DATA_DIR, RAW_DIR, FIGURES_DIR, TABLES_DIR, LOGS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)
