"""ZTA namespace and launcher for the unified source checkout."""
from pathlib import Path

__path__ = [str(Path(__file__).resolve().parent)]

if __name__ == "__main__":
    from zta.dashboard.run_dashboard import main
    main()
