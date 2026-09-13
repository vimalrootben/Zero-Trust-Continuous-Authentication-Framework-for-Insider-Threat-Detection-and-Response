"""ZTA Manager package for API server, background processing, and dashboard orchestration."""
from zta.api.server import create_zta_server
from zta.api.background import BackgroundWorker
from zta.dashboard.run_dashboard import main

__all__ = ["create_zta_server", "BackgroundWorker", "main"]
