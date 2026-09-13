"""ZTA (Zero Trust Architecture) Windows Python Agent Installer."""

import argparse
import ctypes
import os
from pathlib import Path
import sqlite3
import sys
from typing import Dict, Any


class InstallerError(Exception):
    """Custom exception raised when installer operations fail."""
    pass


class ZTAWindowsInstaller:
    """Automates installation of ZTA Agent on Windows endpoints."""

    DEFAULT_INSTALL_DIR = r"C:\Program Files\ZTA Agent"

    def __init__(self, install_dir: str = DEFAULT_INSTALL_DIR, manager_url: str = "http://127.0.0.1:8080"):
        self.install_dir = Path(install_dir)
        self.manager_url = manager_url

    def is_admin(self) -> bool:
        """Checks if installer is running with Windows Administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def create_directories(self):
        """Creates ZTA Agent installation directories with safe exception handling."""
        try:
            print(f"[*] Creating installation directory: {self.install_dir}")
            self.install_dir.mkdir(parents=True, exist_ok=True)
            (self.install_dir / "config").mkdir(exist_ok=True)
            (self.install_dir / "storage").mkdir(exist_ok=True)
            (self.install_dir / "logs").mkdir(exist_ok=True)
            print("    Directories created successfully.")
        except Exception as e:
            raise InstallerError(f"Failed to create installation directories at {self.install_dir}: {str(e)}")

    def write_configuration(self):
        """Writes ZTA Agent environment configuration file."""
        config_file = self.install_dir / "config" / "zta_agent.env"
        try:
            print(f"[*] Writing ZTA Agent configuration to: {config_file}")
            config_content = f"""# ZTA Agent Configuration File
ZTA_MANAGER_URL={self.manager_url}
ZTA_AGENT_ID=
ZTA_AGENT_TOKEN=
ZTA_HEARTBEAT_INTERVAL=30
ZTA_TELEMETRY_INTERVAL=15
ZTA_LOCAL_DB_PATH={self.install_dir / "storage" / "zta_agent_offline.db"}
ZTA_LOG_LEVEL=INFO
"""
            if config_file.exists():
                print("    Existing configuration preserved.")
                return
            with open(config_file, "w", encoding="utf-8") as f:
                f.write(config_content)
            print("    Configuration written successfully.")
        except Exception as e:
            raise InstallerError(f"Failed to write configuration file at {config_file}: {str(e)}")

    def initialize_local_database(self):
        """Initializes SQLite offline queue database schema."""
        db_path = self.install_dir / "storage" / "zta_agent_offline.db"
        try:
            print(f"[*] Initializing local offline database: {db_path}")
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Create offline telemetry queue table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS offline_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    collector_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)

            # Create local rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS local_rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    condition_json TEXT NOT NULL,
                    severity TEXT NOT NULL
                )
            """)

            conn.commit()
            conn.close()
            print("    Local offline database initialized successfully.")
        except Exception as e:
            raise InstallerError(f"Failed to initialize SQLite offline database at {db_path}: {str(e)}")

    def install(self, check_privileges: bool = True) -> bool:
        """Executes full Windows ZTA Agent installation flow.
        
        Returns:
            True on clean success.
        """
        print("==========================================================")
        print("         ZTA Agent Windows Installer Execution            ")
        print("==========================================================")

        if check_privileges and not self.is_admin():
            print("[!] Warning: Administrator privileges recommended for target C:\\Program Files creation.")

        try:
            self.create_directories()
            self.write_configuration()
            self.initialize_local_database()
            print("==========================================================")
            print("      ZTA Agent Installation Completed Successfully!       ")
            print("==========================================================")
            return True
        except InstallerError as ie:
            print(f"[!] Installation Error: {str(ie)}")
            return False
        except Exception as e:
            print(f"[!] Unexpected Installation Failure: {str(e)}")
            return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZTA Windows Agent Installer")
    parser.add_argument("--dir", default=ZTAWindowsInstaller.DEFAULT_INSTALL_DIR, help="Installation directory path")
    parser.add_argument("--manager", default="http://127.0.0.1:8080", help="ZTA Manager URL")
    args = parser.parse_args()

    installer = ZTAWindowsInstaller(install_dir=args.dir, manager_url=args.manager)
    success = installer.install(check_privileges=False)
    sys.exit(0 if success else 1)
