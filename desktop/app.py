"""Application entrypoint for launching CyberSecuritySuite desktop interface."""

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from core.registry import ToolRegistry
from desktop.main_window import MainWindow
from storage.db import Database


def main():
    """Main execution function."""
    app = QApplication(sys.argv)
    app.setApplicationName("CyberSecuritySuite")
    app.setOrganizationName("CyberSecuritySuite")

    # Persistent database path in workspace
    db_path = Path(__file__).resolve().parent.parent / "storage" / "data" / "cybersecuritysuite.db"
    db = Database(db_path)
    registry = ToolRegistry()

    window = MainWindow(db=db, registry=registry)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
