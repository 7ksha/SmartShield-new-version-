

import sqlite3
from abc import ABC, abstractmethod


class ISQLite(ABC):
    """Interface for SQLite database operations."""

    name = "ISQLite"

    def __init__(self, logger, output_dir, main_pid):
        self.logger = logger
        self.output_dir = output_dir
        self.main_pid = main_pid

    @abstractmethod
    def connect(self):
        """Connect to the SQLite database."""

    @abstractmethod
    def create_table(self, query: str):
        """Create a table with the given query."""

    @abstractmethod
    def execute(self, query: str, params=None):
        """Execute a raw query."""

    @abstractmethod
    def fetchall(self, query: str, params=None):
        """Execute and fetch all results."""
