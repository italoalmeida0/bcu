"""
Base scanner interface for application discovery.
"""

from __future__ import annotations

import abc
from typing import List
from bcu.models import ApplicationEntry


class BaseScanner(abc.ABC):
    """Abstract base class for all application discovery scanners."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the scanner."""
        pass

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Returns True if the scanner can run on the current environment."""
        pass

    @abc.abstractmethod
    def scan(self) -> List[ApplicationEntry]:
        """Scans the system and returns discovered ApplicationEntry objects."""
        pass
