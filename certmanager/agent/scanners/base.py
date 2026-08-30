"""Scanner plugin ABC for the datacenter agent.

Each scanner implements:
- scan(scope) -> ScanResult: execute discovery
- health_check() -> HealthStatus: verify operational readiness
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ScanResult:
    """Result from a scanner plugin execution."""

    scanner_name: str
    total_checked: int = 0
    total_new: int = 0
    total_updated: int = 0
    total_errors: int = 0
    certificates: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    def to_api_result(self) -> dict:
        """Convert to the format expected by the central API."""
        return {
            "total_checked": self.total_checked,
            "total_new": self.total_new,
            "total_updated": self.total_updated,
            "total_errors": self.total_errors,
            "certificates": self.certificates,
            "errors": self.errors,
            "scanner": self.scanner_name,
            "metadata": self.metadata,
        }


@dataclass
class HealthStatus:
    """Scanner health check result."""

    status: str  # ok | degraded | error
    message: str
    detail: dict = field(default_factory=dict)


class ScannerPlugin(ABC):
    """Abstract Base Class for agent scanner plugins.

    Scanners are loaded by the agent at startup based on agent_type.
    Each scanner implements the scan() method to discover certificates
    from a specific source (AD CS, TLS endpoints, etc.).
    """

    name: str = "base"

    @abstractmethod
    async def scan(self, scope: dict | None = None) -> ScanResult:
        """Execute a discovery scan.

        Args:
            scope: Scanner-specific filter dict (templates, CIDRs, etc.).

        Returns:
            ScanResult with discovered certificates and stats.
        """

    @abstractmethod
    async def health_check(self) -> HealthStatus:
        """Check if this scanner is operational.

        Returns:
            HealthStatus indicating readiness.
        """
