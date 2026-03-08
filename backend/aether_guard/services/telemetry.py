from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import DefaultDict

logger = logging.getLogger(__name__)


@dataclass
class DetectorMetrics:
    """Performance metrics for a single detector."""

    detector_name: str
    execution_count: int = 0
    total_execution_time: float = 0.0
    error_count: int = 0
    signal_counts: DefaultDict[str, int] = field(default_factory=lambda: defaultdict(int))
    last_execution: datetime | None = None

    @property
    def avg_execution_time(self) -> float:
        """Average execution time in seconds."""
        if self.execution_count == 0:
            return 0.0
        return self.total_execution_time / self.execution_count

    @property
    def reliability(self) -> float:
        """Reliability score (1.0 = no errors, 0.0 = all errors)."""
        if self.execution_count == 0:
            return 1.0
        return 1.0 - (self.error_count / self.execution_count)


class DetectorTelemetry:
    """
    Tracks detector performance metrics.

    Privacy-first: Only tracks execution metadata, not content.
    """

    def __init__(self) -> None:
        self._metrics: dict[str, DetectorMetrics] = {}
        self._lock = threading.Lock()

    def record_execution(
        self,
        *,
        detector_name: str,
        execution_time: float,
        signals_emitted: list[str],
        error: bool = False,
    ) -> None:
        """
        Record detector execution metrics.

        Args:
            detector_name: Name of the detector
            execution_time: Execution time in seconds
            signals_emitted: List of signal names emitted
            error: Whether execution resulted in an error
        """
        with self._lock:
            if detector_name not in self._metrics:
                self._metrics[detector_name] = DetectorMetrics(detector_name=detector_name)

            metrics = self._metrics[detector_name]
            metrics.execution_count += 1
            metrics.total_execution_time += execution_time
            metrics.last_execution = datetime.now(timezone.utc)

            if error:
                metrics.error_count += 1

            for signal_name in signals_emitted:
                metrics.signal_counts[signal_name] += 1

    def get_metrics(self, detector_name: str | None = None) -> DetectorMetrics | dict[str, DetectorMetrics]:
        """
        Get metrics for a detector or all detectors.

        Args:
            detector_name: Specific detector name, or None for all

        Returns:
            DetectorMetrics or dict of all metrics
        """
        with self._lock:
            if detector_name:
                return self._metrics.get(detector_name, DetectorMetrics(detector_name=detector_name))
            return self._metrics.copy()

    def get_summary(self) -> dict:
        """
        Get summary statistics for all detectors.

        Returns:
            Dictionary with aggregated stats
        """
        with self._lock:
            total_executions = sum(m.execution_count for m in self._metrics.values())
            total_errors = sum(m.error_count for m in self._metrics.values())
            avg_time = (
                sum(m.avg_execution_time for m in self._metrics.values()) / len(self._metrics)
                if self._metrics
                else 0.0
            )

            return {
                "total_detectors": len(self._metrics),
                "total_executions": total_executions,
                "total_errors": total_errors,
                "overall_reliability": 1.0 - (total_errors / total_executions) if total_executions > 0 else 1.0,
                "avg_execution_time": avg_time,
                "detectors": {
                    name: {
                        "execution_count": m.execution_count,
                        "avg_execution_time": m.avg_execution_time,
                        "reliability": m.reliability,
                        "error_count": m.error_count,
                        "top_signals": dict(sorted(m.signal_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
                    }
                    for name, m in self._metrics.items()
                },
            }


# Global telemetry instance
_telemetry = DetectorTelemetry()


def get_telemetry() -> DetectorTelemetry:
    """Get global telemetry instance."""
    return _telemetry


def record_detector_execution(
    detector_name: str,
    execution_time: float,
    signals_emitted: list[str],
    error: bool = False,
) -> None:
    """Convenience function to record detector execution."""
    _telemetry.record_execution(
        detector_name=detector_name,
        execution_time=execution_time,
        signals_emitted=signals_emitted,
        error=error,
    )

