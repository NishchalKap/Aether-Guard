from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from aether_guard.detection.base import Detector
from aether_guard.detection.signals import Signal
from aether_guard.services.telemetry import record_detector_execution


class DetectorPipeline:
    """
    Runs multiple detectors and aggregates their signals.

    Parallelism:
    - Uses a thread pool so multiple lightweight detectors can run concurrently.
    - This is appropriate for I/O-bound (future reputation lookups) and small CPU-bound heuristics.
      For heavy ML inference, prefer a dedicated model runtime / async queue / process pool.
    """

    def __init__(self, *, detectors: list[Detector], max_workers: int = 4) -> None:
        self._detectors = detectors
        self._max_workers = max_workers

    def run(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        if not self._detectors:
            return []

        out: list[Signal] = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as ex:
            futures = {
                ex.submit(d.analyze, text=text, sender=sender, links=links): d.name for d in self._detectors
            }
            for fut in as_completed(futures):
                det_name = futures[fut]
                start_time = time.time()
                error_occurred = False

                try:
                    signals = fut.result()
                    execution_time = time.time() - start_time
                    signal_names = [s.name for s in signals]

                    # Record telemetry
                    record_detector_execution(
                        detector_name=det_name,
                        execution_time=execution_time,
                        signals_emitted=signal_names,
                        error=False,
                    )

                    for s in signals:
                        out.append(s.normalized())

                except Exception as e:
                    execution_time = time.time() - start_time
                    error_occurred = True

                    # Record telemetry for error
                    record_detector_execution(
                        detector_name=det_name,
                        execution_time=execution_time,
                        signals_emitted=[],
                        error=True,
                    )

                    # Privacy-first: do not attach raw content to errors; bubble up as a generic failure signal.
                    out.append(
                        Signal(
                            name="detector_error",
                            confidence=1.0,
                            source=det_name,
                            evidence="A detector failed during analysis. The risk score may be less accurate.",
                        )
                    )

        return out


