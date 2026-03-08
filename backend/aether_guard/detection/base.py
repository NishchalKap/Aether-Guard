from __future__ import annotations

from aether_guard.detection.signals import Signal


class Detector:
    """Interface for pluggable detectors."""

    name: str

    def analyze(self, *, text: str, sender: str | None, links: list[str]) -> list[Signal]:
        raise NotImplementedError


