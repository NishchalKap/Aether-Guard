from __future__ import annotations

from typing import Type

from aether_guard.detection.base import Detector

# Registry of all available detectors.
# Detectors register themselves by importing this module and adding their class here.
# This allows the pipeline to dynamically load detectors.

DETECTOR_REGISTRY: list[Type[Detector]] = []


def register_detector(detector_class: Type[Detector]) -> Type[Detector]:
    """
    Decorator to register a detector class.

    Usage:
        @register_detector
        class MyDetector(Detector):
            name = "my_detector"
            ...
    """
    if detector_class not in DETECTOR_REGISTRY:
        DETECTOR_REGISTRY.append(detector_class)
    return detector_class


def get_all_detectors() -> list[Detector]:
    """
    Instantiate all registered detectors.

    Returns:
        List of detector instances ready for use in the pipeline.
    """
    return [cls() for cls in DETECTOR_REGISTRY]

