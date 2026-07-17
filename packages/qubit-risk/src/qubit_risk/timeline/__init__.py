"""CRQC arrival-timeline modeling: surface-code resource math + Monte-Carlo simulator."""

from .simulator import CRQCTimelineSimulator, TimelineCurve
from .surface_code import min_distance, required_physical_qubits

__all__ = ["CRQCTimelineSimulator", "TimelineCurve", "min_distance", "required_physical_qubits"]
