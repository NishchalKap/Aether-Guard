from __future__ import annotations

"""
Very small service container for early-stage development.

Why:
- Ensures shared state (privacy-safe alert history) is consistent across routers.
- Avoids full DI framework complexity until we introduce real persistence/queues.
"""

from aether_guard.services.phishing_service import PhishingAnalysisService


phishing_service = PhishingAnalysisService()


