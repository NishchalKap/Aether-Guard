"""Threat intelligence modules for domain reputation and threat data."""

from aether_guard.intelligence.domain_reputation import (
    DISPOSABLE_DOMAINS,
    SUSPICIOUS_TLDS,
    DomainReputation,
    assess_domain_reputation,
    check_domain_typosquatting,
    get_domain_age,
    is_known_legitimate_domain,
)

__all__ = [
    "assess_domain_reputation",
    "check_domain_typosquatting",
    "get_domain_age",
    "is_known_legitimate_domain",
    "DomainReputation",
    "SUSPICIOUS_TLDS",
    "DISPOSABLE_DOMAINS",
]

