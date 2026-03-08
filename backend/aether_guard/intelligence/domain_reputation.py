from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Suspicious TLDs commonly used in phishing/scams
SUSPICIOUS_TLDS = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".click",
    ".download",
    ".stream",
    ".online",
    ".site",
    ".website",
    ".space",
    ".tech",
    ".store",
    ".shop",
}

# Disposable email domain patterns (common temporary email services)
DISPOSABLE_DOMAINS = {
    "10minutemail.com",
    "tempmail.com",
    "guerrillamail.com",
    "mailinator.com",
    "throwaway.email",
    "temp-mail.org",
    "getnada.com",
    "mohmal.com",
    "yopmail.com",
    "maildrop.cc",
}


@dataclass(frozen=True)
class DomainReputation:
    """Domain reputation assessment."""

    domain: str
    is_suspicious_tld: bool
    is_disposable: bool
    risk_score: float  # 0.0 (safe) to 1.0 (high risk)
    indicators: list[str]


def assess_domain_reputation(domain: str) -> DomainReputation:
    """
    Assess domain reputation based on TLD and known patterns.

    Args:
        domain: Domain name (e.g., "example.com")

    Returns:
        DomainReputation object with risk assessment
    """
    domain_lower = domain.lower().strip()

    indicators: list[str] = []
    risk_score = 0.0

    # Check TLD
    is_suspicious_tld = False
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            is_suspicious_tld = True
            indicators.append(f"Uses suspicious TLD: {tld}")
            risk_score += 0.4
            break

    # Check disposable domains
    is_disposable = domain_lower in DISPOSABLE_DOMAINS
    if is_disposable:
        indicators.append("Domain is a disposable/temporary email service")
        risk_score += 0.3

    # Normalize risk score
    risk_score = min(risk_score, 1.0)

    return DomainReputation(
        domain=domain_lower,
        is_suspicious_tld=is_suspicious_tld,
        is_disposable=is_disposable,
        risk_score=risk_score,
        indicators=indicators,
    )


def get_domain_age(domain: str) -> int | None:
    """
    Get domain age in days (placeholder for future WHOIS integration).

    Args:
        domain: Domain name

    Returns:
        Age in days, or None if unavailable
    """
    # Placeholder: In production, this would query WHOIS or a domain age API
    # For now, return None to indicate unavailable
    return None


def is_known_legitimate_domain(domain: str) -> bool:
    """
    Check if domain is in a known legitimate list (placeholder).

    Args:
        domain: Domain name

    Returns:
        True if domain is known to be legitimate
    """
    # Placeholder: In production, this would check against:
    # - Institutional domain whitelist
    # - Known good domain database
    # - Domain reputation API
    return False


def check_domain_typosquatting(domain: str, legitimate_domains: list[str]) -> bool:
    """
    Check if domain appears to be typosquatting a legitimate domain.

    Args:
        domain: Domain to check
        legitimate_domains: List of known legitimate domains

    Returns:
        True if typosquatting is detected
    """
    domain_lower = domain.lower()

    for legit in legitimate_domains:
        legit_lower = legit.lower()

        # Simple checks:
        # 1. Character insertion/deletion (e.g., "gooogle.com" vs "google.com")
        # 2. Character substitution (e.g., "g00gle.com" vs "google.com")
        # 3. Missing character (e.g., "googl.com" vs "google.com")

        if len(domain_lower) - len(legit_lower) in (-2, -1, 0, 1, 2):
            # Check if domains are similar (simple Levenshtein-like check)
            differences = sum(c1 != c2 for c1, c2 in zip(domain_lower, legit_lower))
            if differences <= 2 and domain_lower != legit_lower:
                return True

    return False

