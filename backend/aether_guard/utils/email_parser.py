from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParsedEmail:
    """Structured representation of parsed email content."""

    text: str
    sender: str | None
    sender_domain: str | None
    links: list[str]
    domains: list[str]
    subject: str | None
    body: str | None
    urgency_indicators: list[str]


def extract_urls(text: str) -> list[str]:
    """
    Extract URLs from text using regex.

    Returns:
        List of unique URLs found in text.
    """
    # Pattern matches http:// and https:// URLs
    pattern = r"https?://[^\s\)>\"]+"
    urls = re.findall(pattern, text, flags=re.IGNORECASE)
    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        if url.lower() not in seen:
            seen.add(url.lower())
            unique_urls.append(url)
    return unique_urls


def extract_domain_from_email(email: str | None) -> str | None:
    """
    Extract domain from email address.

    Args:
        email: Email address (e.g., "user@example.com")

    Returns:
        Domain part (e.g., "example.com") or None
    """
    if not email:
        return None

    match = re.search(r"@([a-z0-9.\-]+\.[a-z]{2,})", email.lower())
    return match.group(1) if match else None


def extract_domain_from_url(url: str) -> str | None:
    """
    Extract domain from URL.

    Args:
        url: Full URL

    Returns:
        Domain part or None
    """
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        return None


def extract_domains(text: str, links: list[str]) -> list[str]:
    """
    Extract all unique domains from text and links.

    Returns:
        List of unique domains
    """
    domains: set[str] = set()

    # Extract from links
    for link in links:
        domain = extract_domain_from_url(link)
        if domain:
            domains.add(domain)

    # Extract from text URLs
    text_urls = extract_urls(text)
    for url in text_urls:
        domain = extract_domain_from_url(url)
        if domain:
            domains.add(domain)

    return sorted(domains)


def split_subject_body(text: str) -> tuple[str | None, str]:
    """
    Attempt to split email text into subject and body.

    Looks for common patterns:
    - "Subject: ..." or "Re: ..." prefixes
    - Double newlines as separator

    Returns:
        Tuple of (subject, body). Subject may be None.
    """
    text = text.strip()

    # Check for explicit Subject: header
    subject_match = re.match(r"^subject:\s*(.+?)(?:\n\n|\r\n\r\n)", text, flags=re.IGNORECASE | re.DOTALL)
    if subject_match:
        subject = subject_match.group(1).strip()
        body = text[subject_match.end() :].strip()
        return subject, body

    # Check for Re:/Fwd: prefix (common in forwarded emails)
    re_match = re.match(r"^(re|fwd|fwd:):\s*(.+?)(?:\n\n|\r\n\r\n)", text, flags=re.IGNORECASE | re.DOTALL)
    if re_match:
        subject = re_match.group(0).split("\n")[0].strip()
        body = text[len(subject) :].strip()
        return subject, body

    # Try splitting on double newline
    parts = re.split(r"\n\n|\r\n\r\n", text, maxsplit=1)
    if len(parts) == 2 and len(parts[0]) < 200:  # Likely a subject if short
        return parts[0].strip(), parts[1].strip()

    # No clear subject/body split
    return None, text


def detect_urgency_indicators(text: str) -> list[str]:
    """
    Detect urgency/time-pressure language indicators.

    Returns:
        List of detected urgency phrases
    """
    urgency_patterns = [
        (r"\burgent\b", "urgent"),
        (r"\bimmediately\b", "immediately"),
        (r"\basap\b", "asap"),
        (r"\brush\b", "rush"),
        (r"\bwithin\s+\d+\s+(?:minutes?|hours?)\b", "time limit"),
        (r"\byour\s+account\s+will\s+be\s+(?:closed|disabled|locked)", "account threat"),
        (r"\bexpir(?:es?|ing)\s+(?:soon|today)", "expiration warning"),
        (r"\bfinal\s+notice\b", "final notice"),
        (r"\baction\s+required\b", "action required"),
    ]

    detected = []
    text_lower = text.lower()
    for pattern, label in urgency_patterns:
        if re.search(pattern, text_lower):
            detected.append(label)

    return detected


def parse_email(*, text: str, sender: str | None, links: list[str] | None = None) -> ParsedEmail:
    """
    Parse email content into structured format.

    Args:
        text: Email text (subject + body)
        sender: Sender email address
        links: Explicit list of links (will also extract from text)

    Returns:
        ParsedEmail object with extracted components
    """
    # Extract links if not provided
    extracted_links = extract_urls(text)
    all_links = list(set((links or []) + extracted_links))

    # Extract domains
    domains = extract_domains(text, all_links)

    # Extract sender domain
    sender_domain = extract_domain_from_email(sender)

    # Split subject/body
    subject, body = split_subject_body(text)

    # Detect urgency
    urgency_indicators = detect_urgency_indicators(text)

    return ParsedEmail(
        text=text,
        sender=sender,
        sender_domain=sender_domain,
        links=all_links,
        domains=domains,
        subject=subject,
        body=body,
        urgency_indicators=urgency_indicators,
    )

