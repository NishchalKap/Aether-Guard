"""Tests for utility modules."""

import pytest

from aether_guard.utils.email_parser import (
    extract_domain_from_email,
    extract_domain_from_url,
    extract_urls,
    parse_email,
)


class TestEmailParser:
    """Tests for email parsing utilities."""

    def test_extract_urls(self):
        """Test URL extraction from text."""
        text = "Visit https://example.com and https://test.org/page"
        urls = extract_urls(text)

        assert len(urls) == 2
        assert "https://example.com" in urls
        assert "https://test.org/page" in urls

    def test_extract_domain_from_email(self):
        """Test domain extraction from email address."""
        domain = extract_domain_from_email("user@example.com")
        assert domain == "example.com"

        domain_none = extract_domain_from_email(None)
        assert domain_none is None

    def test_extract_domain_from_url(self):
        """Test domain extraction from URL."""
        domain = extract_domain_from_url("https://example.com/path")
        assert domain == "example.com"

        domain_none = extract_domain_from_url("not-a-url")
        assert domain_none is None or domain_none == ""

    def test_parse_email(self):
        """Test full email parsing."""
        parsed = parse_email(
            text="Subject: Test\n\nBody text with https://example.com",
            sender="user@example.com",
            links=["https://test.org"],
        )

        assert parsed.sender == "user@example.com"
        assert parsed.sender_domain == "example.com"
        assert len(parsed.links) >= 1
        assert "example.com" in parsed.domains or "test.org" in parsed.domains

