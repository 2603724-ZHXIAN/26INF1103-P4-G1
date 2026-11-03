"""Offline tests for HTML email content extraction."""

import unittest

from src.services.html_email_parser import HtmlEmailParser


class TestHtmlEmailParser(unittest.TestCase):

    def parse_html(self, content):
        parser = HtmlEmailParser()
        parser.feed(content)
        parser.close()
        return parser

    def test_extracts_readable_text_and_character_entities(self):
        parser = self.parse_html(
            "<p>Hello &amp; welcome</p>"
            "<p>Please verify your account.</p>"
        )

        self.assertEqual(
            parser.text,
            "Hello & welcome\nPlease verify your account.",
        )

    def test_collects_actual_link_destination(self):
        parser = self.parse_html(
            '<a href="https://example.com/verify">'
            "Verify account"
            "</a>"
        )

        self.assertEqual(parser.text, "Verify account")
        self.assertEqual(
            parser.links,
            ["https://example.com/verify"],
        )

    def test_excludes_scripts_styles_and_head_content(self):
        parser = self.parse_html(
            "<head><title>Hidden title</title></head>"
            "<style>body { color: red; }</style>"
            "<script>alert('example')</script>"
            "<p>Visible message</p>"
        )

        self.assertEqual(parser.text, "Visible message")

    def test_ignores_non_http_and_relative_links(self):
        parser = self.parse_html(
            '<a href="javascript:alert(1)">One</a>'
            '<a href="mailto:test@example.com">Two</a>'
            '<a href="/relative">Three</a>'
            '<a href="https://example.com">Four</a>'
        )

        self.assertEqual(
            parser.links,
            ["https://example.com"],
        )

    def test_deduplicates_links_and_decodes_entities(self):
        parser = self.parse_html(
            '<a href="https://example.com?a=1&amp;b=2">One</a>'
            '<a href="https://example.com?a=1&amp;b=2">Two</a>'
        )

        self.assertEqual(
            parser.links,
            ["https://example.com?a=1&b=2"],
        )

    def test_links_property_protects_internal_collection(self):
        parser = self.parse_html(
            '<a href="https://example.com">Example</a>'
        )

        links = parser.links
        links.clear()

        self.assertEqual(
            parser.links,
            ["https://example.com"],
        )

    def test_recovers_text_from_unclosed_paragraph(self):
        parser = self.parse_html("<p>Incomplete HTML")

        self.assertEqual(parser.text, "Incomplete HTML")


if __name__ == "__main__":
    unittest.main()