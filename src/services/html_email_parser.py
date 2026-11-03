"""Extract readable text and HTTP(S) links from email HTML.

Does not render HTML, execute scripts or fetch remote resources.
"""

from html.parser import HTMLParser
from urllib.parse import urlsplit


class HtmlEmailParser(HTMLParser):
    """Collect text and hyperlink destinations from HTML."""

    BLOCK_TAGS = {
        "address", "article", "blockquote", "div", "footer",
        "h1", "h2", "h3", "h4", "h5", "h6", "header",
        "li", "p", "section", "table", "tr",
    }

    IGNORED_TAGS = {"head", "script", "style"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._text_parts = []
        self._links = []
        self._ignored_tags = []

    @property
    def text(self) -> str:
        """Return readable text with normalised whitespace."""
        lines = []

        for line in "".join(self._text_parts).splitlines():
            clean_line = " ".join(line.split())

            if clean_line:
                lines.append(clean_line)

        return "\n".join(lines)

    @property
    def links(self) -> list[str]:
        return list(self._links)

    def handle_starttag(self, tag, attrs) -> None:
        if self._ignored_tags:
            if tag in self.IGNORED_TAGS:
                self._ignored_tags.append(tag)
            return

        if tag in self.IGNORED_TAGS:
            self._ignored_tags.append(tag)
            return

        if tag == "br" or tag in self.BLOCK_TAGS:
            self._text_parts.append("\n")

        if tag in {"td", "th"}:
            self._text_parts.append(" ")

        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self._collect_link(value)

    def handle_endtag(self, tag) -> None:
        if self._ignored_tags:
            if tag == self._ignored_tags[-1]:
                self._ignored_tags.pop()
            return

        if tag in self.BLOCK_TAGS:
            self._text_parts.append("\n")

    def handle_startendtag(self, tag, attrs) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data) -> None:
        if not self._ignored_tags:
            self._text_parts.append(data)

    def _collect_link(self, value: str) -> None:
        link = value.strip()

        try:
            parsed = urlsplit(link)

            if parsed.scheme.lower() not in {"http", "https"}:
                return

            if not parsed.hostname:
                return

        except ValueError:
            return

        if link not in self._links:
            self._links.append(link)