"""Literal-aware lexical views for the bounded F* source inventories.

Preserve source positions and fail closed on unsupported lexical forms. These
views identify syntax sites; they do not establish F* declaration semantics.
"""

from __future__ import annotations

import re

# Pinned LexFStar char/escape_char productions, including the byte suffix.
CHAR = re.compile(r"'(?:[^\\]|\\(?:[\\'\"nrtbfv0]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}))'B?")


class SourceLexingError(ValueError):
    """Source uses an unsupported or unterminated lexical construct."""


def lexical_views(text: str, *, allow_comment_eof: bool = False) -> tuple[str, str]:
    """Return comment-free text and a same-length view with literals masked.

    Preserve newline/column positions, and do not interpret comment delimiters
    inside strings or character literals. Nested block comments are supported.
    F* 2025.10.06 permits a block comment to extend to EOF; admission uses that
    convention explicitly. The foreign inventory keeps its stricter syntax policy.
    """
    if any(c in text for c in "\u0085\u2028\u2029\v\f"):
        raise SourceLexingError("unsupported line separator")
    clean, masked = list(text), list(text)

    def blank(start: int, end: int, *, literal: bool = False) -> None:
        for index in range(start, end):
            if text[index] not in "\r\n":
                masked[index] = " "
                if not literal:
                    clean[index] = " "

    i = 0
    while i < len(text):
        if text.startswith("(*", i):
            start, depth = i, 1
            i += 2
            while i < len(text) and depth:
                if text.startswith("(*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*)", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth and not allow_comment_eof:
                raise SourceLexingError("unterminated block comment")
            blank(start, i)
        elif text.startswith("//", i):
            if text.startswith("// IN F*:", i):
                raise SourceLexingError("unsupported F* executable line-comment escape")
            start = i
            while i < len(text) and text[i] not in "\r\n":
                i += 1
            blank(start, i)
        elif text[i] == '"':
            start = i
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise SourceLexingError("unterminated string literal")
            blank(start, i, literal=True)
        elif text.startswith("``", i):
            raise SourceLexingError("unsupported escaped F* identifier")
        elif text[i].isalpha() or text[i] in "_'":
            # F* identifiers may also START with apostrophes. The lexer chooses
            # the longest IDENT/CHAR candidate, with CHAR winning a length tie.
            end = i + 1
            while end < len(text) and (text[end].isalnum() or text[end] in "_'"):
                end += 1
            char = CHAR.match(text, i)
            if char is not None and char.end() >= end:
                blank(i, char.end(), literal=True)
                i = char.end()
            else:
                i = end
        else:
            i += 1
    return "".join(clean), "".join(masked)
