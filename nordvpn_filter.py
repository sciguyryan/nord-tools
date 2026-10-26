"""Small, deliberately bounded Boolean filter language for OpenVPN endpoints."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from nordvpn_regions import normalise_country_code


class FilterSyntaxError(ValueError):
    """An invalid filter expression, including its source position."""


def server_identity(filename: str) -> str:
    """Return a canonical NordVPN hostname, retaining unknown names unchanged."""
    match = re.fullmatch(
        r"(?:\d+-)?([a-z]{2}\d+\.nordvpn\.com)\.(?:udp|tcp)(?:_\d+(?:\.\d+)*)?\.ovpn",
        Path(filename).name,
        re.I,
    )
    return match.group(1).lower() if match else Path(filename).name


def compile_filter(expression: str, region_lists: dict | None = None):
    """Compile !, &, | and parentheses, with NOT > AND > OR precedence."""
    tokens = list(re.finditer(r"\s+|[!&|()]|[^\s!&|()]+", expression))
    items = [(m.group(), m.start()) for m in tokens if not m.group().isspace()]
    index = 0

    def fail(message, pos=None):
        if pos is None:
            pos = items[index][1] if index < len(items) else len(expression)
        raise FilterSyntaxError(f"{message} at column {pos + 1} in {expression!r}")

    def atom():
        nonlocal index
        if index == len(items):
            fail("expected a field or expression")
        token, pos = items[index]
        index += 1
        if token == "!":
            inner = atom()
            return lambda endpoint: not inner(endpoint)
        if token == "(":
            inner = expr(0)
            if index >= len(items) or items[index][0] != ")":
                fail("missing closing parenthesis")
            index += 1
            return inner
        if token in ("&", "|", ")"):
            fail("unexpected operator", pos)
        if ":" in token:
            field, pattern = token.split(":", 1)
        elif re.fullmatch(r"[a-z]{2}", token, re.I):
            field, pattern = "country", token
        elif re.fullmatch(r"[a-z]{2}\d+\*?", token, re.I):
            field, pattern = "server", token
        else:
            fail("use a two-letter country, server ID or explicit field", pos)
        field = field.lower()
        pattern = pattern.lower()
        if field not in ("country", "server", "host", "protocol", "port", "list") or not pattern:
            fail("unknown or empty field", pos)
        if field in ("country", "protocol", "port") and "*" in pattern:
            fail("wildcards are supported only for server and host", pos)
        if field == "list" and (region_lists is None or pattern not in region_lists):
            fail("unknown region list", pos)
        if field == "country" and not re.fullmatch(r"[a-z]{2}", pattern):
            fail("country must be a two-letter code", pos)
        if field == "country":
            pattern = normalise_country_code(pattern)
        if field == "protocol" and pattern not in ("udp", "tcp"):
            fail("protocol must be udp or tcp", pos)
        if field == "port" and (not pattern.isascii() or not pattern.isdecimal() or not 1 <= int(pattern) <= 65535):
            fail("port must be an integer from 1 to 65535", pos)
        if field in ("server", "host") and not re.fullmatch(r"[a-z0-9.*_-]+", pattern):
            fail("invalid wildcard pattern", pos)

        def predicate(endpoint):
            hostname = endpoint.name.lower()
            match = re.fullmatch(r"([a-z]{2}\d+)\.nordvpn\.com", hostname)
            server = match.group(1) if match else ""
            country = normalise_country_code(server[:2]) if server else ""
            if field == "list":
                return country in region_lists[pattern]["countries"]
            value = {
                "country": country,
                "server": server,
                "host": hostname,
                "protocol": endpoint.protocol.lower(),
                "port": str(endpoint.port),
            }[field]
            return fnmatch.fnmatchcase(value, pattern) if field in ("server", "host") else value == pattern

        return predicate

    def expr(min_precedence):
        nonlocal index
        left = atom()
        while index < len(items) and items[index][0] in ("&", "|"):
            operator = items[index][0]
            precedence = 2 if operator == "&" else 1
            if precedence < min_precedence:
                break
            index += 1
            right = expr(precedence + 1)
            previous = left
            if operator == "&":

                def conjunction(endpoint, a=previous, b=right):
                    return a(endpoint) and b(endpoint)

                left = conjunction
            else:

                def disjunction(endpoint, a=previous, b=right):
                    return a(endpoint) or b(endpoint)

                left = disjunction
        return left

    if not items:
        fail("empty filter")
    result = expr(0)
    if index != len(items):
        fail("unexpected token")
    return result
