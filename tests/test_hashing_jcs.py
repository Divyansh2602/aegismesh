"""Canonical JSON conformance (RFC 8785).

These are interop tests, not unit tests. Every assertion here is really the same claim:
that a verifier written in another language, against the same specification, produces the
same bytes we signed. Nothing else in the system can be checked by a third party if these
are wrong.
"""

import json

import pytest

from aegis.common.hashing import canonical_json, hash_object


def c(obj) -> str:
    return canonical_json(obj).decode("utf-8")


class TestNumbers:
    """ECMAScript ``Number::toString``, which is where Python's json module diverges."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # The one that actually bit us: the mock model proposes a float amount, and
            # Python's repr writes a trailing ".0" that no JCS implementation emits.
            (2000000.0, "2000000"),
            (1.0, "1"),
            (100.0, "100"),
            (0.0, "0"),
            (-0.0, "0"),  # JCS folds negative zero.
            (0.1, "0.1"),
            (0.87, "0.87"),
            (123.456, "123.456"),
            (-42.5, "-42.5"),
            # Plain-versus-exponential thresholds. ECMAScript switches at 1e21 and 1e-7;
            # Python's repr switches at 1e16 and 1e-4, so every value between the two sets
            # of thresholds is a divergence waiting to happen.
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1e30, "1e+30"),
            (5e-324, "5e-324"),
            (2.225073858507201e-308, "2.225073858507201e-308"),
            (333333333.3333333, "333333333.3333333"),
            (3, "3"),
            (-7, "-7"),
        ],
    )
    def test_number_serialization(self, value, expected):
        assert c(value) == expected

    def test_integral_float_and_int_are_indistinguishable(self):
        """2000000.0 and 2000000 must hash identically.

        JSON has one number type. A relying party that parsed ``2000000`` into an int while
        the issuer held a float must still recompute the same arguments hash, or step 5 of
        verification rejects every honest transfer with a round amount.
        """
        assert hash_object({"amount": 2000000.0}) == hash_object({"amount": 2000000})

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_numbers_are_rejected(self, value):
        """Emitting ``null`` for these would let an unrepresentable value through a
        signature check as if it had been agreed."""
        with pytest.raises(ValueError):
            canonical_json(value)


class TestStrings:
    def test_only_required_escapes_are_used(self):
        assert c('a"b\\c') == r'"a\"b\\c"'

    def test_control_characters_use_short_forms_then_lowercase_hex(self):
        """Backspace, formfeed, newline, return and tab have short forms; anything
        else below 0x20 is escaped as lowercase hex.

        The expected strings are built with chr() rather than written as literals so
        that no tool in the editing path can silently turn an escape sequence into the
        character it denotes -- which is exactly the class of bug this module tests for.
        """
        quote, backslash = chr(34), chr(92)
        assert c(chr(8) + chr(12) + chr(10) + chr(13) + chr(9)) == (
            quote + backslash + "b" + backslash + "f" + backslash + "n"
            + backslash + "r" + backslash + "t" + quote
        )
        assert c(chr(0) + chr(31)) == (
            quote + backslash + "u0000" + backslash + "u001f" + quote
        )

    def test_non_ascii_is_not_escaped(self):
        """JCS forbids escaping characters that do not require it."""
        assert canonical_json("héllo") == '"héllo"'.encode()
        assert canonical_json({"к": "з"}) == '{"к":"з"}'.encode()


class TestKeyOrdering:
    def test_keys_sort_by_utf16_code_unit_not_code_point(self):
        """The one ordering case where the two rules disagree.

        U+1F600 is a surrogate pair (D83D DE00) in UTF-16, so it sorts *before* U+FB33
        (FB33). By Unicode code point it sorts *after*. RFC 8785 mandates UTF-16, and a
        naive ``sorted()`` gets this backwards -- producing a document that verifies
        locally and fails everywhere else.
        """
        document = {"דּ": "dalet", "\U0001f600": "grin", "€": "euro", "1": "one"}
        assert _keys_in_order(document) == ["1", "€", "\U0001f600", "דּ"]
        assert sorted(document) != _keys_in_order(document), (
            "if a code-point sort matched, this test has stopped proving anything"
        )

    def test_nested_objects_are_sorted_too(self):
        assert c({"b": {"z": 1, "a": 2}, "a": 3}) == '{"a":3,"b":{"a":2,"z":1}}'

    def test_array_order_is_preserved(self):
        """Arrays are ordered data. Sorting them would change meaning, not normalize it."""
        assert c([3, 1, 2]) == "[3,1,2]"


def _keys_in_order(document: dict) -> list[str]:
    return list(json.loads(canonical_json(document).decode("utf-8")).keys())


class TestStructure:
    def test_no_insignificant_whitespace(self):
        assert c({"a": [1, 2], "b": None}) == '{"a":[1,2],"b":null}'

    def test_literals(self):
        assert c({"t": True, "f": False, "n": None}) == '{"f":false,"n":null,"t":true}'

    def test_non_string_keys_are_rejected(self):
        with pytest.raises(TypeError):
            canonical_json({1: "one"})

    def test_unserializable_types_are_rejected(self):
        with pytest.raises(TypeError):
            canonical_json({"when": object()})
