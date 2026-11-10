"""Repeatable evidence for the ldap3 filter-injection review.

Run from the repository root with:

    python -m pytest security-review/ -v

The tests deliberately exercise the raw ldap3 building blocks (parse_filter,
the two escape helpers, the Mock strategy) *and* the thin safe_ldap wrapper,
so each claim can be traced to an observable ldap3 behavior rather than
asserted about the library.
"""

import pytest

from ldap3 import ALL_ATTRIBUTES, Connection, MOCK_SYNC, SUBTREE, Server
from ldap3.core.exceptions import LDAPInvalidFilterError
from ldap3.operation.search import (
    MATCH_EQUAL,
    MATCH_PRESENT,
    MATCH_SUBSTRING,
    AND,
    OR,
    parse_filter,
)
from ldap3.protocol.convert import ava_to_dict, validate_assertion_value
from ldap3.protocol.rfc4511 import AssertionValue, AttributeDescription, EqualityMatch
from ldap3.utils.conv import escape_filter_chars, is_filter_escaped
from ldap3.utils.dn import escape_rdn

from conftest import ber_inspect as ber
from conftest import safe_ldap


# Usernames covering every RFC 4515 metacharacter plus non-ASCII text.
USERNAMES = [
    "alice",
    "a*b",                       # embedded star
    "open(x",                    # opening parenthesis
    "close)y",                   # closing parenthesis
    "back\\slash",              # backslash
    "mix*p(x)y\\z\x00q",        # star, brackets, backslash, NUL together
    "é用户",       # non-ASCII
    "x)(|(uid=*)",               # balanced, syntactically valid injection
]

# A value that needs RFC 4514 comma escaping when used inside a DN.
DN_NAME = "Smith, John"


def parse_tree(filter_text, auto_escape=True):
    root = parse_filter(filter_text, None, auto_escape=auto_escape,
                        auto_encode=False, validator=None, check_names=False)
    return root.elements[0]


# --------------------------------------------------------------------------
# What auto_escape=True actually does (and does not) protect
# --------------------------------------------------------------------------

def test_auto_escape_only_fires_for_backslash_values():
    # No backslash in the value, so validate_assertion_value leaves it alone
    # even with auto_escape enabled: the star survives to become an operator.
    star_value = validate_assertion_value(
        None, "uid", "a*b", auto_escape=True, auto_encode=False,
        validator=None, check_names=False)
    assert star_value == b"a*b"

    # A backslash that is not a valid escape triggers the only auto path.
    slash_value = validate_assertion_value(
        None, "uid", "back\\x", auto_escape=True, auto_encode=False,
        validator=None, check_names=False)
    assert slash_value == b"back\\5cx"


def test_parser_builds_the_tree_before_any_escaping():
    # The injection string is parsed as real filter syntax: an AND with an
    # extra OR/present branch, not as a single uid equality assertion.
    node = parse_tree("(&(objectClass=person)(uid=x)(|(uid=*)))")
    assert node.tag == AND
    assert len(node.elements) == 3
    assert node.elements[2].tag == OR
    present = node.elements[2].elements[0]
    assert present.tag == MATCH_PRESENT
    assert present.assertion == {"attr": "uid"}


def test_star_in_untrusted_input_becomes_substring_operator_when_unescaped():
    node = parse_tree("(uid=a*b)")
    assert node.tag == MATCH_SUBSTRING
    assert node.assertion == {"attr": "uid", "initial": b"a", "final": b"b"}


def test_malformed_injection_is_rejected_not_neutralized():
    # Some payloads simply fail to parse: auto_escape never gets a chance to
    # "fix" them because parsing happens first.
    with pytest.raises(LDAPInvalidFilterError):
        parse_tree("(&(objectClass=person)(uid=admin)(|(uid=*))")


# --------------------------------------------------------------------------
# Correct filter escaping vs. wrong (DN) escaping vs. no escaping
# --------------------------------------------------------------------------

@pytest.mark.parametrize("username", USERNAMES)
def test_escape_filter_chars_covers_every_metacharacter(username):
    escaped = escape_filter_chars(username)
    # After escaping, the text is a valid already-escaped filter value.
    assert is_filter_escaped(escaped)
    node = parse_tree("(uid=%s)" % escaped)
    assert node.tag == MATCH_EQUAL
    assert node.assertion["attr"] == "uid"


def test_escaped_injection_collapses_to_one_equality_assertion():
    injected = "x)(|(uid=*)"
    node = parse_tree("(uid=%s)" % escape_filter_chars(injected))
    assert node.tag == MATCH_EQUAL
    assert node.assertion == {
        "attr": "uid",
        "value": b"x\\29\\28|\\28uid=\\2a\\29",
    }


def test_dn_escaping_does_not_protect_a_filter():
    injected = "x)(|(uid=*)"
    # escape_rdn only handles the RFC 4514 set (", + \" < > ; \\ = NUL"); it
    # never escapes the RFC 4515 metacharacters '*' '(' ')'. The injected
    # parentheses therefore stay live filter syntax and the string is simply
    # rejected as malformed here instead of becoming a safe equality match.
    with pytest.raises(LDAPInvalidFilterError):
        parse_tree("(uid=%s)" % escape_rdn(injected))

    # A star-only payload makes the same point without unbalanced brackets:
    # DN escaping leaves '*' untouched, so the value is parsed as a substring
    # filter instead of a literal equality value.
    star_node = parse_tree("(uid=%s)" % escape_rdn("a*b"))
    assert star_node.tag == MATCH_SUBSTRING
    assert star_node.assertion["attr"] == "uid"


def test_dn_escaping_handles_comma_for_dn_layer_only():
    assert safe_ldap.dn_value(DN_NAME) == "Smith\\, John"
    assert safe_ldap.build_dn("cn", DN_NAME, "ou=users") == \
        "cn=Smith\\, John,ou=users"
    # The same helper must never be used on filter data: it keeps '*' literal
    # as far as filter syntax is concerned.
    assert "*" in escape_rdn("a*b")


# --------------------------------------------------------------------------
# BER-level confirmation of the on-the-wire filter tree
# --------------------------------------------------------------------------

def test_ber_shows_escaped_value_as_single_equality_literal():
    filter_text = "(&(objectClass=person)(uid=%s))" % \
        escape_filter_chars("x)(|(uid=*)")
    ber_bytes = ber.encode_search_request("ou=users", filter_text)
    base, tree = ber.decode_request_filter(ber_bytes)
    assert base == "ou=users"
    assert tree["op"] == "and"
    assert len(tree["children"]) == 2
    uid_clause = tree["children"][1]
    assert uid_clause["op"] == "equalityMatch"
    # The metacharacters travel as ASCII RFC 4515 hex pairs on the wire.
    assert uid_clause["value"] == b"x\\29\\28|\\28uid=\\2a\\29"
    assert uid_clause["value_hex"] == "785c32395c32387c5c32387569643d5c32615c3239"


def test_ber_shows_naive_injection_as_boolean_tree():
    ber_bytes = ber.encode_search_request(
        "ou=users", "(&(objectClass=person)(uid=x)(|(uid=*)))")
    _, tree = ber.decode_request_filter(ber_bytes)
    assert tree["op"] == "and"
    assert tree["children"][2]["op"] == "or"
    assert tree["children"][2]["children"][0] == {
        "op": "present", "attribute": "uid"}


def test_ber_preserves_caller_owned_substring_wildcards():
    # The wrapper adds the structural '*' around an escaped term; user stars
    # inside the term are themselves escaped and stay literal.
    filter_text = safe_ldap.substring_filter("cn", "a*b(c)")
    assert filter_text == "(cn=*a\\2ab\\28c\\29*)"
    _, tree = ber.decode_request_filter(
        ber.encode_search_request("ou=users", filter_text))
    assert tree["op"] == "substringFilter"
    assert tree["substrings"] == [{
        "kind": "any",
        "value": b"a\\2ab\\28c\\29",
        "value_hex": "615c3261625c3238635c3239",
    }]


def test_ber_non_ascii_is_utf8_with_metacharacters_hex_escaped():
    filter_text = safe_ldap.equality_filter("uid", "é用户*(")
    _, tree = ber.decode_request_filter(
        ber.encode_search_request("ou=users", filter_text))
    assert tree["value"] == "é用户\\2a\\28".encode("utf-8")
    assert tree["value_hex"] == "c3a9e794a8e688b75c32615c3238"


# --------------------------------------------------------------------------
# Mock directory: only the expected accounts come back, bytes values survive
# --------------------------------------------------------------------------

@pytest.fixture()
def mock_connection():
    conn = Connection(Server("fake-directory"), client_strategy=MOCK_SYNC)
    conn.bind()
    conn.strategy.add_entry("uid=alice,ou=users", {
        "uid": "alice",
        "objectClass": "person",
        "cn": "Alice Wong",
        "jpegPhoto": b"\xff\xd8\xff\xe0binary\x00data",
    })
    conn.strategy.add_entry("uid=admin,ou=users", {
        "uid": "admin", "objectClass": "person", "cn": "Admin Root"})
    conn.strategy.add_entry("uid=victim,ou=users", {
        "uid": "victim", "objectClass": "person", "cn": "Victim User"})
    yield conn
    conn.unbind()


def test_mock_escaped_injection_matches_nothing(mock_connection):
    filter_text = safe_ldap.and_filter(
        safe_ldap.equality_filter("objectClass", "person"),
        safe_ldap.equality_filter("uid", "x)(|(uid=*)"))
    mock_connection.search("ou=users", filter_text,
                           search_scope=SUBTREE, attributes=["uid"])
    assert [entry.entry_dn for entry in mock_connection.entries] == []


def test_mock_plain_equality_returns_only_expected_account(mock_connection):
    filter_text = safe_ldap.and_filter(
        safe_ldap.equality_filter("objectClass", "person"),
        safe_ldap.equality_filter("uid", "alice"))
    mock_connection.search("ou=users", filter_text,
                           search_scope=SUBTREE, attributes=ALL_ATTRIBUTES)
    dns = [entry.entry_dn for entry in mock_connection.entries]
    assert dns == ["uid=alice,ou=users"]


def test_mock_substring_search_still_works_and_is_scoped(mock_connection):
    # Intentional substring feature retained: "Ali" finds Alice only.
    mock_connection.search(
        "ou=users", safe_ldap.substring_filter("cn", "Ali"),
        search_scope=SUBTREE, attributes=["uid"])
    assert [e.entry_dn for e in mock_connection.entries] == \
        ["uid=alice,ou=users"]

    # A user-typed star is literal, so it cannot widen the search.
    mock_connection.search(
        "ou=users", safe_ldap.substring_filter("cn", "a*b"),
        search_scope=SUBTREE, attributes=["uid"])
    assert list(mock_connection.entries) == []


def test_mock_bytes_attribute_value_round_trips(mock_connection):
    mock_connection.search(
        "ou=users", safe_ldap.equality_filter("uid", "alice"),
        search_scope=SUBTREE, attributes=["jpegPhoto"])
    entry = mock_connection.entries[0]
    assert isinstance(entry["jpegPhoto"].value, bytes)
    assert entry["jpegPhoto"].value == b"\xff\xd8\xff\xe0binary\x00data"


def test_escaping_is_done_once_and_is_idempotent():
    username = "mix*p(x)y\\z\x00q"
    once = escape_filter_chars(username)
    # A second pass over an already-escaped value must not double the
    # backslashes: is_filter_escaped recognizes the valid hex pairs.
    again = validate_assertion_value(
        None, "uid", once, auto_escape=True, auto_encode=False,
        validator=None, check_names=False)
    assert again == once.encode("utf-8")
    # And calling escape_filter_chars twice directly would be wrong (it
    # re-escapes the backslash), documenting why the caller escapes once.
    twice = escape_filter_chars(once)
    assert twice != once
    assert twice.startswith("mix\\5c2a")


def test_mock_strategy_re_escapes_wire_values_known_limitation():
    # Documents (not works around) a real ldap3 Mock behavior: ava_to_dict
    # runs escape_filter_chars again when decoding the request, turning an
    # already-escaped value into a double-escaped one.
    ava = EqualityMatch()
    ava["attributeDesc"] = AttributeDescription("uid")
    ava["assertionValue"] = AssertionValue(b"star\\2ax")
    assert ava_to_dict(ava)["value"] == "star\\5c2ax"

    conn = Connection(Server("fake"), client_strategy=MOCK_SYNC)
    conn.bind()
    conn.strategy.add_entry("uid=star*x,ou=users",
                            {"uid": "star*x", "objectClass": "person"})
    conn.search("ou=users", safe_ldap.equality_filter("uid", "star*x"),
                search_scope=SUBTREE, attributes=["uid"])
    # A real directory receives the correct single-escaped BER; the Mock
    # re-decode quirk means this equality lookup does not match in Mock.
    assert list(conn.entries) == []
