"""Runnable side-by-side of unsafe vs. safe ldap3 filter construction.

Usage (from the repository root):

    python security-review/demo.py

It uses the in-process Mock strategy, so no LDAP server or network access is
required. The BER inspection step uses the same search_operation() encoder
that Connection.search() uses for a real socket connection.
"""

import importlib.util
import pathlib

from ldap3 import Connection, MOCK_SYNC, SUBTREE, Server
from ldap3.core.exceptions import LDAPInvalidFilterError
from ldap3.operation.search import parse_filter
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

HERE = pathlib.Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


safe_ldap = _load("safe_ldap")
ber = _load("ber_inspect")

USERNAMES = [
    "alice",
    "a*b",
    "p(x)y",
    "back\\slash",
    "nul\\x00here".replace("\\x00", "\x00"),
    "é用户",
    "x)(|(uid=*)",
]


def section(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main():
    section("1. Three ways to build the same filter for one username")
    sample = "x)(|(uid=*)"
    naive = "(&(objectClass=person)(uid=%s))" % sample
    dn_escaped = "(&(objectClass=person)(uid=%s))" % escape_rdn(sample)
    safe = safe_ldap.and_filter(
        safe_ldap.equality_filter("objectClass", "person"),
        safe_ldap.equality_filter("uid", sample))
    print("untrusted username :", repr(sample))
    print("no escaping        :", naive)
    print("DN escaping (wrong):", dn_escaped)
    print("filter escaping    :", safe)

    section("2. What auto_escape=True actually parses")
    for label, text in (("no escaping", naive), ("filter escaping", safe)):
        try:
            tree = parse_filter(text, None, True, False, None, False)
            print("\n[%s] %s" % (label, text))
            print(repr(tree))
        except LDAPInvalidFilterError as exc:
            print("\n[%s] %s\n  rejected: %s" % (label, text, exc))

    section("3. BER wire tree of the correctly escaped filter")
    ber_bytes = ber.encode_search_request("ou=users", safe)
    base, tree = ber.decode_request_filter(ber_bytes)
    print("base object:", base)
    print("filter tree:", tree)

    section("4. Every required metacharacter, escaped once")
    for username in USERNAMES:
        print(repr(username).ljust(20), "->", safe_ldap.equality_filter("uid", username))

    section("5. Substring search keeps the caller's wildcard, not the user's")
    term = "a*b(c)"
    print("user term          :", repr(term))
    print("substring filter   :", safe_ldap.substring_filter("cn", term))
    print("anchored filter    :", safe_ldap.substring_filter("cn", term, anchored=True))

    section("6. DN layer: comma escaping where it actually belongs")
    print(safe_ldap.build_dn("cn", "Smith, John", "ou=users", "dc=example,dc=org"))

    section("7. Mock directory returns only the expected account")
    conn = Connection(Server("fake-directory"), client_strategy=MOCK_SYNC)
    conn.bind()
    conn.strategy.add_entry("uid=alice,ou=users", {
        "uid": "alice", "objectClass": "person", "cn": "Alice Wong",
        "jpegPhoto": b"\xff\xd8\xff\xe0binary\x00data"})
    conn.strategy.add_entry("uid=admin,ou=users", {
        "uid": "admin", "objectClass": "person", "cn": "Admin Root"})
    conn.strategy.add_entry("uid=victim,ou=users", {
        "uid": "victim", "objectClass": "person", "cn": "Victim User"})

    queries = [
        ("injection, escaped", safe_ldap.equality_filter("uid", "x)(|(uid=*)")),
        ("real account", safe_ldap.equality_filter("uid", "alice")),
        ("substring 'Ali'", safe_ldap.substring_filter("cn", "Ali")),
        ("substring user '*'", safe_ldap.substring_filter("cn", "a*b")),
    ]
    for label, filter_text in queries:
        conn.search("ou=users", filter_text, search_scope=SUBTREE,
                    attributes=["uid", "jpegPhoto"])
        print("%-22s %-34s -> %s" % (
            label, filter_text, [e.entry_dn for e in conn.entries]))
    conn.search("ou=users", safe_ldap.equality_filter("uid", "alice"),
                search_scope=SUBTREE, attributes=["jpegPhoto"])
    photo = conn.entries[0]["jpegPhoto"].value
    print("bytes attribute round-trip:", type(photo).__name__, photo)
    conn.unbind()


if __name__ == "__main__":
    main()
