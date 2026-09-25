"""
Fixture for alias dereferencing in the Mock strategies. No real server is
needed: the DIT below is loaded into the in-memory mock server and every
combination of dereference_aliases (NEVER, SEARCH, FINDING_BASE, ALWAYS) and
search scope (BASE, LEVEL, SUBTREE) is checked against an explicit DN set.

Dereferencing semantics implemented by the mock server:
- FINDING_BASE (and ALWAYS) dereference the base object when it is an alias;
  a dangling target returns aliasProblem (33), an alias loop returns
  aliasDereferencingProblem (36)
- SEARCH (and ALWAYS) dereference aliases found while searching (never the
  base object itself); the filter and the returned attributes are evaluated
  against the real target entry and the target DN is returned
- the same target entry reached through multiple aliases (or directly and
  through an alias) is returned only once
- aliases with a dangling target or involved in a loop are skipped while
  searching; cross-subtree targets are followed
- alias chains are followed up to a non-alias entry
"""

import unittest

from ldap3 import Server, Connection, MOCK_SYNC, BASE, LEVEL, SUBTREE, \
    DEREF_NEVER, DEREF_SEARCH, DEREF_BASE, DEREF_ALWAYS

LAB = 'o=lab'
PEOPLE = 'ou=people,o=lab'
ALICE = 'cn=alice,ou=people,o=lab'
BOB = 'cn=bob,ou=people,o=lab'
ALIAS_TO_ALICE = 'cn=alias-to-alice,ou=people,o=lab'
SECOND_ALIAS_TO_ALICE = 'cn=second-alias-to-alice,ou=people,o=lab'
ALIAS_TO_GROUPS = 'cn=alias-to-groups,ou=people,o=lab'
GROUPS = 'ou=groups,o=lab'
ADMINS = 'cn=admins,ou=groups,o=lab'
ALIASES = 'ou=aliases,o=lab'
ALIAS_TO_BOB = 'cn=alias-to-bob,ou=aliases,o=lab'
CHAIN_FIRST = 'cn=chain-first,ou=aliases,o=lab'
CHAIN_SECOND = 'cn=chain-second,ou=aliases,o=lab'
DANGLING_ALIAS = 'cn=dangling-alias,ou=aliases,o=lab'
LOOP_FIRST = 'cn=loop-first,ou=aliases,o=lab'
LOOP_SECOND = 'cn=loop-second,ou=aliases,o=lab'

DEREF_MODES = (DEREF_NEVER, DEREF_SEARCH, DEREF_BASE, DEREF_ALWAYS)
SCOPES = (BASE, LEVEL, SUBTREE)

# expected DN sets for base 'ou=people,o=lab' and filter '(objectClass=*)'
EXPECTED_FROM_PEOPLE = {
    (DEREF_NEVER, BASE): {PEOPLE},
    (DEREF_NEVER, LEVEL): {ALICE, BOB, ALIAS_TO_ALICE, SECOND_ALIAS_TO_ALICE, ALIAS_TO_GROUPS},
    (DEREF_NEVER, SUBTREE): {PEOPLE, ALICE, BOB, ALIAS_TO_ALICE, SECOND_ALIAS_TO_ALICE, ALIAS_TO_GROUPS},
    (DEREF_SEARCH, BASE): {PEOPLE},
    (DEREF_SEARCH, LEVEL): {ALICE, BOB, GROUPS},
    (DEREF_SEARCH, SUBTREE): {PEOPLE, ALICE, BOB, GROUPS},
    (DEREF_BASE, BASE): {PEOPLE},
    (DEREF_BASE, LEVEL): {ALICE, BOB, ALIAS_TO_ALICE, SECOND_ALIAS_TO_ALICE, ALIAS_TO_GROUPS},
    (DEREF_BASE, SUBTREE): {PEOPLE, ALICE, BOB, ALIAS_TO_ALICE, SECOND_ALIAS_TO_ALICE, ALIAS_TO_GROUPS},
    (DEREF_ALWAYS, BASE): {PEOPLE},
    (DEREF_ALWAYS, LEVEL): {ALICE, BOB, GROUPS},
    (DEREF_ALWAYS, SUBTREE): {PEOPLE, ALICE, BOB, GROUPS},
}

# expected DN sets for base 'cn=alias-to-groups,ou=people,o=lab' (an alias)
EXPECTED_FROM_ALIAS_BASE = {
    (DEREF_NEVER, BASE): {ALIAS_TO_GROUPS},
    (DEREF_NEVER, LEVEL): set(),
    (DEREF_NEVER, SUBTREE): {ALIAS_TO_GROUPS},
    (DEREF_SEARCH, BASE): {ALIAS_TO_GROUPS},
    (DEREF_SEARCH, LEVEL): set(),
    (DEREF_SEARCH, SUBTREE): {ALIAS_TO_GROUPS},
    (DEREF_BASE, BASE): {GROUPS},
    (DEREF_BASE, LEVEL): {ADMINS},
    (DEREF_BASE, SUBTREE): {GROUPS, ADMINS},
    (DEREF_ALWAYS, BASE): {GROUPS},
    (DEREF_ALWAYS, LEVEL): {ADMINS},
    (DEREF_ALWAYS, SUBTREE): {GROUPS, ADMINS},
}

# expected DN sets for base 'ou=aliases,o=lab' (dangling and looping aliases
# are skipped while searching, chains and cross-subtree targets are followed)
EXPECTED_FROM_ALIASES = {
    (DEREF_NEVER, BASE): {ALIASES},
    (DEREF_NEVER, LEVEL): {ALIAS_TO_BOB, CHAIN_FIRST, CHAIN_SECOND, DANGLING_ALIAS, LOOP_FIRST, LOOP_SECOND},
    (DEREF_NEVER, SUBTREE): {ALIASES, ALIAS_TO_BOB, CHAIN_FIRST, CHAIN_SECOND, DANGLING_ALIAS, LOOP_FIRST, LOOP_SECOND},
    (DEREF_SEARCH, BASE): {ALIASES},
    (DEREF_SEARCH, LEVEL): {ALICE, BOB},
    (DEREF_SEARCH, SUBTREE): {ALIASES, ALICE, BOB},
    (DEREF_BASE, BASE): {ALIASES},
    (DEREF_BASE, LEVEL): {ALIAS_TO_BOB, CHAIN_FIRST, CHAIN_SECOND, DANGLING_ALIAS, LOOP_FIRST, LOOP_SECOND},
    (DEREF_BASE, SUBTREE): {ALIASES, ALIAS_TO_BOB, CHAIN_FIRST, CHAIN_SECOND, DANGLING_ALIAS, LOOP_FIRST, LOOP_SECOND},
    (DEREF_ALWAYS, BASE): {ALIASES},
    (DEREF_ALWAYS, LEVEL): {ALICE, BOB},
    (DEREF_ALWAYS, SUBTREE): {ALIASES, ALICE, BOB},
}


class Test(unittest.TestCase):
    def setUp(self):
        server = Server('dummy')  # no schema and no real server needed
        self.connection = Connection(server, client_strategy=MOCK_SYNC)
        self.connection.open()
        self.connection.bind()
        add = self.connection.strategy.add_entry
        add(LAB, {'objectClass': ['top', 'organization'], 'o': 'lab'})
        add(PEOPLE, {'objectClass': ['top', 'organizationalUnit'], 'ou': 'people'})
        add(ALICE, {'objectClass': ['top', 'person'], 'cn': 'alice', 'sn': 'alice_sn'})
        add(BOB, {'objectClass': ['top', 'person'], 'cn': 'bob', 'sn': 'bob_sn'})
        add(ALIAS_TO_ALICE, {'objectClass': ['top', 'alias'], 'aliasedObjectName': ALICE})
        add(SECOND_ALIAS_TO_ALICE, {'objectClass': ['top', 'alias'], 'aliasedObjectName': ALICE})
        add(ALIAS_TO_GROUPS, {'objectClass': ['top', 'alias'], 'aliasedObjectName': GROUPS})
        add(GROUPS, {'objectClass': ['top', 'organizationalUnit'], 'ou': 'groups'})
        add(ADMINS, {'objectClass': ['top', 'groupOfNames'], 'cn': 'admins', 'member': ALICE})
        add(ALIASES, {'objectClass': ['top', 'organizationalUnit'], 'ou': 'aliases'})
        add(ALIAS_TO_BOB, {'objectClass': ['top', 'alias'], 'aliasedObjectName': BOB})
        add(CHAIN_FIRST, {'objectClass': ['top', 'alias'], 'aliasedObjectName': CHAIN_SECOND})
        add(CHAIN_SECOND, {'objectClass': ['top', 'alias'], 'aliasedObjectName': ALICE})
        add(DANGLING_ALIAS, {'objectClass': ['top', 'alias'], 'aliasedObjectName': 'cn=ghost,ou=people,o=lab'})
        add(LOOP_FIRST, {'objectClass': ['top', 'alias'], 'aliasedObjectName': LOOP_SECOND})
        add(LOOP_SECOND, {'objectClass': ['top', 'alias'], 'aliasedObjectName': LOOP_FIRST})

    def tearDown(self):
        self.connection.unbind()
        self.assertFalse(self.connection.bound)

    def _search_dns(self, base, scope, deref, search_filter='(objectClass=*)', attributes=None):
        self.connection.search(base, search_filter, search_scope=scope, dereference_aliases=deref, attributes=attributes or ['cn'])
        self.assertEqual(self.connection.result['description'], 'success')
        return set(entry['dn'] for entry in self.connection.response)

    def _check_matrix(self, base, expected):
        for deref in DEREF_MODES:
            for scope in SCOPES:
                found = self._search_dns(base, scope, deref)
                self.assertEqual(found, expected[(deref, scope)], 'unexpected result for deref=%s scope=%s base=%s' % (deref, scope, base))

    def test_deref_matrix_from_people(self):
        self._check_matrix(PEOPLE, EXPECTED_FROM_PEOPLE)

    def test_deref_matrix_from_alias_base(self):
        self._check_matrix(ALIAS_TO_GROUPS, EXPECTED_FROM_ALIAS_BASE)

    def test_deref_matrix_from_aliases(self):
        self._check_matrix(ALIASES, EXPECTED_FROM_ALIASES)

    def test_dangling_alias_base_returns_alias_problem(self):
        self.connection.search(DANGLING_ALIAS, '(objectClass=*)', search_scope=BASE, dereference_aliases=DEREF_BASE, attributes=['cn'])
        self.assertEqual(self.connection.result['result'], 33)  # aliasProblem

    def test_looping_alias_base_returns_deref_problem(self):
        self.connection.search(LOOP_FIRST, '(objectClass=*)', search_scope=BASE, dereference_aliases=DEREF_ALWAYS, attributes=['cn'])
        self.assertEqual(self.connection.result['result'], 36)  # aliasDereferencingProblem

    def test_dangling_alias_base_not_dereferenced_when_never(self):
        found = self._search_dns(DANGLING_ALIAS, BASE, DEREF_NEVER)
        self.assertEqual(found, {DANGLING_ALIAS})

    def test_filter_matches_target_attributes_not_alias(self):
        # sn=alice_sn lives on the target entry, not on the alias
        found = self._search_dns(PEOPLE, LEVEL, DEREF_SEARCH, search_filter='(sn=alice_sn)')
        self.assertEqual(found, {ALICE})

    def test_filter_on_alias_own_attribute_ignored_after_deref(self):
        # cn=alias-to-alice is the alias own attribute, the target has cn=alice
        found = self._search_dns(PEOPLE, LEVEL, DEREF_SEARCH, search_filter='(cn=alias-to-alice)')
        self.assertEqual(found, set())
        found = self._search_dns(PEOPLE, LEVEL, DEREF_NEVER, search_filter='(cn=alias-to-alice)')
        self.assertEqual(found, {ALIAS_TO_ALICE})

    def test_attributes_come_from_target_entry(self):
        self.connection.search(PEOPLE, '(objectClass=*)', search_scope=LEVEL, dereference_aliases=DEREF_SEARCH, attributes=['sn'])
        self.assertEqual(self.connection.result['description'], 'success')
        attributes_by_dn = dict((entry['dn'], entry['attributes']) for entry in self.connection.response)
        self.assertEqual(attributes_by_dn[ALICE]['sn'], ['alice_sn'])
        self.assertNotIn('aliasedObjectName', attributes_by_dn[ALICE])
        self.assertNotIn('aliasedObjectName', attributes_by_dn[BOB])


if __name__ == '__main__':
    unittest.main()


