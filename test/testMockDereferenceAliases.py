"""
"""

# Created on 2026.09.25
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING.LESSER and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.


import unittest

from ldap3 import Server, Connection, MOCK_SYNC, BASE, LEVEL, SUBTREE, DEREF_NEVER, DEREF_SEARCH, DEREF_BASE, DEREF_ALWAYS

# fixture DIT, no real server is involved:
#
# o=lab                                          organization
# |- ou=people,o=lab                             organizationalUnit
# |  |- cn=alice,ou=people,o=lab                 person
# |  |- cn=alias1,ou=people,o=lab                alias -> cn=bob,ou=contacts,o=lab
# |  '- cn=alias2,ou=people,o=lab                alias -> cn=bob,ou=contacts,o=lab (same target as alias1)
# |- ou=contacts,o=lab                           organizationalUnit
# |  '- cn=bob,ou=contacts,o=lab                 person
# '- cn=base-alias,o=lab                         alias -> ou=people,o=lab
#
# o=broken                                       organization
# |- ou=dangling,o=broken                        organizationalUnit
# |  '- cn=dangling,ou=dangling,o=broken         alias -> cn=ghost,o=nowhere (non-existent target)
# '- ou=loops,o=broken                           organizationalUnit
#    |- cn=loop-a,ou=loops,o=broken              alias -> cn=loop-b,ou=loops,o=broken
#    '- cn=loop-b,ou=loops,o=broken              alias -> cn=loop-a,ou=loops,o=broken (loop)

ALICE = 'cn=alice,ou=people,o=lab'
ALIAS1 = 'cn=alias1,ou=people,o=lab'
ALIAS2 = 'cn=alias2,ou=people,o=lab'
BOB = 'cn=bob,ou=contacts,o=lab'
PEOPLE = 'ou=people,o=lab'
CONTACTS = 'ou=contacts,o=lab'
BASE_ALIAS = 'cn=base-alias,o=lab'
LAB = 'o=lab'

# expected DN sets for every (base, scope, dereference_aliases) combination
EXPECTED = [
    # base o=lab, BASE scope: the base object is not an alias, dereferencing never kicks in
    (LAB, BASE, DEREF_NEVER, {LAB}),
    (LAB, BASE, DEREF_SEARCH, {LAB}),
    (LAB, BASE, DEREF_BASE, {LAB}),
    (LAB, BASE, DEREF_ALWAYS, {LAB}),
    # base o=lab, LEVEL scope: cn=base-alias is dereferenced only when in-search dereferencing is
    # enabled; its target ou=people,o=lab is already a child of o=lab so it must not be duplicated
    (LAB, LEVEL, DEREF_NEVER, {PEOPLE, CONTACTS, BASE_ALIAS}),
    (LAB, LEVEL, DEREF_SEARCH, {PEOPLE, CONTACTS}),
    (LAB, LEVEL, DEREF_BASE, {PEOPLE, CONTACTS, BASE_ALIAS}),
    (LAB, LEVEL, DEREF_ALWAYS, {PEOPLE, CONTACTS}),
    # base o=lab, SUBTREE scope: the three aliases are replaced by their targets, each target is returned once
    (LAB, SUBTREE, DEREF_NEVER, {LAB, PEOPLE, ALICE, ALIAS1, ALIAS2, CONTACTS, BOB, BASE_ALIAS}),
    (LAB, SUBTREE, DEREF_SEARCH, {LAB, PEOPLE, ALICE, CONTACTS, BOB}),
    (LAB, SUBTREE, DEREF_BASE, {LAB, PEOPLE, ALICE, ALIAS1, ALIAS2, CONTACTS, BOB, BASE_ALIAS}),
    (LAB, SUBTREE, DEREF_ALWAYS, {LAB, PEOPLE, ALICE, CONTACTS, BOB}),
    # base cn=base-alias,o=lab, BASE scope: the alias itself is returned unless finding-base dereferencing is enabled
    (BASE_ALIAS, BASE, DEREF_NEVER, {BASE_ALIAS}),
    (BASE_ALIAS, BASE, DEREF_SEARCH, {BASE_ALIAS}),
    (BASE_ALIAS, BASE, DEREF_BASE, {PEOPLE}),
    (BASE_ALIAS, BASE, DEREF_ALWAYS, {PEOPLE}),
    # base cn=base-alias,o=lab, LEVEL scope: an alias has no children, only finding-base dereferencing
    # exposes the children of the target; aliases below the target are expanded only with derefAlways
    (BASE_ALIAS, LEVEL, DEREF_NEVER, set()),
    (BASE_ALIAS, LEVEL, DEREF_SEARCH, set()),
    (BASE_ALIAS, LEVEL, DEREF_BASE, {ALICE, ALIAS1, ALIAS2}),
    (BASE_ALIAS, LEVEL, DEREF_ALWAYS, {ALICE, BOB}),
    # base cn=base-alias,o=lab, SUBTREE scope: with FINDING_BASE only, aliases in the subtree are not expanded
    (BASE_ALIAS, SUBTREE, DEREF_NEVER, {BASE_ALIAS}),
    (BASE_ALIAS, SUBTREE, DEREF_SEARCH, {BASE_ALIAS}),
    (BASE_ALIAS, SUBTREE, DEREF_BASE, {PEOPLE, ALICE, ALIAS1, ALIAS2}),
    (BASE_ALIAS, SUBTREE, DEREF_ALWAYS, {PEOPLE, ALICE, BOB}),
    # base ou=people,o=lab, BASE scope
    (PEOPLE, BASE, DEREF_NEVER, {PEOPLE}),
    (PEOPLE, BASE, DEREF_SEARCH, {PEOPLE}),
    (PEOPLE, BASE, DEREF_BASE, {PEOPLE}),
    (PEOPLE, BASE, DEREF_ALWAYS, {PEOPLE}),
    # base ou=people,o=lab, LEVEL scope: alias1 and alias2 point to the same cross-subtree target,
    # cn=bob,ou=contacts,o=lab must be returned exactly once
    (PEOPLE, LEVEL, DEREF_NEVER, {ALICE, ALIAS1, ALIAS2}),
    (PEOPLE, LEVEL, DEREF_SEARCH, {ALICE, BOB}),
    (PEOPLE, LEVEL, DEREF_BASE, {ALICE, ALIAS1, ALIAS2}),
    (PEOPLE, LEVEL, DEREF_ALWAYS, {ALICE, BOB}),
    # base ou=people,o=lab, SUBTREE scope
    (PEOPLE, SUBTREE, DEREF_NEVER, {PEOPLE, ALICE, ALIAS1, ALIAS2}),
    (PEOPLE, SUBTREE, DEREF_SEARCH, {PEOPLE, ALICE, BOB}),
    (PEOPLE, SUBTREE, DEREF_BASE, {PEOPLE, ALICE, ALIAS1, ALIAS2}),
    (PEOPLE, SUBTREE, DEREF_ALWAYS, {PEOPLE, ALICE, BOB}),
]


class Test(unittest.TestCase):
    def setUp(self):
        server = Server('dummy')  # offline mock server, no schema needed
        self.connection = Connection(server, client_strategy=MOCK_SYNC)
        add_entry = self.connection.strategy.add_entry
        add_entry(LAB, {'objectClass': ['top', 'organization']})
        add_entry(PEOPLE, {'objectClass': ['top', 'organizationalUnit']})
        add_entry(ALICE, {'objectClass': ['top', 'person'], 'sn': 'alice_sn'})
        add_entry(ALIAS1, {'objectClass': ['top', 'alias'], 'aliasedObjectName': BOB})
        add_entry(ALIAS2, {'objectClass': ['top', 'alias'], 'aliasedObjectName': BOB})
        add_entry(CONTACTS, {'objectClass': ['top', 'organizationalUnit']})
        add_entry(BOB, {'objectClass': ['top', 'person'], 'sn': 'bob_sn'})
        add_entry(BASE_ALIAS, {'objectClass': ['top', 'alias'], 'aliasedObjectName': PEOPLE})
        add_entry('o=broken', {'objectClass': ['top', 'organization']})
        add_entry('ou=dangling,o=broken', {'objectClass': ['top', 'organizationalUnit']})
        add_entry('cn=dangling,ou=dangling,o=broken', {'objectClass': ['top', 'alias'], 'aliasedObjectName': 'cn=ghost,o=nowhere'})
        add_entry('ou=loops,o=broken', {'objectClass': ['top', 'organizationalUnit']})
        add_entry('cn=loop-a,ou=loops,o=broken', {'objectClass': ['top', 'alias'], 'aliasedObjectName': 'cn=loop-b,ou=loops,o=broken'})
        add_entry('cn=loop-b,ou=loops,o=broken', {'objectClass': ['top', 'alias'], 'aliasedObjectName': 'cn=loop-a,ou=loops,o=broken'})
        self.connection.bind()

    def tearDown(self):
        self.connection.unbind()
        self.assertFalse(self.connection.bound)

    def search_dns(self, base, scope, deref, search_filter='(objectClass=*)', attributes=None):
        self.connection.search(base, search_filter, search_scope=scope, dereference_aliases=deref, attributes=attributes or ['cn'])
        result = self.connection.result
        self.assertEqual('success', result['description'], 'search failed for base=%s scope=%s deref=%s: %s' % (base, scope, deref, result))
        return set(entry['dn'] for entry in self.connection.response)

    def test_search_dereference_aliases_matrix(self):
        for base, scope, deref, expected in EXPECTED:
            found = self.search_dns(base, scope, deref)
            self.assertEqual(expected, found, 'unexpected DN set for base=%s scope=%s deref=%s' % (base, scope, deref))

    def test_two_aliases_to_same_target_return_entry_once(self):
        self.connection.search(PEOPLE, '(objectClass=*)', search_scope=SUBTREE, dereference_aliases=DEREF_ALWAYS, attributes=['cn'])
        self.assertEqual('success', self.connection.result['description'])
        dns = [entry['dn'] for entry in self.connection.response]
        self.assertEqual(len(dns), len(set(dns)))
        self.assertEqual(1, dns.count(BOB))

    def test_filter_applies_to_dereferenced_target(self):
        # (cn=bob) matches the target entry only, aliases carry their own cn values
        found = self.search_dns(PEOPLE, SUBTREE, DEREF_SEARCH, search_filter='(cn=bob)')
        self.assertEqual({BOB}, found)
        found = self.search_dns(PEOPLE, SUBTREE, DEREF_NEVER, search_filter='(cn=bob)')
        self.assertEqual(set(), found)

    def test_filter_on_alias_own_attributes(self):
        # (cn=alias1) matches the alias entry only when it is not dereferenced
        found = self.search_dns(PEOPLE, SUBTREE, DEREF_NEVER, search_filter='(cn=alias1)')
        self.assertEqual({ALIAS1}, found)
        found = self.search_dns(PEOPLE, SUBTREE, DEREF_SEARCH, search_filter='(cn=alias1)')
        self.assertEqual(set(), found)

    def test_attributes_come_from_dereferenced_target(self):
        self.connection.search(PEOPLE, '(cn=bob)', search_scope=SUBTREE, dereference_aliases=DEREF_SEARCH, attributes=['cn', 'sn'])
        self.assertEqual('success', self.connection.result['description'])
        self.assertEqual(1, len(self.connection.response))
        entry = self.connection.response[0]
        self.assertEqual(BOB, entry['dn'])
        self.assertEqual(['bob'], entry['attributes']['cn'])
        self.assertEqual(['bob_sn'], entry['attributes']['sn'])
        self.assertNotIn('aliasedObjectName', entry['attributes'])

    def test_dangling_alias_as_base_object(self):
        self.connection.search('cn=dangling,ou=dangling,o=broken', '(objectClass=*)', search_scope=BASE, dereference_aliases=DEREF_BASE, attributes=['cn'])
        self.assertEqual('aliasProblem', self.connection.result['description'])

    def test_dangling_alias_as_base_object_never_deref(self):
        found = self.search_dns('cn=dangling,ou=dangling,o=broken', BASE, DEREF_NEVER)
        self.assertEqual({'cn=dangling,ou=dangling,o=broken'}, found)

    def test_dangling_alias_found_while_searching(self):
        self.connection.search('ou=dangling,o=broken', '(objectClass=*)', search_scope=SUBTREE, dereference_aliases=DEREF_SEARCH, attributes=['cn'])
        self.assertEqual('aliasProblem', self.connection.result['description'])

    def test_dangling_alias_not_dereferenced(self):
        found = self.search_dns('ou=dangling,o=broken', SUBTREE, DEREF_NEVER)
        self.assertEqual({'ou=dangling,o=broken', 'cn=dangling,ou=dangling,o=broken'}, found)

    def test_loop_alias_as_base_object(self):
        self.connection.search('cn=loop-a,ou=loops,o=broken', '(objectClass=*)', search_scope=BASE, dereference_aliases=DEREF_ALWAYS, attributes=['cn'])
        self.assertEqual('loopDetected', self.connection.result['description'])

    def test_loop_alias_found_while_searching(self):
        self.connection.search('ou=loops,o=broken', '(objectClass=*)', search_scope=SUBTREE, dereference_aliases=DEREF_ALWAYS, attributes=['cn'])
        self.assertEqual('loopDetected', self.connection.result['description'])

    def test_loop_alias_not_dereferenced(self):
        found = self.search_dns('ou=loops,o=broken', SUBTREE, DEREF_NEVER)
        self.assertEqual({'ou=loops,o=broken', 'cn=loop-a,ou=loops,o=broken', 'cn=loop-b,ou=loops,o=broken'}, found)


if __name__ == '__main__':
    unittest.main()
