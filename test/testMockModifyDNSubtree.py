"""
Offline tests for the subtree-aware ModifyDN implementation of the Mock strategy.

The Mock strategy is an in-memory test double, not a production LDAP service: no real
directory is ever contacted and no rename command is sent over the network. These tests
exercise only the local DIT through the public Connection.modify_dn and Connection.search API.
"""

import unittest

from ldap3 import Server, Connection, MOCK_SYNC, SUBTREE, BASE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES


class TestMockModifyDNSubtree(unittest.TestCase):
    def setUp(self):
        self.server = Server('mock-subtree-server')
        # the same server (and its DIT) is shared by two connections to verify bound identity handling
        self.connection = Connection(self.server, client_strategy=MOCK_SYNC)
        self.connection.bind()
        self.strategy = self.connection.strategy
        self._build_tree()

    def tearDown(self):
        self.connection.unbind()

    def _build_tree(self):
        strategy = self.strategy
        strategy.add_entry('o=lab', {'objectClass': 'organization'})
        strategy.add_entry('ou=dept,o=lab', {'objectClass': 'organizationalUnit', 'description': 'the department'})
        strategy.add_entry('cn=child,ou=dept,o=lab', {'objectClass': 'inetOrgPerson', 'sn': 'child-sn'})
        strategy.add_entry('cn=grand,cn=child,ou=dept,o=lab', {'objectClass': 'inetOrgPerson', 'sn': 'grand-sn'})
        strategy.add_entry('ou=target,o=lab', {'objectClass': 'organizationalUnit'})
        strategy.add_entry('cn=taken,ou=target,o=lab', {'objectClass': 'inetOrgPerson'})

    def _search_dns(self, base, search_filter='(objectClass=*)'):
        self.connection.search(base, search_filter, search_scope=SUBTREE, attributes=ALL_ATTRIBUTES)
        return sorted(entry.entry_dn for entry in self.connection.entries)

    def test_rename_moves_the_whole_two_level_subtree(self):
        result = self.connection.modify_dn('ou=dept,o=lab', 'ou=renamed')
        self.assertEqual(self.connection.result['description'], 'success')
        self.assertEqual(result, True)

        expected = sorted([
            'o=lab',
            'ou=renamed,o=lab',
            'cn=child,ou=renamed,o=lab',
            'cn=grand,cn=child,ou=renamed,o=lab',
            'ou=target,o=lab',
            'cn=taken,ou=target,o=lab',
        ])
        self.assertEqual(self._search_dns('o=lab'), expected)
        # the old subtree must be completely gone
        self.assertNotIn('ou=dept,o=lab', self.strategy.entries)
        self.assertNotIn('cn=child,ou=dept,o=lab', self.strategy.entries)
        self.assertNotIn('cn=grand,cn=child,ou=dept,o=lab', self.strategy.entries)

    def test_move_reparents_every_descendant_under_new_superior(self):
        self.connection.modify_dn('ou=dept,o=lab', 'ou=dept', new_superior='ou=target,o=lab')
        self.assertEqual(self.connection.result['description'], 'success')

        expected = sorted([
            'ou=dept,ou=target,o=lab',
            'cn=child,ou=dept,ou=target,o=lab',
            'cn=grand,cn=child,ou=dept,ou=target,o=lab',
        ])
        self.assertEqual(self._search_dns('ou=dept,ou=target,o=lab'), expected)

    def test_subtree_entries_keep_their_attributes_and_entrydn(self):
        self.connection.modify_dn('ou=dept,o=lab', 'ou=renamed')
        self.connection.search('cn=grand,cn=child,ou=renamed,o=lab', '(objectClass=*)',
                               search_scope=BASE, attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
        entry = self.connection.entries[0]
        self.assertEqual(entry.entry_dn, 'cn=grand,cn=child,ou=renamed,o=lab')
        self.assertEqual(entry.sn.value, 'grand-sn')
        # entryDN is the operational attribute computed for every moved entry
        self.assertEqual(entry.entry_raw_attributes['entryDN'], [b'cn=grand,cn=child,ou=renamed,o=lab'])

    def test_escaped_comma_survives_rename_and_descendant_rebase(self):
        self.strategy.add_entry('cn=doe\\, john,o=lab', {})
        self.strategy.add_entry('cn=kid,cn=doe\\, john,o=lab', {})
        self.connection.modify_dn('cn=doe\\, john,o=lab', 'cn=roe\\, jane')
        self.assertEqual(self.connection.result['description'], 'success')
        self.assertIn('cn=roe\\, jane,o=lab', self.strategy.entries)
        self.assertIn('cn=kid,cn=roe\\, jane,o=lab', self.strategy.entries)
        self.assertNotIn('cn=doe\\, john,o=lab', self.strategy.entries)

    def test_request_dn_is_case_insensitive(self):
        self.connection.modify_dn('OU=DEPT,O=LAB', 'OU=Renamed')
        self.assertEqual(self.connection.result['description'], 'success')
        self.assertIn('cn=child,OU=Renamed,O=LAB', self.strategy.entries)

    def test_target_collision_is_rejected_and_leaves_tree_untouched(self):
        before = sorted(self.strategy.entries.keys())
        # ou=target,o=lab already exists, renaming onto it must fail
        self.connection.modify_dn('ou=dept,o=lab', 'ou=target')
        self.assertEqual(self.connection.result['description'], 'entryAlreadyExists')
        self.assertEqual(sorted(self.strategy.entries.keys()), before)

    def test_collision_on_deep_target_is_rejected(self):
        # a second entry subtree already living under ou=target must not be overwritten by the move
        self.strategy.add_entry('ou=occupied,ou=target,o=lab', {'objectClass': 'organizationalUnit'})
        self.strategy.add_entry('cn=nested,ou=occupied,ou=target,o=lab', {'objectClass': 'inetOrgPerson'})
        before = sorted(self.strategy.entries.keys())

        self.connection.modify_dn('ou=dept,o=lab', 'ou=occupied', new_superior='ou=target,o=lab')
        self.assertEqual(self.connection.result['description'], 'entryAlreadyExists')
        # neither the moved subtree nor the pre-existing target subtree is modified
        self.assertEqual(sorted(self.strategy.entries.keys()), before)
        self.assertIn('cn=nested,ou=occupied,ou=target,o=lab', self.strategy.entries)
        self.assertIn('cn=grand,cn=child,ou=dept,o=lab', self.strategy.entries)

    def test_moving_under_own_descendant_returns_loop_detected(self):
        before = sorted(self.strategy.entries.keys())
        self.connection.modify_dn('ou=dept,o=lab', 'ou=dept',
                                  new_superior='cn=grand,cn=child,ou=dept,o=lab')
        self.assertEqual(self.connection.result['description'], 'loopDetected')
        self.assertEqual(sorted(self.strategy.entries.keys()), before)

    def test_moving_under_itself_returns_loop_detected(self):
        before = sorted(self.strategy.entries.keys())
        self.connection.modify_dn('ou=dept,o=lab', 'ou=dept', new_superior='ou=dept,o=lab')
        self.assertEqual(self.connection.result['description'], 'loopDetected')
        self.assertEqual(sorted(self.strategy.entries.keys()), before)

    def test_missing_new_superior_returns_no_such_object(self):
        before = sorted(self.strategy.entries.keys())
        self.connection.modify_dn('ou=dept,o=lab', 'ou=dept', new_superior='ou=missing,o=lab')
        self.assertEqual(self.connection.result['description'], 'noSuchObject')
        self.assertEqual(sorted(self.strategy.entries.keys()), before)

    def test_renaming_missing_entry_returns_no_such_object(self):
        self.connection.modify_dn('ou=ghost,o=lab', 'ou=phantom')
        self.assertEqual(self.connection.result['description'], 'noSuchObject')

    def test_delete_old_rdn_removes_only_obsolete_values(self):
        self.strategy.add_entry('cn=john,o=lab', {'cn': [b'john', b'extra'], 'sn': b'doe'})
        self.connection.modify_dn('cn=john,o=lab', 'cn=jack', delete_old_dn=True)
        self.assertEqual(self.connection.result['description'], 'success')
        entry = self.strategy.entries['cn=jack,o=lab']
        self.assertEqual(sorted(entry['cn']), [b'extra', b'jack'])  # old RDN value gone, extra value kept
        self.assertEqual(entry['sn'], [b'doe'])

    def test_keep_old_rdn_preserves_the_old_value(self):
        self.strategy.add_entry('cn=john,o=lab', {'cn': [b'john', b'extra']})
        self.connection.modify_dn('cn=john,o=lab', 'cn=jack', delete_old_dn=False)
        self.assertEqual(self.connection.result['description'], 'success')
        entry = self.strategy.entries['cn=jack,o=lab']
        self.assertEqual(sorted(entry['cn']), [b'extra', b'jack', b'john'])

    def test_multi_valued_rdn_updates_each_ava_by_ldap_semantics(self):
        self.strategy.add_entry('cn=john+sn=doe,o=lab', {'cn': [b'john'], 'sn': [b'doe']})
        self.connection.modify_dn('cn=john+sn=doe,o=lab', 'cn=jack+sn=doe', delete_old_dn=True)
        self.assertEqual(self.connection.result['description'], 'success')
        entry = self.strategy.entries['cn=jack+sn=doe,o=lab']
        self.assertEqual(entry['cn'], [b'jack'])       # obsolete cn value removed
        self.assertEqual(entry['sn'], [b'doe'])        # value shared by both RDNs is kept

    def test_no_op_rename_leaves_the_tree_untouched(self):
        before = sorted(self.strategy.entries.keys())
        self.connection.modify_dn('ou=dept,o=lab', 'ou=dept')
        self.assertEqual(self.connection.result['description'], 'success')
        self.assertEqual(sorted(self.strategy.entries.keys()), before)

    def test_invalid_rdn_syntax_is_rejected_without_touching_the_tree(self):
        from ldap3.core.exceptions import LDAPInvalidDnError
        before = sorted(self.strategy.entries.keys())
        # malformed RDNs are rejected at the client boundary, the in-memory DIT is never touched
        with self.assertRaises(LDAPInvalidDnError):
            self.connection.modify_dn('ou=dept,o=lab', 'not-a-valid-rdn')
        self.assertEqual(sorted(self.strategy.entries.keys()), before)

    def test_empty_rdn_is_rejected_by_the_strategy(self):
        from ldap3.operation.modifyDn import modify_dn_operation
        from ldap3.strategy.mockSync import MockSyncStrategy
        before = sorted(self.strategy.entries.keys())
        # bypass the client side safe_dn validation to exercise the strategy guard directly
        request = modify_dn_operation('ou=dept,o=lab', '', True)
        result = self.strategy.mock_modify_dn(request, None)
        self.assertEqual(result['resultCode'], 34)  # invalidDNSyntax
        self.assertEqual(sorted(self.strategy.entries.keys()), before)

    def test_injected_commit_failure_rolls_back_the_whole_subtree(self):
        before = sorted(self.strategy.entries.keys())
        original_entry = self.strategy.entries['ou=dept,o=lab']
        calls = {'count': 0}
        real_store = self.strategy._store_mock_entry

        def failing_store(dn, entry):
            calls['count'] += 1
            if calls['count'] == 2:  # fail while writing the second entry of the moved subtree
                raise RuntimeError('injected storage failure')
            return real_store(dn, entry)

        self.strategy._store_mock_entry = failing_store
        try:
            self.connection.modify_dn('ou=dept,o=lab', 'ou=renamed')
        finally:
            self.strategy._store_mock_entry = real_store

        self.assertEqual(self.connection.result['description'], 'operationsError')
        # exact DIT state, including key casing, is restored: no half-moved entry survives
        self.assertEqual(sorted(self.strategy.entries.keys()), before)
        self.assertIs(self.strategy.entries['ou=dept,o=lab'], original_entry)
        self.assertNotIn('ou=renamed,o=lab', self.strategy.entries)
        self.assertIn('cn=grand,cn=child,ou=dept,o=lab', self.strategy.entries)

    def test_bound_identity_follows_the_moved_entry(self):
        self.strategy.add_entry('cn=admin,ou=dept,o=lab', {'userPassword': 'secret'})
        identity_connection = Connection(self.server, user='cn=admin,ou=dept,o=lab',
                                         password='secret', client_strategy=MOCK_SYNC)
        identity_connection.bind()
        self.assertEqual(identity_connection.strategy.bound, 'cn=admin,ou=dept,o=lab')

        identity_connection.modify_dn('ou=dept,o=lab', 'ou=moved')
        self.assertEqual(identity_connection.result['description'], 'success')
        # the mock binds by DN, so the session identity is rewritten to the new location on success
        self.assertEqual(identity_connection.strategy.bound, 'cn=admin,ou=moved,o=lab')
        identity_connection.unbind()

    def test_bound_identity_outside_the_moved_subtree_is_untouched(self):
        self.strategy.add_entry('cn=boss,o=lab', {'userPassword': 'secret'})
        identity_connection = Connection(self.server, user='cn=boss,o=lab',
                                         password='secret', client_strategy=MOCK_SYNC)
        identity_connection.bind()
        identity_connection.modify_dn('ou=dept,o=lab', 'ou=moved')
        self.assertEqual(identity_connection.strategy.bound, 'cn=boss,o=lab')
        identity_connection.unbind()

    def test_failed_move_keeps_the_bound_identity(self):
        self.strategy.add_entry('cn=admin,ou=dept,o=lab', {'userPassword': 'secret'})
        identity_connection = Connection(self.server, user='cn=admin,ou=dept,o=lab',
                                         password='secret', client_strategy=MOCK_SYNC)
        identity_connection.bind()
        # collision makes the operation fail before any identity or DIT change is committed
        identity_connection.modify_dn('ou=dept,o=lab', 'ou=target')
        self.assertEqual(identity_connection.result['description'], 'entryAlreadyExists')
        self.assertEqual(identity_connection.strategy.bound, 'cn=admin,ou=dept,o=lab')
        identity_connection.unbind()


if __name__ == '__main__':
    unittest.main()
