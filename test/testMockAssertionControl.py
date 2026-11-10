"""
"""

# Created on 2026.11.10
#
# Author: Giovanni Cannata
#
# Copyright 2016 - 2025 Giovanni Cannata
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
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.


import unittest

from threading import Thread, Barrier

from ldap3 import Server, Connection, MOCK_SYNC, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE
from ldap3.protocol.controls import build_control
from ldap3.protocol.rfc2696 import paged_search_control
from ldap3.protocol.rfc4527 import pre_read_control, post_read_control
from ldap3.protocol.rfc4528 import assertion_control

testcase_id = ''


class Test(unittest.TestCase):
    def setUp(self):
        global testcase_id
        testcase_id = self.id()
        self.server = Server('dummy')  # no schema, all data is kept in the mock DIT
        self.connection = Connection(self.server, user='cn=user1,ou=test,o=lab', password='test1111', client_strategy=MOCK_SYNC)
        self.connection.strategy.add_entry('cn=user1,ou=test,o=lab', {'userPassword': 'test1111', 'sn': 'user1_sn', 'revision': 7, 'title': ['title1', 'title2']})
        self.connection.bind()

    def tearDown(self):
        self.connection.unbind()
        self.assertFalse(self.connection.bound)

    def test_assertion_true_allows_modify_and_returns_pre_post_read(self):
        dn = 'cn=user1,ou=test,o=lab'
        result = self.connection.modify(dn, {'revision': [(MODIFY_REPLACE, ['8'])]},
                                        controls=[assertion_control('(revision=7)'),
                                                  pre_read_control(['revision', 'sn']),
                                                  post_read_control(['revision'])])
        self.assertTrue(result)
        self.assertEqual(self.connection.result['result'], 0)
        pre_read = self.connection.result['controls']['1.3.6.1.1.13.1']['value']['result']
        post_read = self.connection.result['controls']['1.3.6.1.1.13.2']['value']['result']
        self.assertEqual(pre_read, {'revision': ['7'], 'sn': ['user1_sn']})  # only requested attributes, values before the update
        self.assertEqual(post_read, {'revision': ['8']})  # only requested attributes, values after the same update
        self.assertEqual(self.connection.strategy.entries[dn]['revision'], [b'8'])

    def test_assertion_false_fails_modify_and_returns_no_read_controls(self):
        dn = 'cn=user1,ou=test,o=lab'
        result = self.connection.modify(dn, {'revision': [(MODIFY_REPLACE, ['8'])]},
                                        controls=[assertion_control('(revision=6)'),
                                                  pre_read_control(['revision']),
                                                  post_read_control(['revision'])])
        self.assertFalse(result)
        self.assertEqual(self.connection.result['result'], 122)  # assertionFailed
        self.assertEqual(self.connection.result['description'], 'assertionFailed')
        self.assertNotIn('controls', self.connection.result)  # a failed request must not read back a success illusion
        self.assertEqual(self.connection.strategy.entries[dn]['revision'], [b'7'])  # entry unchanged

    def test_assertion_evaluated_on_target_entry_only(self):
        dn = 'cn=user1,ou=test,o=lab'
        self.connection.strategy.add_entry('cn=user2,ou=test,o=lab', {'userPassword': 'test2222', 'sn': 'user2_sn', 'revision': 9})
        result = self.connection.modify(dn, {'revision': [(MODIFY_REPLACE, ['8'])]},
                                        controls=[assertion_control('(revision=9)')])
        self.assertFalse(result)  # revision is 9 on user2 but the assertion is checked against the modified entry only
        self.assertEqual(self.connection.result['result'], 122)
        self.assertEqual(self.connection.strategy.entries[dn]['revision'], [b'7'])

    def test_assertion_on_missing_entry_returns_no_such_object(self):
        result = self.connection.modify('cn=ghost,ou=test,o=lab', {'revision': [(MODIFY_REPLACE, ['8'])]},
                                        controls=[assertion_control('(revision=7)')])
        self.assertFalse(result)
        self.assertEqual(self.connection.result['result'], 32)  # noSuchObject

    def test_failing_change_rolls_back_whole_modify(self):
        dn = 'cn=user1,ou=test,o=lab'
        result = self.connection.modify(dn, {'title': [(MODIFY_ADD, ['title3'])],  # applied first, must be rolled back
                                             'sn': [(MODIFY_DELETE, ['not_a_value'])]},  # fails, value not present
                                        controls=[assertion_control('(revision=7)'),
                                                  post_read_control(['title', 'sn'])])
        self.assertFalse(result)
        self.assertNotEqual(self.connection.result['result'], 0)
        self.assertNotIn('controls', self.connection.result)
        entry = self.connection.strategy.entries[dn]
        self.assertEqual(entry['title'], [b'title1', b'title2'])  # no partial modification left behind
        self.assertEqual(entry['sn'], [b'user1_sn'])

    def test_duplicate_control_rejected(self):
        dn = 'cn=user1,ou=test,o=lab'
        result = self.connection.modify(dn, {'revision': [(MODIFY_REPLACE, ['8'])]},
                                        controls=[assertion_control('(revision=7)'),
                                                  assertion_control('(revision=7)')])
        self.assertFalse(result)
        self.assertEqual(self.connection.result['result'], 2)  # protocolError
        self.assertEqual(self.connection.strategy.entries[dn]['revision'], [b'7'])

    def test_malformed_assertion_value_rejected(self):
        dn = 'cn=user1,ou=test,o=lab'
        bad_assertion = build_control('1.3.6.1.1.12', True, b'not-a-valid-filter', encode_control_value=False)
        result = self.connection.modify(dn, {'revision': [(MODIFY_REPLACE, ['8'])]},
                                        controls=[bad_assertion])
        self.assertFalse(result)
        self.assertEqual(self.connection.result['result'], 2)  # protocolError
        self.assertEqual(self.connection.strategy.entries[dn]['revision'], [b'7'])

    def test_unsupported_critical_control_combination_rejected(self):
        dn = 'cn=user1,ou=test,o=lab'
        result = self.connection.modify(dn, {'revision': [(MODIFY_REPLACE, ['8'])]},
                                        controls=[assertion_control('(revision=7)'),
                                                  paged_search_control(True, 10, '')])  # simple paged search is not a modify control
        self.assertFalse(result)
        self.assertEqual(self.connection.result['result'], 12)  # unavailableCriticalExtension
        self.assertEqual(self.connection.strategy.entries[dn]['revision'], [b'7'])

    def test_unknown_noncritical_control_ignored(self):
        dn = 'cn=user1,ou=test,o=lab'
        result = self.connection.modify(dn, {'revision': [(MODIFY_REPLACE, ['8'])]},
                                        controls=[build_control('1.2.3.4', False, None)])
        self.assertTrue(result)
        self.assertEqual(self.connection.strategy.entries[dn]['revision'], [b'8'])

    def test_plain_modify_without_controls_is_unchanged(self):
        dn = 'cn=user1,ou=test,o=lab'
        result = self.connection.modify(dn, {'revision': [(MODIFY_REPLACE, ['8'])]})
        self.assertTrue(result)
        self.assertEqual(self.connection.result['result'], 0)
        self.assertNotIn('controls', self.connection.result)
        self.assertEqual(self.connection.strategy.entries[dn]['revision'], [b'8'])

    def test_competing_modifies_on_same_version_at_most_one_succeeds(self):
        dn = 'cn=user1,ou=test,o=lab'
        barrier = Barrier(3)  # the two workers and the main thread start together
        outcomes = [None, None]

        def competing_modify(index):
            connection = Connection(self.server, user='cn=user1,ou=test,o=lab', password='test1111', client_strategy=MOCK_SYNC)
            connection.bind()
            barrier.wait()
            connection.modify(dn, {'revision': [(MODIFY_REPLACE, ['8'])]},
                              controls=[assertion_control('(revision=7)'),
                                        pre_read_control(['revision']),
                                        post_read_control(['revision'])])
            outcomes[index] = connection.result
            connection.unbind()

        threads = [Thread(target=competing_modify, args=(index,)) for index in (0, 1)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        successes = [result for result in outcomes if result['result'] == 0]
        failures = [result for result in outcomes if result['result'] != 0]
        self.assertEqual(len(successes), 1)  # at most one (exactly one) competing modify succeeds
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]['result'], 122)  # assertionFailed
        self.assertNotIn('controls', failures[0])  # the failed request does not read back a success illusion
        winner_pre_read = successes[0]['controls']['1.3.6.1.1.13.1']['value']['result']
        winner_post_read = successes[0]['controls']['1.3.6.1.1.13.2']['value']['result']
        self.assertEqual(winner_pre_read, {'revision': ['7']})
        self.assertEqual(winner_post_read, {'revision': ['8']})
        self.assertEqual(self.connection.strategy.entries[dn]['revision'], [b'8'])


if __name__ == '__main__':
    unittest.main()
