"""
"""

# Created on 2026.11.10
#
# Author: Giovanni Cannata
#
# Copyright 2026 Giovanni Cannata
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
# You should have received a copy of the GNU General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

# Regression tests for the authentication state of MOCK_SYNC and MOCK_ASYNC
# connections. The focus is on what identity the connection actually works as
# after a successful login is followed by a failing bind/rebind.
#
# Three distinct layers are checked against the LDAP bind state contract
# (RFC 4511 section 4.2.1, RFC 4513 section 5.1, RFC 4532):
#   1. the protocol result        -> connection.result / return value of bind()
#   2. the connection bound flag  -> connection.bound (True only while a bind
#                                    succeeded, False after any failed bind)
#   3. the real authenticated identity -> connection.strategy.bound (the DN the
#                                    mock DSA works as, None when anonymous) and
#                                    the WhoAmI extended operation [RFC4532]
#
# A successful *anonymous* bind must NOT be confused with a successful *user*
# authentication: connection.bound is True in both cases, but only the
# identity layer (strategy.bound / WhoAmI) tells them apart.
#
# MINIMAL EXAMPLE of the application mistake these tests guard against:
#
#     # WRONG: treats the bound flag as proof of login
#     conn = Connection(server, user, password, client_strategy=MOCK_SYNC, lazy=True)
#     conn.bind()
#     if conn.bound:            # True even with a WRONG password (bind is deferred)
#         grant_access()
#
#     # WRONG: treats an anonymous bind as user authentication
#     conn = Connection(server, authentication=ANONYMOUS, client_strategy=MOCK_SYNC)
#     if conn.bind():           # True: anonymous bind succeeded at protocol level
#         grant_access()        # but NO user identity was ever verified
#
#     # CORRECT: force the operation to be really sent, then check the identity
#     conn = Connection(server, user, password, client_strategy=MOCK_SYNC)
#     if conn.bind() and conn.extend.standard.who_am_i():  # non-empty authzId
#         grant_access()        # only now a real user identity is established
#
# After a failed bind/rebind the connection must NOT silently keep working as
# the previously authenticated user: connection.bound is False and
# connection.strategy.bound is None (anonymous state), mirroring what a real
# LDAP server does.

import json
import unittest

from ldap3 import Server, Connection, MOCK_SYNC, MOCK_ASYNC, ANONYMOUS
from ldap3.core.exceptions import LDAPPasswordIsMandatoryError, LDAPInvalidCredentialsResult
from ldap3.protocol.rfc4512 import SchemaInfo, DsaInfo
from ldap3.protocol.schemas.edir914 import edir_9_1_4_dsa_info, edir_9_1_4_schema
from test.config import random_id

testcase_id = ''

USER_DN = 'cn=user1,ou=test,o=lab'
USER_PASSWORD = 'test1111'
OTHER_USER_DN = 'cn=user2,ou=test,o=lab'
OTHER_USER_PASSWORD = 'test2222'
GHOST_DN = 'cn=ghost,ou=test,o=lab'
WHOAMI_OID = '1.3.6.1.4.1.4203.1.11.3'  # RFC 4532


def mock_server_with_whoami():
    # the edir 9.1.4 offline definition lacks the WhoAmI extension, so it is added
    schema = SchemaInfo.from_json(edir_9_1_4_schema)
    dsa_definition = json.loads(edir_9_1_4_dsa_info)
    dsa_definition['raw']['supportedExtension'].append(WHOAMI_OID)
    info = DsaInfo.from_json(json.dumps(dsa_definition), schema)
    return Server.from_definition('MockBindIdentityServer', info, schema)


def record_sends(connection):
    """Wraps connection.send so that the message types actually sent are recorded.

    Returns the list that accumulates the message types, in sending order.
    """
    sent_messages = []
    original_send = connection.send

    def recording_send(message_type, request, controls=None):
        sent_messages.append(message_type)
        return original_send(message_type, request, controls)

    connection.send = recording_send
    return sent_messages


class BindIdentityMixin(object):
    """Shared authentication-state regression tests, run for MOCK_SYNC and MOCK_ASYNC."""

    # each subclass defines: client_strategy (MOCK_SYNC or MOCK_ASYNC)

    def setUp(self):
        global testcase_id
        testcase_id = random_id()
        self.server = mock_server_with_whoami()
        self.connection = Connection(self.server, user=USER_DN, password=USER_PASSWORD, client_strategy=self.client_strategy)
        self.connection.strategy.add_entry(USER_DN, {'userPassword': USER_PASSWORD, 'sn': 'user1_sn'})
        self.connection.strategy.add_entry(OTHER_USER_DN, {'userPassword': OTHER_USER_PASSWORD, 'sn': 'user2_sn'})

    def tearDown(self):
        self.connection.unbind()
        self.assertFalse(self.connection.bound)
        self.assertIsNone(self.connection.strategy.bound)

    def assert_anonymous_state(self, connection):
        # after a failed bind the connection must not keep the previous identity
        self.assertFalse(connection.bound)
        self.assertIsNone(connection.strategy.bound)
        self.assertFalse(connection.extend.standard.who_am_i())

    def test_successful_bind_sets_real_identity(self):
        self.assertTrue(self.connection.bind())
        self.assertTrue(self.connection.bound)
        self.assertEqual(self.connection.strategy.bound, USER_DN)
        self.assertEqual(self.connection.extend.standard.who_am_i(), USER_DN)

    def test_failed_rebind_drops_previous_identity(self):
        self.assertTrue(self.connection.bind())
        self.assertEqual(self.connection.strategy.bound, USER_DN)
        # wrong password: protocol fails, connection unbound, identity reset to anonymous
        self.assertFalse(self.connection.rebind(user=USER_DN, password='wrong-password'))
        self.assertEqual(self.connection.last_error, 'invalidCredentials')
        self.assert_anonymous_state(self.connection)
        # nonexistent user: same contract
        self.assertFalse(self.connection.rebind(user=GHOST_DN, password='any'))
        self.assertEqual(self.connection.last_error, 'invalidCredentials')
        self.assert_anonymous_state(self.connection)

    def test_failed_rebind_with_raise_exceptions_still_resets_identity(self):
        connection = Connection(self.server, user=USER_DN, password=USER_PASSWORD, client_strategy=self.client_strategy, raise_exceptions=True)
        self.assertTrue(connection.bind())
        self.assertEqual(connection.strategy.bound, USER_DN)
        with self.assertRaises(LDAPInvalidCredentialsResult):
            connection.rebind(user=USER_DN, password='wrong-password')
        # with raise_exceptions the exception is the failure signal: connection.bound
        # is not updated on the raising path (same behaviour as the real strategies),
        # while the real identity is correctly dropped to anonymous
        self.assertTrue(connection.bound)
        self.assertIsNone(connection.strategy.bound)
        connection.unbind()

    def test_successful_rebind_changes_identity(self):
        self.assertTrue(self.connection.bind())
        self.assertTrue(self.connection.rebind(user=OTHER_USER_DN, password=OTHER_USER_PASSWORD))
        self.assertTrue(self.connection.bound)
        self.assertEqual(self.connection.strategy.bound, OTHER_USER_DN)
        self.assertEqual(self.connection.extend.standard.who_am_i(), OTHER_USER_DN)

    def test_empty_password_is_rejected_before_any_request(self):
        connection = Connection(self.server, user=USER_DN, password='', client_strategy=self.client_strategy)
        connection.strategy.add_entry(USER_DN, {'userPassword': USER_PASSWORD, 'sn': 'user1_sn'})
        sent_messages = record_sends(connection)
        # RFC 4513 (5.1.2): a non-empty DN with an empty password is an
        # unauthenticated bind, ldap3 refuses to even send it
        with self.assertRaises(LDAPPasswordIsMandatoryError):
            connection.bind()
        self.assertNotIn('bindRequest', sent_messages)
        self.assertFalse(connection.bound)
        self.assertIsNone(connection.strategy.bound)
        connection.unbind()

    def test_anonymous_bind_success_is_not_user_authentication(self):
        connection = Connection(self.server, authentication=ANONYMOUS, client_strategy=self.client_strategy)
        self.assertTrue(connection.bind())  # protocol success...
        self.assertTrue(connection.bound)   # ...and bound flag set...
        self.assertEqual(connection.strategy.bound, '<anonymous>')  # ...but no user identity
        self.assertFalse(connection.extend.standard.who_am_i())  # empty authzId as per RFC 4532
        connection.unbind()

    def test_nonexistent_user_bind_fails_anonymously(self):
        connection = Connection(self.server, user=GHOST_DN, password='any', client_strategy=self.client_strategy)
        self.assertFalse(connection.bind())
        self.assertEqual(connection.last_error, 'invalidCredentials')
        self.assert_anonymous_state(connection)
        connection.unbind()

    def test_lazy_connection_defers_bind_until_first_operation(self):
        connection = Connection(self.server, user=USER_DN, password=USER_PASSWORD, client_strategy=self.client_strategy, lazy=True)
        connection.strategy.add_entry(USER_DN, {'userPassword': USER_PASSWORD, 'sn': 'user1_sn'})
        sent_messages = record_sends(connection)
        self.assertTrue(connection.bind())  # deferred: nothing is sent yet
        self.assertTrue(connection.bound)   # bound flag is optimistic here, no login happened yet
        self.assertTrue(connection._deferred_bind)
        self.assertEqual(sent_messages, [])
        # the first real operation fires the deferred open+bind, in order
        self.assertTrue(connection.search('o=lab', '(sn=*)'))
        self.assertEqual(sent_messages, ['bindRequest', 'searchRequest'])
        self.assertTrue(connection.bound)
        self.assertEqual(connection.strategy.bound, USER_DN)
        connection.unbind()

    def test_lazy_connection_with_wrong_password_binds_late_and_fails(self):
        connection = Connection(self.server, user=USER_DN, password='wrong-password', client_strategy=self.client_strategy, lazy=True)
        connection.strategy.add_entry(USER_DN, {'userPassword': USER_PASSWORD, 'sn': 'user1_sn'})
        sent_messages = record_sends(connection)
        self.assertTrue(connection.bind())  # deferred bind always "succeeds" at this point
        self.assertTrue(connection.bound)   # WRONG assumption for an application: login is not proven
        self.assertEqual(sent_messages, [])
        connection.search('o=lab', '(sn=*)')  # fires the deferred bind, which fails
        self.assertEqual(sent_messages, ['bindRequest', 'searchRequest'])
        self.assertFalse(connection.bound)  # only now the failure is visible
        self.assertIsNone(connection.strategy.bound)
        connection.unbind()

    def test_reopen_after_unbind_starts_anonymous(self):
        self.assertTrue(self.connection.bind())
        self.assertEqual(self.connection.strategy.bound, USER_DN)
        self.connection.unbind()
        self.assertFalse(self.connection.bound)
        self.assertIsNone(self.connection.strategy.bound)  # unbind drops the identity
        # reopening the connection must not resurrect the previous identity
        self.assertTrue(self.connection.bind())
        self.assertTrue(self.connection.bound)
        self.assertEqual(self.connection.strategy.bound, USER_DN)
        self.assertEqual(self.connection.extend.standard.who_am_i(), USER_DN)

    def test_bound_flag_is_not_login_success_minimal_example(self):
        # the wrong pattern: checking connection.bound (or bind() with lazy=True)
        lazy_connection = Connection(self.server, user=USER_DN, password='wrong-password', client_strategy=self.client_strategy, lazy=True)
        lazy_connection.strategy.add_entry(USER_DN, {'userPassword': USER_PASSWORD, 'sn': 'user1_sn'})
        lazy_connection.bind()
        self.assertTrue(lazy_connection.bound)  # looks logged in, but is not
        lazy_connection.search('o=lab', '(sn=*)')  # deferred bind really fails here
        self.assertFalse(lazy_connection.bound)
        lazy_connection.unbind()
        # the correct pattern: a non-lazy bind plus an identity check
        strict_connection = Connection(self.server, user=USER_DN, password=USER_PASSWORD, client_strategy=self.client_strategy)
        self.assertTrue(strict_connection.bind())
        self.assertEqual(strict_connection.extend.standard.who_am_i(), USER_DN)
        strict_connection.unbind()


class TestMockSyncBindIdentity(BindIdentityMixin, unittest.TestCase):
    client_strategy = MOCK_SYNC


class TestMockAsyncBindIdentity(BindIdentityMixin, unittest.TestCase):
    client_strategy = MOCK_ASYNC
