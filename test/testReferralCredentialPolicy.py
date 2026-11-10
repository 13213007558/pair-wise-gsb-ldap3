"""
"""

# Created on 2026.11.10
#
# Author: Giovanni Cannata
#
# Copyright 2013 - 2025 Giovanni Cannata
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
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from ldap3 import Server, Connection, SIMPLE, SASL, ANONYMOUS, PLAIN, SUBTREE, SYNC, DEREF_ALWAYS, \
    ReferralCredentialPolicy, DefaultReferralCredentialPolicy, \
    REFERRAL_CREDENTIALS_DENY, REFERRAL_CREDENTIALS_ANONYMOUS, REFERRAL_CREDENTIALS_ALLOW
from ldap3.core.exceptions import LDAPReferralError, LDAPStartTLSError
from ldap3.strategy.base import BaseStrategy

CANARY_PASSWORD = 'c4n4ry-Pazzw0rd-not-in-diagnostics'


class FakeConnection(object):
    """In-memory replacement of Connection: records the bind parameters it
    receives and never touches the network."""

    instances = []
    start_tls_result = True

    @classmethod
    def reset(cls):
        cls.instances = []
        cls.start_tls_result = True

    def __init__(self, server=None, user=None, password=None, version=3, authentication=None,
                 client_strategy=None, auto_referrals=None, read_only=None, check_names=None,
                 raise_exceptions=None, fast_decoder=None, receive_timeout=None,
                 sasl_mechanism=None, sasl_credentials=None, **kwargs):
        self.server = server
        self.user = user
        self.password = password
        self.version = version
        self.authentication = authentication
        self.sasl_mechanism = sasl_mechanism
        self.sasl_credentials = sasl_credentials
        self.extra_kwargs = kwargs
        self.bound = False
        self.tls_started = False
        self.last_error = None
        self.use_referral_cache = False
        self.usage = None
        self._usage = None
        self.read_only = read_only
        self.check_names = check_names
        self.raise_exceptions = raise_exceptions
        self.fast_decoder = fast_decoder
        self.receive_timeout = receive_timeout
        self.strategy = BaseStrategy(self)
        self.bind_calls = []
        self.unbind_calls = 0
        self.start_tls_calls = 0
        self.search_calls = []
        self.response = []
        self.result = {'result': 0, 'description': 'success'}
        FakeConnection.instances.append(self)

    def open(self):
        pass

    def bind(self):
        self.bound = True
        self.bind_calls.append({
            'user': self.user,
            'password': self.password,
            'authentication': self.authentication,
            'sasl_mechanism': self.sasl_mechanism,
            'sasl_credentials': self.sasl_credentials,
        })
        return True

    def unbind(self):
        self.unbind_calls += 1
        self.bound = False

    def start_tls(self):
        self.start_tls_calls += 1
        return FakeConnection.start_tls_result

    def search(self, *args, **kwargs):
        self.search_calls.append((args, kwargs))
        return True


class RecordingPolicy(ReferralCredentialPolicy):
    """Policy that records its inputs and replays a scripted decision."""

    def __init__(self, decision):
        self.decision = decision
        self.calls = []

    def decide(self, connection, referral):
        self.calls.append((connection, dict(referral)))
        return self.decision


def make_connection(authentication=SIMPLE, use_ssl=False, allowed_referral_hosts=None,
                    policy=None, use_referral_cache=False, sasl_mechanism=None,
                    sasl_credentials=None, user='cn=referral-user,dc=test'):
    server = Server('host-a.test', use_ssl=use_ssl, get_info=None,
                    allowed_referral_hosts=allowed_referral_hosts,
                    referral_credential_policy=policy)
    connection = Connection(server,
                            user=user if authentication in (SIMPLE, None) else None,
                            password=CANARY_PASSWORD if authentication in (SIMPLE, None) else None,
                            authentication=authentication,
                            sasl_mechanism=sasl_mechanism,
                            sasl_credentials=sasl_credentials,
                            client_strategy=SYNC,
                            use_referral_cache=use_referral_cache)
    connection.bound = True
    return connection


def search_request():
    return {'type': 'searchRequest',
            'base': 'dc=original,dc=test',
            'filter': '(cn=original)',
            'scope': SUBTREE,
            'dereferenceAlias': DEREF_ALWAYS,
            'attributes': ['cn'],
            'sizeLimit': 0,
            'timeLimit': 0,
            'typesOnly': False,
            'controls': None}


class TestReferralCredentialPolicy(unittest.TestCase):

    def setUp(self):
        FakeConnection.reset()

    def follow(self, connection, referral_uri, request=None):
        connection.strategy._referrals = []  # each operation starts with a fresh referral chain, as get_response does
        with patch('ldap3.core.connection.Connection', FakeConnection):
            return connection.strategy.do_operation_on_referral(request or search_request(), [referral_uri])

    def last_fake(self):
        return FakeConnection.instances[-1]

    # credential passing per authentication type

    def test_simple_bind_credentials_passed_when_allowed(self):
        connection = make_connection(allowed_referral_hosts=[('*', True)])
        self.follow(connection, 'ldap://host-b.test/dc=test')
        bind = self.last_fake().bind_calls[0]
        self.assertEqual(bind['authentication'], SIMPLE)
        self.assertEqual(bind['user'], 'cn=referral-user,dc=test')
        self.assertEqual(bind['password'], CANARY_PASSWORD)

    def test_simple_bind_anonymous_when_host_not_auth_allowed(self):
        connection = make_connection(allowed_referral_hosts=[('*', False)])
        self.follow(connection, 'ldap://host-b.test/dc=test')
        bind = self.last_fake().bind_calls[0]
        self.assertEqual(bind['authentication'], ANONYMOUS)
        self.assertIsNone(bind['user'])
        self.assertIsNone(bind['password'])

    def test_sasl_credentials_passed_when_allowed(self):
        connection = make_connection(authentication=SASL, sasl_mechanism=PLAIN,
                                     sasl_credentials=(None, 'sasl-user', CANARY_PASSWORD),
                                     allowed_referral_hosts=[('*', True)])
        self.follow(connection, 'ldap://host-b.test/dc=test')
        bind = self.last_fake().bind_calls[0]
        self.assertEqual(bind['authentication'], SASL)
        self.assertEqual(bind['sasl_mechanism'], PLAIN)
        self.assertEqual(bind['sasl_credentials'], (None, 'sasl-user', CANARY_PASSWORD))

    def test_sasl_credentials_not_copied_in_anonymous_branch(self):
        connection = make_connection(authentication=SASL, sasl_mechanism=PLAIN,
                                     sasl_credentials=(None, 'sasl-user', CANARY_PASSWORD),
                                     allowed_referral_hosts=[('*', False)])
        self.follow(connection, 'ldap://host-b.test/dc=test')
        bind = self.last_fake().bind_calls[0]
        self.assertEqual(bind['authentication'], ANONYMOUS)
        self.assertIsNone(bind['sasl_mechanism'])
        self.assertIsNone(bind['sasl_credentials'])
        self.assertIsNone(bind['password'])

    def test_anonymous_connection_followed_anonymously(self):
        connection = make_connection(authentication=ANONYMOUS,
                                     allowed_referral_hosts=[('*', True)])
        self.follow(connection, 'ldap://host-b.test/dc=test')
        bind = self.last_fake().bind_calls[0]
        self.assertEqual(bind['authentication'], ANONYMOUS)
        self.assertIsNone(bind['password'])

    # TLS downgrade

    def test_tls_downgrade_never_carries_password(self):
        connection = make_connection(use_ssl=True, allowed_referral_hosts=[('*', True)])
        self.follow(connection, 'ldap://host-b.test/dc=test')  # cleartext target
        bind = self.last_fake().bind_calls[0]
        self.assertEqual(bind['authentication'], ANONYMOUS)
        self.assertIsNone(bind['password'])

    def test_secure_to_secure_referral_keeps_credentials(self):
        connection = make_connection(use_ssl=True, allowed_referral_hosts=[('*', True)])
        self.follow(connection, 'ldaps://host-b.test/dc=test')
        bind = self.last_fake().bind_calls[0]
        self.assertEqual(bind['authentication'], SIMPLE)
        self.assertEqual(bind['password'], CANARY_PASSWORD)

    def test_start_tls_failure_raises_without_password(self):
        FakeConnection.start_tls_result = False
        connection = make_connection(allowed_referral_hosts=[('*', True)])
        connection.tls_started = True
        with self.assertRaises(LDAPStartTLSError) as raised:
            self.follow(connection, 'ldap://host-b.test/dc=test')
        self.assertNotIn(CANARY_PASSWORD, str(raised.exception))
        self.assertNotIn(CANARY_PASSWORD, connection.last_error or '')
        self.assertEqual(self.last_fake().unbind_calls, 1)  # failed referral connection cleaned up
        self.assertEqual(self.last_fake().bind_calls, [])  # no bind attempted after tls failure

    # custom policy

    def test_deny_policy_refuses_referral_without_password_leak(self):
        policy = RecordingPolicy(REFERRAL_CREDENTIALS_DENY)
        connection = make_connection(policy=policy)
        with self.assertRaises(LDAPReferralError) as raised:
            self.follow(connection, 'ldap://host-b.test:1389/dc=test')
        self.assertNotIn(CANARY_PASSWORD, str(raised.exception))
        self.assertIn('host-b.test', str(raised.exception))
        self.assertEqual(FakeConnection.instances, [])

    def test_policy_receives_connection_and_target_context(self):
        policy = RecordingPolicy(REFERRAL_CREDENTIALS_ANONYMOUS)
        connection = make_connection(policy=policy)
        self.follow(connection, 'ldaps://host-b.test:1636/dc=test')
        self.assertEqual(len(policy.calls), 1)
        seen_connection, seen_referral = policy.calls[0]
        self.assertIs(seen_connection, connection)
        self.assertEqual(seen_referral['scheme'], 'ldaps')
        self.assertEqual(seen_referral['host'], 'host-b.test')
        self.assertEqual(seen_referral['port'], 1636)
        self.assertTrue(seen_referral['ssl'])
        self.assertEqual(seen_referral['authentication'], SIMPLE)
        bind = self.last_fake().bind_calls[0]
        self.assertEqual(bind['authentication'], ANONYMOUS)

    def test_custom_policy_overrides_allowed_referral_hosts_flag(self):
        # allowed_referral_hosts still gates which hosts are followed, the
        # custom policy decides about credentials
        policy = RecordingPolicy(REFERRAL_CREDENTIALS_ALLOW)
        connection = make_connection(allowed_referral_hosts=[('*', False)], policy=policy)
        self.follow(connection, 'ldap://host-b.test/dc=test')
        self.assertEqual(self.last_fake().bind_calls[0]['password'], CANARY_PASSWORD)

    def test_default_policy_is_used_when_no_policy_configured(self):
        server = Server('host-a.test', get_info=None)
        self.assertIsNone(server.referral_credential_policy)
        policy = DefaultReferralCredentialPolicy()
        connection = make_connection()
        referral = {'ssl': False, 'anonymousBindOnly': False}
        self.assertEqual(policy.decide(connection, referral), REFERRAL_CREDENTIALS_ALLOW)

    # multi-hop and loops

    def test_two_hop_referral_carries_policy_on_each_hop(self):
        connection = make_connection(allowed_referral_hosts=[('*', True)])
        with patch('ldap3.core.connection.Connection', FakeConnection):
            _, hop1, _ = connection.strategy.create_referral_connection(['ldap://host-b.test/dc=test'])
            _, hop2, _ = hop1.strategy.create_referral_connection(['ldap://host-c.test/dc=test'])
        self.assertEqual(len(FakeConnection.instances), 2)
        for fake in FakeConnection.instances:
            self.assertEqual(fake.bind_calls[0]['password'], CANARY_PASSWORD)
        self.assertEqual(hop2.server.host, 'host-c.test')

    def test_referral_loop_is_not_followed(self):
        connection = make_connection(allowed_referral_hosts=[('*', True)])
        with patch('ldap3.core.connection.Connection', FakeConnection):
            _, hop1, _ = connection.strategy.create_referral_connection(['ldap://host-b.test/dc=test'])
            _, hop2, _ = hop1.strategy.create_referral_connection(['ldap://host-a.test/dc=test'])
            selected, hop3, _ = hop2.strategy.create_referral_connection(['ldap://host-b.test/dc=test'])
        self.assertIsNone(selected)
        self.assertIsNone(hop3)
        self.assertEqual(len(FakeConnection.instances), 2)  # loop back to host-b not followed

    # referral cache

    def test_cache_reuses_connection_with_same_decision(self):
        connection = make_connection(allowed_referral_hosts=[('*', True)], use_referral_cache=True)
        self.follow(connection, 'ldap://host-b.test/dc=test')
        self.follow(connection, 'ldap://host-b.test/dc=test')
        self.assertEqual(len(FakeConnection.instances), 1)
        self.assertEqual(len(self.last_fake().bind_calls), 1)

    def test_cache_not_reused_after_config_change_to_anonymous(self):
        connection = make_connection(allowed_referral_hosts=[('*', True)], use_referral_cache=True)
        self.follow(connection, 'ldap://host-b.test/dc=test')
        connection.server.allowed_referral_hosts = [('*', False)]  # configuration change
        self.follow(connection, 'ldap://host-b.test/dc=test')
        self.assertEqual(len(FakeConnection.instances), 2)  # high-privilege cached connection not reused
        first, second = FakeConnection.instances
        self.assertEqual(first.bind_calls[0]['password'], CANARY_PASSWORD)
        self.assertEqual(second.bind_calls[0]['authentication'], ANONYMOUS)
        self.assertIsNone(second.bind_calls[0]['password'])
        # anonymous connection is now the one cached for the anonymous decision
        self.follow(connection, 'ldap://host-b.test/dc=test')
        self.assertEqual(len(FakeConnection.instances), 2)

    def test_cache_not_reused_after_config_change_to_credentials(self):
        connection = make_connection(allowed_referral_hosts=[('*', False)], use_referral_cache=True)
        self.follow(connection, 'ldap://host-b.test/dc=test')
        connection.server.allowed_referral_hosts = [('*', True)]  # configuration change
        self.follow(connection, 'ldap://host-b.test/dc=test')
        self.assertEqual(len(FakeConnection.instances), 2)  # anonymous cached connection not reused
        first, second = FakeConnection.instances
        self.assertEqual(first.bind_calls[0]['authentication'], ANONYMOUS)
        self.assertEqual(second.bind_calls[0]['password'], CANARY_PASSWORD)

    # operation parameters

    def test_search_uses_referral_base_filter_attributes(self):
        connection = make_connection()
        self.follow(connection, 'ldap://host-b.test/dc=referral,dc=test?sn,givenName?sub?(cn=referral)')
        args, _ = self.last_fake().search_calls[0]
        self.assertEqual(args[0], 'dc=referral,dc=test')
        self.assertEqual(args[1], '(cn=referral)')
        self.assertEqual(args[4], ['sn', 'givenName'])

    def test_search_falls_back_to_request_parameters(self):
        connection = make_connection()
        self.follow(connection, 'ldap://host-b.test')
        args, _ = self.last_fake().search_calls[0]
        self.assertEqual(args[0], 'dc=original,dc=test')
        self.assertEqual(args[1], '(cn=original)')
        self.assertEqual(args[4], ['cn'])

    def test_referral_connection_unbound_without_cache(self):
        connection = make_connection(use_referral_cache=False)
        self.follow(connection, 'ldap://host-b.test/dc=test')
        self.assertEqual(self.last_fake().unbind_calls, 1)


if __name__ == '__main__':
    unittest.main()
