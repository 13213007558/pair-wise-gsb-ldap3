"""
"""

# Created on 2026.09.25
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

import base64
import hashlib
import hmac
import unittest

from ldap3 import AUTO_BIND_NONE, SASL, SCRAM_SHA_256, SCRAM_SHA_256_PLUS, Server, Connection, SYNC
from ldap3.core.connection import SASL_AVAILABLE_MECHANISMS
from ldap3.core.exceptions import LDAPCommunicationError, LDAPPasswordIsMandatoryError, LDAPScramChannelBindingError, LDAPScramError, LDAPScramServerError, LDAPScramVerificationError
from ldap3.protocol.sasl.scram import sasl_scram_sha_256, sasl_scram_sha_256_plus, SUPPORTED_CHANNEL_BINDING_TYPES


# test vector from RFC 7677 (section 3)
RFC7677_CLIENT_NONCE = 'rOprNGfwEbeRWgbNEkqO'
RFC7677_SERVER_FIRST = b'r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096'
RFC7677_SERVER_FINAL = b'v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4='
RFC7677_EXPECTED_CLIENT_FIRST = b'n,,n=user,r=rOprNGfwEbeRWgbNEkqO'
RFC7677_EXPECTED_CLIENT_FINAL = b'c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ='


def scram_keys(password, salt, iterations, auth_message):
    # independent reference implementation of the RFC 5802/7677 key derivation
    salted_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, 32)
    client_key = hmac.new(salted_password, b'Client Key', hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    client_signature = hmac.new(stored_key, auth_message.encode('ascii'), hashlib.sha256).digest()
    client_proof = bytes(part_x ^ part_y for part_x, part_y in zip(client_key, client_signature))
    server_key = hmac.new(salted_password, b'Server Key', hashlib.sha256).digest()
    server_signature = hmac.new(server_key, auth_message.encode('ascii'), hashlib.sha256).digest()
    return client_proof, server_signature


class FakeSyncStrategy(object):
    sync = True


class FakeTls(object):
    def __init__(self, peer_certificate=None):
        self.peer_certificate = peer_certificate


class FakeServer(object):
    def __init__(self, ssl=False, tls=None):
        self.ssl = ssl
        self.host = 'localhost'
        self.tls = tls if tls is not None else FakeTls()


class FakeSocket(object):
    def __init__(self, tls_unique=None):
        self._tls_unique = tls_unique

    def get_channel_binding(self, channel_binding_type):
        if channel_binding_type == 'tls-unique':
            return self._tls_unique
        return None


class FakeScramConnection(object):
    # mimics the parts of Connection used by send_sasl_negotiation/abort_sasl_negotiation
    def __init__(self, mechanism, credentials, responses, server=None, socket=None, fail_on_send=None):
        self.sasl_mechanism = mechanism
        self.sasl_credentials = credentials
        self.version = 3
        self.server = server if server is not None else FakeServer()
        self.socket = socket
        self.strategy = FakeSyncStrategy()
        self.result = None
        self.sasl_in_progress = False
        self.sent_messages = []
        self._responses = list(responses)
        self._fail_on_send = fail_on_send

    def send(self, message_type, request, controls):
        message_id = len(self.sent_messages) + 1
        if self._fail_on_send == message_id:
            raise LDAPCommunicationError('simulated connection drop')
        sasl_credentials = request['authentication'].getComponentByName('sasl').getComponentByName('credentials')
        self.sent_messages.append(bytes(sasl_credentials) if sasl_credentials.isValue else None)
        return message_id

    def post_send_single_response(self, message_id):
        self.result = self._responses.pop(0)
        return message_id


def bind_result(result_code, sasl_credentials=None, description=''):
    return {'result': result_code, 'description': description, 'dn': '', 'message': '', 'referrals': None, 'saslCreds': sasl_credentials}
def bind_result(result_code, sasl_credentials=None, description=''):
    return {'result': result_code, 'description': description, 'dn': '', 'message': '', 'referrals': None, 'saslCreds': sasl_credentials}


class TestScramSha256(unittest.TestCase):
    def test_rfc7677_exchange(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, RFC7677_SERVER_FINAL)])
        result = sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(connection.sent_messages[0], RFC7677_EXPECTED_CLIENT_FIRST)
        self.assertEqual(connection.sent_messages[1], RFC7677_EXPECTED_CLIENT_FINAL)
        self.assertEqual(result['result'], 0)

    def test_server_signature_mismatch_fails_even_on_ldap_success(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, b'v=' + base64.b64encode(b'\x00' * 32))])
        with self.assertRaises(LDAPScramVerificationError) as context:
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertNotIn('pencil', str(context.exception))

    def test_ldap_success_without_server_final_message_fails(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0)])
        with self.assertRaises(LDAPScramError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)

    def test_server_error_in_server_final_message(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, b'e=invalid-credentials')])
        with self.assertRaises(LDAPScramServerError) as context:
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertIn('invalid-credentials', str(context.exception))
        self.assertNotIn('pencil', str(context.exception))

    def test_truncated_server_nonce_fails(self):
        server_first = b'r=' + RFC7677_CLIENT_NONCE[:-1].encode('ascii') + b',s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096'
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, server_first),
            bind_result(7)])  # result of the abort request
        with self.assertRaises(LDAPScramError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(len(connection.sent_messages), 2)  # client-first + abort
        self.assertIsNone(connection.sent_messages[1])  # abort sends no credentials

    def test_unrelated_server_nonce_fails(self):
        server_first = b'r=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096'
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, server_first),
            bind_result(7)])
        with self.assertRaises(LDAPScramError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)

    def test_duplicated_attribute_fails(self):
        server_first = RFC7677_SERVER_FIRST + b',i=1'
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, server_first),
            bind_result(7)])
        with self.assertRaises(LDAPScramError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)

    def test_mandatory_extension_fails(self):
        server_first = b'm=unsupported,' + RFC7677_SERVER_FIRST
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, server_first),
            bind_result(7)])
        with self.assertRaises(LDAPScramError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)

    def test_invalid_salt_fails(self):
        server_first = b'r=' + RFC7677_CLIENT_NONCE.encode('ascii') + b'AA,s=!!!not-base64!!!,i=4096'
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, server_first),
            bind_result(7)])
        with self.assertRaises(LDAPScramError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)

    def test_invalid_iteration_count_fails(self):
        for iteration_count in (b'0', b'-1', b'abc'):
            server_first = b'r=' + RFC7677_CLIENT_NONCE.encode('ascii') + b'AA,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=' + iteration_count
            connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
                bind_result(14, server_first),
                bind_result(7)])
            with self.assertRaises(LDAPScramError):
                sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)

    def test_invalid_credentials_result_returned(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(49, description='invalidCredentials')])
        result = sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(result['result'], 49)

    def test_disconnect_before_first_send(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [], fail_on_send=1)
        with self.assertRaises(LDAPCommunicationError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(connection.sent_messages, [])
        self.assertFalse(connection.sasl_in_progress)

    def test_disconnect_mid_exchange(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, RFC7677_SERVER_FIRST)], fail_on_send=2)
        with self.assertRaises(LDAPCommunicationError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(len(connection.sent_messages), 1)
        self.assertFalse(connection.sasl_in_progress)

    def test_no_state_left_on_connection_after_failure(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, b'v=' + base64.b64encode(b'\x00' * 32))])
        attributes_before = set(vars(connection))
        with self.assertRaises(LDAPScramVerificationError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(set(vars(connection)), attributes_before)
        self.assertEqual(set(vars(connection)), attributes_before)


class TestScramSha256Plus(unittest.TestCase):
    def test_plus_exchange_with_injected_channel_binding(self):
        channel_binding_data = b'test-tls-channel-binding-data'
        gs2_header = b'p=tls-server-end-point,,'
        channel_binding = base64.b64encode(gs2_header + channel_binding_data).decode('ascii')
        client_first_bare = 'n=user,r=' + RFC7677_CLIENT_NONCE
        client_final_without_proof = 'c=' + channel_binding + ',r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0'
        auth_message = client_first_bare + ',' + RFC7677_SERVER_FIRST.decode('ascii') + ',' + client_final_without_proof
        client_proof, server_signature = scram_keys('pencil', base64.b64decode(b'W22ZaJ0SNY7soEsUEjb6gQ=='), 4096, auth_message)
        expected_client_final = (client_final_without_proof + ',p=' + base64.b64encode(client_proof).decode('ascii')).encode('ascii')

        connection = FakeScramConnection(SCRAM_SHA_256_PLUS, ('user', 'pencil', 'tls-server-end-point'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, b'v=' + base64.b64encode(server_signature))])
        result = sasl_scram_sha_256_plus(connection, None, client_nonce=RFC7677_CLIENT_NONCE, channel_binding_data=channel_binding_data)
        self.assertEqual(connection.sent_messages[0], gs2_header + client_first_bare.encode('ascii'))
        self.assertEqual(connection.sent_messages[1], expected_client_final)
        self.assertEqual(result['result'], 0)

    def test_plus_fails_without_channel_binding_data(self):
        # no TLS peer certificate and no usable socket: must fail, never downgrade
        connection = FakeScramConnection(SCRAM_SHA_256_PLUS, ('user', 'pencil', 'tls-server-end-point'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, RFC7677_SERVER_FINAL)])
        with self.assertRaises(LDAPScramChannelBindingError):
            sasl_scram_sha_256_plus(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(connection.sent_messages, [])

    def test_plus_fails_with_unselected_channel_binding_type(self):
        connection = FakeScramConnection(SCRAM_SHA_256_PLUS, ('user', 'pencil', None), [])
        with self.assertRaises(LDAPScramChannelBindingError):
            sasl_scram_sha_256_plus(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(connection.sent_messages, [])

    def test_plus_fails_with_unsupported_channel_binding_type(self):
        connection = FakeScramConnection(SCRAM_SHA_256_PLUS, ('user', 'pencil', 'tls-made-up'), [])
        with self.assertRaises(LDAPScramChannelBindingError):
            sasl_scram_sha_256_plus(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(connection.sent_messages, [])

    def test_plus_tls_unique_from_socket(self):
        tls_unique = b'\x01\x02\x03\x04tls-unique-finished'
        gs2_header = b'p=tls-unique,,'
        channel_binding = base64.b64encode(gs2_header + tls_unique).decode('ascii')
        client_first_bare = 'n=user,r=' + RFC7677_CLIENT_NONCE
        client_final_without_proof = 'c=' + channel_binding + ',r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0'
        auth_message = client_first_bare + ',' + RFC7677_SERVER_FIRST.decode('ascii') + ',' + client_final_without_proof
        client_proof, server_signature = scram_keys('pencil', base64.b64decode(b'W22ZaJ0SNY7soEsUEjb6gQ=='), 4096, auth_message)

        connection = FakeScramConnection(SCRAM_SHA_256_PLUS, ('user', 'pencil', 'tls-unique'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, b'v=' + base64.b64encode(server_signature))],
            server=FakeServer(ssl=True), socket=FakeSocket(tls_unique=tls_unique))
        result = sasl_scram_sha_256_plus(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(connection.sent_messages[1], (client_final_without_proof + ',p=' + base64.b64encode(client_proof).decode('ascii')).encode('ascii'))
        self.assertEqual(result['result'], 0)

    def test_plus_tls_unique_unavailable_fails(self):
        connection = FakeScramConnection(SCRAM_SHA_256_PLUS, ('user', 'pencil', 'tls-unique'), [],
            server=FakeServer(ssl=True), socket=FakeSocket(tls_unique=None))
        with self.assertRaises(LDAPScramChannelBindingError):
            sasl_scram_sha_256_plus(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        self.assertEqual(connection.sent_messages, [])

    def test_supported_channel_binding_types(self):
        self.assertIn('tls-unique', SUPPORTED_CHANNEL_BINDING_TYPES)
        self.assertIn('tls-server-end-point', SUPPORTED_CHANNEL_BINDING_TYPES)
    def test_supported_channel_binding_types(self):
        self.assertIn('tls-unique', SUPPORTED_CHANNEL_BINDING_TYPES)
        self.assertIn('tls-server-end-point', SUPPORTED_CHANNEL_BINDING_TYPES)


class TestScramCredentials(unittest.TestCase):
    def test_username_escaping(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('u=ser,name', 'pencil'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, RFC7677_SERVER_FINAL)])
        try:
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        except LDAPScramVerificationError:
            pass  # signature does not match with a different username, only the outgoing message matters here
        self.assertTrue(connection.sent_messages[0].startswith(b'n,,n=u=3Dser=2Cname,r='))

    def test_authzid_in_gs2_header(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil', 'admin'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, RFC7677_SERVER_FINAL)])
        try:
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)
        except LDAPScramVerificationError:
            pass
        self.assertTrue(connection.sent_messages[0].startswith(b'n,a=admin,n=user,r='))

    def test_empty_password_fails(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', ''), [])
        with self.assertRaises(LDAPPasswordIsMandatoryError):
            sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)

    def test_invalid_credentials_tuple_fails(self):
        for credentials in (None, 'user', ('user',), ('user', 'pencil', 'authzid', 'extra')):
            connection = FakeScramConnection(SCRAM_SHA_256, credentials, [])
            with self.assertRaises(LDAPScramError):
                sasl_scram_sha_256(connection, None, client_nonce=RFC7677_CLIENT_NONCE)

    def test_generated_nonce_is_used_and_extended(self):
        connection = FakeScramConnection(SCRAM_SHA_256, ('user', 'pencil'), [
            bind_result(14, RFC7677_SERVER_FIRST),
            bind_result(0, RFC7677_SERVER_FINAL)])

        # server nonce must extend the generated client nonce, so patch the
        # first response after seeing the outgoing client-first-message
        original_send = connection.send

        def send_and_fix_response(message_type, request, controls):
            message_id = original_send(message_type, request, controls)
            if message_id == 1:
                client_nonce = connection.sent_messages[0].split(b',r=')[1].decode('ascii')
                connection._responses[0] = bind_result(14, RFC7677_SERVER_FIRST.replace(RFC7677_CLIENT_NONCE.encode('ascii'), client_nonce.encode('ascii')))
            return message_id

        connection.send = send_and_fix_response
        try:
            sasl_scram_sha_256(connection, None)
        except LDAPScramVerificationError:
            pass  # server signature no longer matches, nonce handling already verified
        self.assertEqual(len(connection.sent_messages), 2)

    def test_mechanisms_registered(self):
        self.assertIn(SCRAM_SHA_256, SASL_AVAILABLE_MECHANISMS)
        self.assertIn(SCRAM_SHA_256_PLUS, SASL_AVAILABLE_MECHANISMS)

    def test_repr_hides_password(self):
        server = Server('localhost')
        connection = Connection(server, authentication=SASL, sasl_mechanism=SCRAM_SHA_256, sasl_credentials=('user', 'secret-password'), auto_bind=AUTO_BIND_NONE, client_strategy=SYNC)
        representation = connection.repr_with_sensitive_data_stripped()
        self.assertNotIn('secret-password', representation)
        self.assertIn('***************', representation)
        connection_plus = Connection(server, authentication=SASL, sasl_mechanism=SCRAM_SHA_256_PLUS, sasl_credentials=('user', 'secret-password', 'tls-server-end-point'), auto_bind=AUTO_BIND_NONE, client_strategy=SYNC)
        representation_plus = connection_plus.repr_with_sensitive_data_stripped()
        self.assertNotIn('secret-password', representation_plus)
        self.assertIn('tls-server-end-point', representation_plus)
