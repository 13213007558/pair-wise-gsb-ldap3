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

# implements the client side of the SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
# SASL mechanisms as per RFC 5802 (SCRAM), RFC 7677 (SCRAM-SHA-256)
# and RFC 5929 (TLS channel bindings)

from base64 import b64encode, b64decode
from binascii import hexlify
import hashlib
import hmac
from os import urandom
from string import ascii_letters

from ... import SEQUENCE_TYPES, STRING_TYPES
from ...core.exceptions import LDAPPackageUnavailableError, LDAPPasswordIsMandatoryError, LDAPScramChannelBindingError, LDAPScramError, LDAPScramServerError, LDAPScramVerificationError, LDAPUserNameIsMandatoryError
from ...core.results import RESULT_SUCCESS
from ...protocol.sasl.sasl import abort_sasl_negotiation, send_sasl_negotiation, sasl_prep, validate_simple_password
from ...utils.conv import to_unicode

SCRAM_SHA_256_HASH = 'sha256'
SCRAM_SHA_256_DIGEST_SIZE = hashlib.new(SCRAM_SHA_256_HASH).digest_size

TLS_UNIQUE = 'tls-unique'
TLS_SERVER_END_POINT = 'tls-server-end-point'
SUPPORTED_CHANNEL_BINDING_TYPES = (TLS_UNIQUE, TLS_SERVER_END_POINT)


def _escape_scram_name(name):
    # escaping of '=' and ',' in usernames and authzids as per RFC 5802 (5.1)
    return name.replace('=', '=3D').replace(',', '=2C')


def _generate_client_nonce():
    return str(hexlify(urandom(18)).decode('ascii'))  # str fix for Python 2


def _validate_nonce(nonce):
    # nonce must be printable ASCII without ',' as per RFC 5802 (printable)
    if not nonce or any(ord(c) < 0x21 or ord(c) > 0x7E or c == ',' for c in nonce):
        raise LDAPScramError('SCRAM error: invalid nonce')
    return nonce


def _parse_scram_message(message, message_name):
    # strict parser for SCRAM messages as per RFC 5802 (7): attributes are a
    # single ALPHA, values are printable ASCII without ','; duplicated
    # attributes are rejected
    if isinstance(message, bytes):
        try:
            message = message.decode('ascii')
        except UnicodeDecodeError:
            raise LDAPScramError('SCRAM error: ' + message_name + ' is not ASCII')
    if not message:
        raise LDAPScramError('SCRAM error: empty ' + message_name)
    attributes = dict()
    for part in message.split(','):
        if len(part) < 2 or part[0] not in ascii_letters or part[1] != '=':
            raise LDAPScramError('SCRAM error: malformed attribute in ' + message_name)
        attribute, value = part[0], part[2:]
        if any(ord(c) < 0x21 or ord(c) > 0x7E for c in value):
            raise LDAPScramError('SCRAM error: non-printable value in ' + message_name)
        if attribute in attributes:
            raise LDAPScramError('SCRAM error: duplicated attribute in ' + message_name)
        attributes[attribute] = value
    return attributes


def _validate_server_first_message(attributes, client_nonce):
    if 'm' in attributes:  # mandatory extension, unsupported as per RFC 5802 (5.1)
        raise LDAPScramError('SCRAM error: unsupported mandatory extension in server-first-message')
    for mandatory in ('r', 's', 'i'):
        if mandatory not in attributes:
            raise LDAPScramError('SCRAM error: missing attribute in server-first-message')
    server_nonce = attributes['r']
    if not server_nonce.startswith(client_nonce):  # the server must extend the client nonce as per RFC 5802 (3)
        raise LDAPScramError('SCRAM error: server nonce does not extend client nonce')
    _validate_nonce(server_nonce)
    try:
        salt = b64decode(attributes['s'].encode('ascii'), validate=True)
    except Exception:
        raise LDAPScramError('SCRAM error: invalid base64 salt in server-first-message')
    if not salt:
        raise LDAPScramError('SCRAM error: empty salt in server-first-message')
    if not attributes['i'].isdigit():
        raise LDAPScramError('SCRAM error: invalid iteration count in server-first-message')
    iterations = int(attributes['i'])
    if iterations < 1:
        raise LDAPScramError('SCRAM error: iteration count must be positive')
    return server_nonce, salt, iterations


def _parse_server_final_message(attributes):
    if 'e' in attributes:  # server error as per RFC 5802 (5.2)
        raise LDAPScramServerError('SCRAM authentication refused by server: ' + attributes['e'])
    if 'v' not in attributes:
        raise LDAPScramError('SCRAM error: missing verifier in server-final-message')
    try:
        server_signature = b64decode(attributes['v'].encode('ascii'), validate=True)
    except Exception:
        raise LDAPScramError('SCRAM error: invalid base64 verifier in server-final-message')
    if len(server_signature) != SCRAM_SHA_256_DIGEST_SIZE:
        raise LDAPScramError('SCRAM error: invalid verifier length in server-final-message')
    return server_signature
    return server_signature


def _tls_server_end_point_data(peer_certificate):
    # tls-server-end-point channel binding as per RFC 5929 (4.1)
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        raise LDAPPackageUnavailableError('package cryptography missing')
    certificate = x509.load_der_x509_certificate(peer_certificate, default_backend())
    signature_hash_algorithm = certificate.signature_hash_algorithm
    if isinstance(signature_hash_algorithm, (hashes.MD5, hashes.SHA1)):  # RFC 5929 (4.1) hash function selection
        digest = hashes.Hash(hashes.SHA256(), default_backend())
    else:
        digest = hashes.Hash(signature_hash_algorithm, default_backend())
    digest.update(peer_certificate)
    return digest.finalize()


def _get_channel_binding_data(connection, channel_binding_type):
    # retrieve the channel binding data for the caller-selected binding type;
    # fails when the TLS layer cannot provide it, never downgrades to plain SCRAM
    if channel_binding_type == TLS_UNIQUE:
        socket = getattr(connection, 'socket', None)
        get_channel_binding = getattr(socket, 'get_channel_binding', None)
        data = get_channel_binding(TLS_UNIQUE) if get_channel_binding else None
        if not data:
            raise LDAPScramChannelBindingError('SCRAM error: tls-unique channel binding data unavailable')
        return data
    if channel_binding_type == TLS_SERVER_END_POINT:
        tls = getattr(getattr(connection, 'server', None), 'tls', None)
        peer_certificate = getattr(tls, 'peer_certificate', None)
        if not peer_certificate:
            raise LDAPScramChannelBindingError('SCRAM error: tls-server-end-point channel binding data unavailable')
        return _tls_server_end_point_data(peer_certificate)
    raise LDAPScramChannelBindingError('SCRAM error: unsupported channel binding type: ' + to_unicode(channel_binding_type))


def _scram_credentials(connection, plus):
    # sasl_credentials must be a tuple made up of the following elements:
    # SCRAM-SHA-256: (username, password) or (username, password, authzid)
    # SCRAM-SHA-256-PLUS: (username, password, channel_binding_type) or (username, password, channel_binding_type, authzid)
    credentials = connection.sasl_credentials
    if not isinstance(credentials, SEQUENCE_TYPES) or isinstance(credentials, STRING_TYPES + (bytes,)):
        raise LDAPScramError('SCRAM error: invalid sasl_credentials')
    if plus:
        if len(credentials) not in (3, 4):
            raise LDAPScramError('SCRAM error: sasl_credentials for SCRAM-SHA-256-PLUS must be (username, password, channel_binding_type[, authzid])')
        username, password, channel_binding_type = credentials[0], credentials[1], credentials[2]
        authzid = credentials[3] if len(credentials) == 4 else None
        if not channel_binding_type or not isinstance(channel_binding_type, STRING_TYPES):
            raise LDAPScramChannelBindingError('SCRAM error: a channel binding type must be explicitly selected for SCRAM-SHA-256-PLUS')
    else:
        if len(credentials) not in (2, 3):
            raise LDAPScramError('SCRAM error: sasl_credentials for SCRAM-SHA-256 must be (username, password[, authzid])')
        username, password = credentials[0], credentials[1]
        authzid = credentials[2] if len(credentials) == 3 else None
        channel_binding_type = None
    if not username:
        raise LDAPUserNameIsMandatoryError('user name is mandatory in SCRAM bind')
    if not password:
        raise LDAPPasswordIsMandatoryError('password is mandatory in SCRAM bind')
    username = sasl_prep(to_unicode(username))  # as per RFC 5802 (5.1)
    password = validate_simple_password(password)
    if authzid:
        authzid = sasl_prep(to_unicode(authzid))
    return username, password, authzid, channel_binding_type


def _extract_server_message(result, message_name):
    if result is None:
        raise LDAPScramError('SCRAM error: no response received from server')
    server_creds = result.get('saslCreds', None)
    if server_creds is None:
        if result.get('result', None) == RESULT_SUCCESS:
            # a successful LDAP result never skips the SCRAM proof exchange
            raise LDAPScramError('SCRAM error: ' + message_name + ' missing in server response')
        return None  # regular bind failure (e.g. invalid credentials)
    return server_creds


def _abort_quietly(connection, controls):
    try:
        abort_sasl_negotiation(connection, controls)
    except Exception:
        pass


def sasl_scram_sha_256(connection, controls, client_nonce=None, channel_binding_data=None):
    return _sasl_scram(connection, controls, plus=False, client_nonce=client_nonce, channel_binding_data=channel_binding_data)


def sasl_scram_sha_256_plus(connection, controls, client_nonce=None, channel_binding_data=None):
    return _sasl_scram(connection, controls, plus=True, client_nonce=client_nonce, channel_binding_data=channel_binding_data)


def _sasl_scram(connection, controls, plus, client_nonce=None, channel_binding_data=None):
    # client_nonce and channel_binding_data are injectable for testing purposes
    username, password, authzid, channel_binding_type = _scram_credentials(connection, plus)

    if plus:
        if channel_binding_data is None:
            channel_binding_data = _get_channel_binding_data(connection, channel_binding_type)
        gs2_header = 'p=' + channel_binding_type + ','
    else:
        channel_binding_data = b''
        gs2_header = 'n,'
    gs2_header += ('a=' + _escape_scram_name(authzid) + ',') if authzid else ','

    if client_nonce is None:
        client_nonce = _generate_client_nonce()
    client_nonce = _validate_nonce(to_unicode(client_nonce))

    # step one of RFC 5802: client-first-message
    client_first_bare = 'n=' + _escape_scram_name(username) + ',r=' + client_nonce
    result = send_sasl_negotiation(connection, controls, (gs2_header + client_first_bare).encode('ascii'))
    server_first_message = _extract_server_message(result, 'server-first-message')
    if server_first_message is None:
        return result

    try:
        server_first_attributes = _parse_scram_message(server_first_message, 'server-first-message')
        server_nonce, salt, iterations = _validate_server_first_message(server_first_attributes, client_nonce)
    except LDAPScramError:
        _abort_quietly(connection, controls)
        raise
    if isinstance(server_first_message, bytes):
        server_first_message = server_first_message.decode('ascii')

    # step two of RFC 5802: client-final-message
    channel_binding = b64encode(gs2_header.encode('ascii') + channel_binding_data).decode('ascii')
    client_final_without_proof = 'c=' + channel_binding + ',r=' + server_nonce
    auth_message = client_first_bare + ',' + server_first_message + ',' + client_final_without_proof

    salted_password = hashlib.pbkdf2_hmac(SCRAM_SHA_256_HASH, password, salt, iterations, SCRAM_SHA_256_DIGEST_SIZE)
    client_key = hmac.new(salted_password, b'Client Key', hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    client_signature = hmac.new(stored_key, auth_message.encode('ascii'), hashlib.sha256).digest()
    client_proof = bytes(bytearray(part_x ^ part_y for part_x, part_y in zip(client_key, client_signature)))
    server_key = hmac.new(salted_password, b'Server Key', hashlib.sha256).digest()
    expected_server_signature = hmac.new(server_key, auth_message.encode('ascii'), hashlib.sha256).digest()

    client_final_message = client_final_without_proof + ',p=' + b64encode(client_proof).decode('ascii')
    result = send_sasl_negotiation(connection, controls, client_final_message.encode('ascii'))

    # step three of RFC 5802: server-final-message; the server signature must
    # always be verified, even when the LDAP bind result is success
    server_final_message = _extract_server_message(result, 'server-final-message')
    if server_final_message is None:
        return result
    server_final_attributes = _parse_scram_message(server_final_message, 'server-final-message')
    server_signature = _parse_server_final_message(server_final_attributes)
    if not hmac.compare_digest(server_signature, expected_server_signature):
        raise LDAPScramVerificationError('SCRAM error: server signature verification failed')

    return result
