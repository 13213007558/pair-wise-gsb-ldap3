"""
Tests for the RFC 4533 Content Synchronization (syncrepl) extension.

A scripted LDAP peer speaks BER over a real socket and sends
SearchResultEntry, IntermediateResponse and SearchResultDone messages
split at arbitrary byte boundaries.
"""

import socket
import threading
import time
import types
import unittest

from pyasn1.type.univ import OctetString, Boolean

from ldap3 import Server, Connection, SYNC, NONE
from ldap3.core.exceptions import LDAPSocketReceiveError
from ldap3.extend.standard.ContentSync import ContentSync
from ldap3.protocol.controls import build_control
from ldap3.protocol.convert import build_controls_list
from ldap3.protocol.rfc4511 import (LDAPMessage, MessageID, ProtocolOp, BindResponse, ResultCode, LDAPDN, LDAPString,
                                    SearchResultEntry, SearchResultDone, PartialAttribute, PartialAttributeList,
                                    AttributeDescription, AttributeValue, Vals,
                                    IntermediateResponse, IntermediateResponseName, IntermediateResponseValue)
from ldap3.protocol.rfc4533 import (SYNC_REQUEST_CONTROL, SYNC_STATE_CONTROL, SYNC_DONE_CONTROL, SYNC_INFO_MESSAGE,
                                    SyncRequestControlValue, SyncStateControlValue, SyncStateValue, SyncDoneControlValue,
                                    sync_info_refresh_present, sync_info_refresh_delete, sync_info_id_set, sync_info_newcookie)
from ldap3.strategy.base import BaseStrategy
from ldap3.utils.asn1 import encode, decoder

LDAP_MESSAGE_TEMPLATE = LDAPMessage()

TEST_BASE = 'dc=example,dc=com'


def read_ldap_message(conn):
    data = b''
    while True:
        length = BaseStrategy.compute_ldap_message_size(data)
        if length != -1 and len(data) >= length:
            return data[:length]
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk


def send_chunked(conn, data, chunk_size=1):
    # send a message split at arbitrary byte boundaries
    for offset in range(0, len(data), chunk_size):
        conn.sendall(data[offset:offset + chunk_size])
        time.sleep(0.001)


def ldap_message(message_id, operation_name, operation, controls=None):
    message = LDAPMessage()
    message['messageID'] = MessageID(message_id)
    message['protocolOp'] = ProtocolOp().setComponentByName(operation_name, operation)
    if controls:
        message['controls'] = build_controls_list(controls)
    return encode(message)


def bind_response(message_id, result_code=0):
    response = BindResponse()
    response['resultCode'] = ResultCode(result_code)
    response['matchedDN'] = LDAPDN('')
    response['diagnosticMessage'] = LDAPString('')
    return ldap_message(message_id, 'bindResponse', response)


def sync_state_control(state, entry_uuid, cookie=None):
    value = SyncStateControlValue()
    value['state'] = SyncStateValue(state)
    value['entryUUID'] = OctetString(entry_uuid)
    if cookie is not None:
        value['cookie'] = OctetString(cookie)
    return build_control(SYNC_STATE_CONTROL, False, value)


def sync_entry(message_id, dn, attributes, state, entry_uuid, cookie=None):
    entry = SearchResultEntry()
    entry['object'] = LDAPDN(dn)
    attribute_list = PartialAttributeList()
    for position, (name, values) in enumerate(attributes.items()):
        partial_attribute = PartialAttribute()
        partial_attribute['type'] = AttributeDescription(name)
        vals = Vals()
        for value_position, value in enumerate(values):
            vals.setComponentByPosition(value_position, AttributeValue(value))
        partial_attribute['vals'] = vals
        attribute_list.setComponentByPosition(position, partial_attribute)
    entry['attributes'] = attribute_list
    return ldap_message(message_id, 'searchResEntry', entry, [sync_state_control(state, entry_uuid, cookie)])


def sync_info_message(message_id, info_value):
    response = IntermediateResponse()
    response['responseName'] = IntermediateResponseName(SYNC_INFO_MESSAGE)
    response['responseValue'] = IntermediateResponseValue(encode(info_value))
    return ldap_message(message_id, 'intermediateResponse', response)


def search_done(message_id, result_code=0, cookie=None, refresh_deletes=False, diagnostic=''):
    done = SearchResultDone()
    done['resultCode'] = ResultCode(result_code)
    done['matchedDN'] = LDAPDN('')
    done['diagnosticMessage'] = LDAPString(diagnostic)
    controls = None
    if cookie is not None or refresh_deletes:
        value = SyncDoneControlValue()
        if cookie is not None:
            value['cookie'] = OctetString(cookie)
        if refresh_deletes:
            value['refreshDeletes'] = Boolean(True)
        controls = [build_control(SYNC_DONE_CONTROL, False, value)]
    return ldap_message(message_id, 'searchResDone', done, controls)


def extract_sync_request(message):
    if not message['controls'].hasValue():
        return None
    for control in message['controls']:
        if str(control['controlType']) == SYNC_REQUEST_CONTROL:
            value, _ = decoder.decode(bytes(control['controlValue']), asn1Spec=SyncRequestControlValue())
            return {'mode': str(value['mode']),
                    'cookie': bytes(value['cookie']) if value['cookie'].hasValue() else None,
                    'reload_hint': bool(value['reloadHint']) if value['reloadHint'].hasValue() else False}
    return None


class ScriptedLdapPeer(threading.Thread):
    """A scripted fake LDAP server speaking BER over a real socket."""

    def __init__(self, on_search):
        threading.Thread.__init__(self)
        self.daemon = True
        self.on_search = on_search
        self.client_socket, self.server_socket = socket.socketpair()
        self.sync_requests = []
        self.error = None

    def run(self):
        conn = self.server_socket
        try:
            conn.settimeout(15)
            while True:
                raw = read_ldap_message(conn)
                if raw is None:
                    break
                message, _ = decoder.decode(raw, asn1Spec=LDAP_MESSAGE_TEMPLATE)
                message_id = int(message['messageID'])
                operation_name = message['protocolOp'].getName()
                if operation_name == 'bindRequest':
                    conn.sendall(bind_response(message_id))
                elif operation_name == 'unbindRequest':
                    break
                elif operation_name == 'abandonRequest':
                    continue
                elif operation_name == 'searchRequest':
                    self.sync_requests.append(extract_sync_request(message))
                    if not self.on_search(self, conn, message_id):
                        break  # drop the connection without a searchResDone
                else:
                    break
        except Exception as e:  # noqa
            self.error = e
        finally:
            try:
                conn.close()
            except OSError:
                pass


def make_connection(peer, fast_decoder=True):
    server = Server('127.0.0.1', get_info=NONE, connect_timeout=5)
    connection = Connection(server,
                            user='cn=admin,dc=example,dc=com',
                            password='password',
                            client_strategy=SYNC,
                            receive_timeout=10,
                            fast_decoder=fast_decoder)
    client_socket = peer.client_socket

    def _open_socket(strategy, address, use_ssl=False, unix_socket=False):
        # inject the pre-connected end of the socket pair instead of dialing out
        strategy.connection.socket = client_socket
        if strategy.connection.receive_timeout is not None:
            strategy.connection.socket.settimeout(strategy.connection.receive_timeout)
        strategy.connection.closed = False

    connection.strategy._open_socket = types.MethodType(_open_socket, connection.strategy)
    return connection


class Test(unittest.TestCase):
    def check_peer(self, peer):
        peer.join(timeout=5)
        if peer.error:
            raise peer.error

    def run_initial_sync(self, fast_decoder):
        def on_search(peer, conn, message_id):
            send_chunked(conn, sync_entry(message_id, 'uid=alice,' + TEST_BASE, {'uid': ['alice'], 'cn': ['Alice']}, 'present', b'uuid-1'))
            send_chunked(conn, sync_entry(message_id, 'uid=bob,' + TEST_BASE, {'uid': ['bob']}, 'present', b'uuid-2', cookie=b'cookie-1'))
            send_chunked(conn, sync_info_message(message_id, sync_info_refresh_present(cookie=b'cookie-2', refresh_done=True)))
            send_chunked(conn, search_done(message_id, cookie=b'cookie-3'))
            return True

        peer = ScriptedLdapPeer(on_search)
        peer.start()
        connection = make_connection(peer, fast_decoder=fast_decoder)
        sync = ContentSync(connection, TEST_BASE, mode='refreshOnly')
        collected = list(sync.events())
        sync.ack()

        self.assertEqual([event['type'] for event in collected], ['present', 'present', 'phase_end', 'sync_done'])
        self.assertEqual(collected[0]['entry_uuid'], 'uuid-1')
        self.assertEqual(collected[0]['dn'], 'uid=alice,' + TEST_BASE)
        self.assertEqual(collected[0]['attributes']['uid'], ['alice'])
        self.assertIsNone(collected[0]['cookie'])
        self.assertEqual(collected[1]['entry_uuid'], 'uuid-2')
        self.assertEqual(collected[1]['cookie'], b'cookie-1')
        self.assertEqual(collected[2]['phase'], 'present')
        self.assertEqual(collected[2]['cookie'], b'cookie-2')
        self.assertFalse(collected[3]['refresh_deletes'])
        self.assertEqual(collected[3]['cookie'], b'cookie-3')
        # no fabricated delete events for entries not seen in this refresh
        self.assertNotIn('delete', [event['type'] for event in collected])
        self.assertEqual(sync.cookie, b'cookie-3')
        self.assertFalse(sync.in_refresh)
        self.assertTrue(sync.done)
        self.assertEqual(peer.sync_requests[0]['mode'], 'refreshOnly')
        self.assertIsNone(peer.sync_requests[0]['cookie'])

        connection.unbind()
        self.check_peer(peer)

    def test_initial_sync_refresh_only_fast_decoder(self):
        self.run_initial_sync(fast_decoder=True)

    def test_initial_sync_refresh_only_pyasn1_decoder(self):
        self.run_initial_sync(fast_decoder=False)

    def test_refresh_and_persist_disconnect_reconnect(self):
        def on_search_a(peer, conn, message_id):
            send_chunked(conn, sync_entry(message_id, 'uid=alice,' + TEST_BASE, {'uid': ['alice']}, 'present', b'uuid-1', cookie=b'c1'))
            send_chunked(conn, sync_info_message(message_id, sync_info_refresh_present(cookie=b'c2', refresh_done=True)))
            send_chunked(conn, sync_info_message(message_id, sync_info_refresh_delete(refresh_done=False)))
            send_chunked(conn, sync_info_message(message_id, sync_info_id_set([b'uuid-8', b'uuid-9'], refresh_deletes=True, cookie=b'c3')))
            send_chunked(conn, sync_info_message(message_id, sync_info_refresh_delete(cookie=b'c4', refresh_done=True)))
            send_chunked(conn, sync_entry(message_id, 'uid=carol,' + TEST_BASE, {'uid': ['carol']}, 'add', b'uuid-2', cookie=b'c5'))
            return False  # simulate a broken connection: no searchResDone

        peer_a = ScriptedLdapPeer(on_search_a)
        peer_a.start()
        connection = make_connection(peer_a)
        sync = ContentSync(connection, TEST_BASE, mode='refreshAndPersist')
        events = sync.events()

        event = next(events)
        self.assertEqual(event['type'], 'present')
        self.assertEqual(event['entry_uuid'], 'uuid-1')
        sync.ack()
        self.assertEqual(sync.cookie, b'c1')

        event = next(events)
        self.assertEqual((event['type'], event['phase']), ('phase_end', 'present'))
        sync.ack()
        self.assertEqual(sync.cookie, b'c2')

        event = next(events)
        self.assertEqual((event['type'], event['phase']), ('phase_begin', 'delete'))
        sync.ack()

        event = next(events)
        self.assertEqual(event['type'], 'id_set')
        self.assertEqual(event['phase'], 'delete')
        self.assertEqual(event['entry_uuids'], ['uuid-8', 'uuid-9'])
        sync.ack()
        self.assertEqual(sync.cookie, b'c3')

        event = next(events)
        self.assertEqual((event['type'], event['phase']), ('phase_end', 'delete'))
        sync.ack()

        event = next(events)
        self.assertEqual(event['type'], 'persist_begin')
        self.assertFalse(sync.in_refresh)
        sync.ack()
        self.assertEqual(sync.cookie, b'c4')

        # the add event is delivered but not acknowledged by the caller
        event = next(events)
        self.assertEqual(event['type'], 'add')
        self.assertEqual(event['entry_uuid'], 'uuid-2')
        self.assertEqual(event['cookie'], b'c5')
        self.assertEqual(sync.cookie, b'c4')

        with self.assertRaises(LDAPSocketReceiveError):
            next(events)
        # the resumable cookie must not have moved past the unacknowledged event
        self.assertEqual(sync.cookie, b'c4')
        self.check_peer(peer_a)

        # reconnect and resume from the last acknowledged cookie
        def on_search_b(peer, conn, message_id):
            send_chunked(conn, sync_entry(message_id, 'uid=alice,' + TEST_BASE, {'uid': ['alice'], 'description': ['changed']}, 'modify', b'uuid-1', cookie=b'c6'))
            send_chunked(conn, sync_info_message(message_id, sync_info_newcookie(b'c7')))
            send_chunked(conn, search_done(message_id, cookie=b'c8'))
            return True

        peer_b = ScriptedLdapPeer(on_search_b)
        peer_b.start()
        connection2 = make_connection(peer_b)
        sync2 = ContentSync(connection2, TEST_BASE, mode='refreshAndPersist', cookie=sync.cookie)
        collected = list(sync2.events())
        sync2.ack()

        self.assertEqual([event['type'] for event in collected], ['persist_begin', 'modify', 'new_cookie', 'sync_done'])
        self.assertEqual(collected[1]['entry_uuid'], 'uuid-1')
        self.assertEqual(collected[1]['attributes']['description'], ['changed'])
        self.assertEqual(collected[2]['cookie'], b'c7')
        self.assertEqual(sync2.cookie, b'c8')
        # the resumed session must present the last acknowledged cookie to the server
        self.assertEqual(peer_b.sync_requests[0]['mode'], 'refreshAndPersist')
        self.assertEqual(peer_b.sync_requests[0]['cookie'], b'c4')

        connection2.unbind()
        self.check_peer(peer_b)

    def test_refresh_required(self):
        def on_search(peer, conn, message_id):
            send_chunked(conn, search_done(message_id, result_code=4096, cookie=b'useless-cookie', diagnostic='sync cookie is stale'))
            return True

        peer = ScriptedLdapPeer(on_search)
        peer.start()
        connection = make_connection(peer)
        sync = ContentSync(connection, TEST_BASE, mode='refreshOnly', cookie=b'stale-cookie')
        collected = list(sync.events())

        self.assertEqual(len(collected), 1)
        self.assertEqual(collected[0]['type'], 'refresh_required')
        self.assertEqual(collected[0]['result'], 4096)
        # the stored cookie is no longer usable, a full re-refresh is needed
        self.assertIsNone(sync.cookie)
        self.assertTrue(sync.done)
        self.assertEqual(peer.sync_requests[0]['cookie'], b'stale-cookie')

        connection.unbind()
        self.check_peer(peer)


if __name__ == '__main__':
    unittest.main()
