# Created on 2026.09.25
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
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

import socket
import threading
import time
import unittest

from ldap3 import Server, Connection, MODIFY_REPLACE, SYNC, ASYNC, NONE, AUTO_BIND_NONE
from ldap3.core.exceptions import LDAPTransactionError
from ldap3.core.results import RESULT_SUCCESS
from ldap3.protocol.convert import build_controls_list
from ldap3.protocol.rfc4511 import LDAPMessage, MessageID, ProtocolOp, BindResponse, AddResponse, DelResponse, ModifyResponse, ModifyDNResponse, SearchResultDone, ExtendedResponse, ResultCode, LDAPDN, LDAPString, ResponseName, ResponseValue
from ldap3.protocol.rfc5805 import START_TRANSACTION_REQUEST_NAME, TRANSACTION_SPECIFICATION_CONTROL, END_TRANSACTION_REQUEST_NAME, ABORTED_TRANSACTION_NOTICE, TransactionIdentifier, EndTransactionRequestValue, EndTransactionResponseValue
from ldap3.strategy.base import BaseStrategy
from ldap3.utils.asn1 import decoder, encode

RESULT_UNWILLING_TO_PERFORM = 53
UPDATE_REQUEST_TYPES = ['addRequest', 'modifyRequest', 'delRequest', 'modDNRequest']


class Rfc5805FakeServer(threading.Thread):
    """A minimal local LDAP protocol stand-in that speaks RFC5805 transactions.

    Communicates with the client over a socketpair, no network listener is needed.
    """

    def __init__(self, server_socket):
        threading.Thread.__init__(self)
        self.daemon = True
        self._socket = server_socket
        self.transaction_id = b'fake-rfc5805-transaction-id'
        self.requests = []  # every received request as a dict
        self.end_transaction_requests = []
        self.fail_commit = False  # fail the commit with a failed messageID and a per-operation response control
        self.abort_on_end_transaction = False  # answer the End Transaction request with an Aborted Transaction Notice
        self.abort_after_modify = False  # send an Aborted Transaction Notice right after a modifyResponse
        self.per_operation_control = ('1.2.3.4', False, b'per-operation-response-control')
        self._stopped = False

    def run(self):
        unprocessed = b''
        while not self._stopped:
            try:
                data = self._socket.recv(4096)
            except OSError:
                break
            if not data:
                break
            unprocessed += data
            while True:
                length = BaseStrategy.compute_ldap_message_size(unprocessed)
                if length == -1 or len(unprocessed) < length:
                    break
                raw_message = unprocessed[:length]
                unprocessed = unprocessed[length:]
                ldap_message = decoder.decode(raw_message, asn1Spec=LDAPMessage())[0]
                self._handle(ldap_message)
        try:
            self._socket.close()
        except OSError:
            pass

    def stop(self):
        self._stopped = True
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass

    def message_id_of(self, message_type):
        for request in self.requests:
            if request['type'] == message_type:
                return request['message_id']
        return None

    def requests_of(self, message_type):
        return [request for request in self.requests if request['type'] == message_type]

    def _handle(self, ldap_message):
        message_id = int(ldap_message['messageID'])
        message_type = ldap_message['protocolOp'].getName()
        component = ldap_message['protocolOp'].getComponent()
        controls = dict()
        if ldap_message['controls'].hasValue():
            for control in ldap_message['controls']:
                controls[str(control['controlType'])] = {'criticality': bool(control['criticality']), 'value': bytes(control['controlValue'])}
        self.requests.append({'message_id': message_id, 'type': message_type, 'controls': controls})

        if message_type == 'bindRequest':
            self._send(message_id, 'bindResponse', BindResponse())
        elif message_type == 'extendedReq':
            request_name = str(component['requestName'])
            if request_name == START_TRANSACTION_REQUEST_NAME:
                response = ExtendedResponse()
                response['responseValue'] = ResponseValue(encode(TransactionIdentifier(self.transaction_id)))
                self._send(message_id, 'extendedResp', response)
            elif request_name == END_TRANSACTION_REQUEST_NAME:
                end_request = decoder.decode(bytes(component['requestValue']), asn1Spec=EndTransactionRequestValue())[0]
                end_transaction = {'message_id': message_id, 'identifier': bytes(end_request['identifier']), 'commit': bool(end_request['commit'])}
                self.end_transaction_requests.append(end_transaction)
                if self.abort_on_end_transaction:
                    self._send_aborted_transaction_notice()
                elif self.fail_commit and end_transaction['commit']:
                    response = ExtendedResponse()
                    response_value = EndTransactionResponseValue()
                    response_value['messageID'] = self.message_id_of('modifyRequest')
                    response['responseValue'] = ResponseValue(encode(response_value))
                    self._send(message_id, 'extendedResp', response, result_code=RESULT_UNWILLING_TO_PERFORM, controls=[self.per_operation_control])
                else:
                    self._send(message_id, 'extendedResp', ExtendedResponse())
        elif message_type == 'addRequest':
            self._send(message_id, 'addResponse', AddResponse())
        elif message_type == 'delRequest':
            self._send(message_id, 'delResponse', DelResponse())
        elif message_type == 'modifyRequest':
            self._send(message_id, 'modifyResponse', ModifyResponse())
            if self.abort_after_modify:
                self._send_aborted_transaction_notice()
        elif message_type == 'modDNRequest':
            self._send(message_id, 'modDNResponse', ModifyDNResponse())
        elif message_type == 'searchRequest':
            self._send(message_id, 'searchResDone', SearchResultDone())
        elif message_type == 'unbindRequest':
            self._stopped = True

    def _send(self, message_id, component_name, component, result_code=0, diagnostic='', controls=None):
        component['resultCode'] = ResultCode(result_code)
        component['matchedDN'] = LDAPDN('')
        component['diagnosticMessage'] = LDAPString(diagnostic)
        message = LDAPMessage()
        message['messageID'] = MessageID(message_id)
        message['protocolOp'] = ProtocolOp().setComponentByName(component_name, component)
        if controls:
            message['controls'] = build_controls_list(controls)
        self._socket.sendall(encode(message))

    def _send_aborted_transaction_notice(self):
        response = ExtendedResponse()
        response['responseName'] = ResponseName(ABORTED_TRANSACTION_NOTICE)
        self._send(0, 'extendedResp', response, result_code=RESULT_UNWILLING_TO_PERFORM)


class Test(unittest.TestCase):
    def setUp(self):
        self.connection = None
        self.client_socket, server_socket = socket.socketpair()
        self.server = Rfc5805FakeServer(server_socket)
        self.server.start()

    def tearDown(self):
        if self.connection is not None and self.connection.bound:
            self.connection.unbind()
        self.server.stop()
        self.server.join(5)

    def get_connection(self, strategy=SYNC):
        server = Server('localhost', get_info=NONE)  # the socket is injected, no real connection is opened
        connection = Connection(server, 'cn=admin,o=test', 'password', client_strategy=strategy, auto_bind=AUTO_BIND_NONE, receive_timeout=5)
        connection.socket = self.client_socket
        connection.closed = False
        connection.strategy._outstanding = dict()
        if strategy == ASYNC:
            connection.strategy._responses = dict()
            connection.strategy._requests = dict()
        connection.strategy._start_listen()
        connection.bind(read_server_info=False)
        self.connection = connection
        return self.connection

    def assert_transaction_control(self, request):
        self.assertIn(TRANSACTION_SPECIFICATION_CONTROL, request['controls'])
        control = request['controls'][TRANSACTION_SPECIFICATION_CONTROL]
        self.assertTrue(control['criticality'])
        transaction_id = decoder.decode(control['value'], asn1Spec=TransactionIdentifier())[0]
        self.assertEqual(bytes(transaction_id), self.server.transaction_id)

    def test_sync_commit_transaction(self):
        connection = self.get_connection()
        with connection.extend.standard.transaction() as transaction:
            transaction.add('cn=user1,o=test', 'inetOrgPerson', {'sn': 'user1'})
            transaction.modify('cn=user1,o=test', {'givenName': (MODIFY_REPLACE, ['user1b'])})
            transaction.delete('cn=user2,o=test')
            transaction.modify_dn('cn=user1,o=test', 'cn=user1-renamed')
            self.assertTrue(transaction.commit())
        self.assertTrue(transaction.committed)
        self.assertFalse(transaction.active)
        self.assertEqual(transaction.transaction_id, self.server.transaction_id)
        self.assertEqual(len(self.server.end_transaction_requests), 1)
        self.assertTrue(self.server.end_transaction_requests[0]['commit'])
        self.assertEqual(self.server.end_transaction_requests[0]['identifier'], self.server.transaction_id)
        for request_type in UPDATE_REQUEST_TYPES:
            requests = self.server.requests_of(request_type)
            self.assertEqual(len(requests), 1)
            self.assert_transaction_control(requests[0])

    def test_sync_explicit_abort(self):
        connection = self.get_connection()
        transaction = connection.extend.standard.transaction()
        transaction.start()
        transaction.add('cn=user1,o=test', 'inetOrgPerson', {'sn': 'user1'})
        transaction.abort()
        self.assertTrue(transaction.aborted)
        self.assertFalse(transaction.active)
        self.assertEqual(len(self.server.end_transaction_requests), 1)
        self.assertFalse(self.server.end_transaction_requests[0]['commit'])
        self.assertRaises(LDAPTransactionError, transaction.add, 'cn=user2,o=test', 'inetOrgPerson', {'sn': 'user2'})
        self.assertRaises(LDAPTransactionError, transaction.commit)

    def test_sync_exception_in_context_aborts_transaction(self):
        connection = self.get_connection()

        def raise_inside_transaction():
            with connection.extend.standard.transaction() as transaction:
                transaction.add('cn=user1,o=test', 'inetOrgPerson', {'sn': 'user1'})
                raise ValueError('simulated failure')

        self.assertRaises(ValueError, raise_inside_transaction)
        self.assertEqual(len(self.server.end_transaction_requests), 1)
        self.assertFalse(self.server.end_transaction_requests[0]['commit'])

    def test_sync_aborted_transaction_notice(self):
        self.server.abort_on_end_transaction = True
        connection = self.get_connection()
        transaction = connection.extend.standard.transaction()
        transaction.start()
        transaction.add('cn=user1,o=test', 'inetOrgPerson', {'sn': 'user1'})
        self.assertRaises(LDAPTransactionError, transaction.commit)
        self.assertTrue(transaction.aborted)
        self.assertTrue(transaction.server_aborted)
        self.assertFalse(transaction.active)
        self.assertRaises(LDAPTransactionError, transaction.add, 'cn=user2,o=test', 'inetOrgPerson', {'sn': 'user2'})

    def test_sync_commit_failure_reports_failed_message_id(self):
        self.server.fail_commit = True
        connection = self.get_connection()
        transaction = connection.extend.standard.transaction()
        transaction.start()
        transaction.add('cn=user1,o=test', 'inetOrgPerson', {'sn': 'user1'})
        transaction.modify('cn=user1,o=test', {'givenName': (MODIFY_REPLACE, ['user1b'])})
        committed = transaction.commit()
        self.assertFalse(committed)
        self.assertFalse(transaction.committed)
        self.assertEqual(transaction.failed_message_id, self.server.message_id_of('modifyRequest'))
        self.assertEqual(transaction.failed_operation['type'], 'modifyRequest')
        self.assertEqual(transaction.failed_operation['dn'], 'cn=user1,o=test')
        self.assertIn('1.2.3.4', transaction.result['controls'])
        self.assertEqual(transaction.result['controls']['1.2.3.4']['value'], b'per-operation-response-control')

    def test_sync_transaction_control_not_leaked_to_other_requests(self):
        connection = self.get_connection()
        connection.search('o=test', '(objectClass=*)', attributes=['cn'])
        with connection.extend.standard.transaction() as transaction:
            transaction.add('cn=user1,o=test', 'inetOrgPerson', {'sn': 'user1'}, controls=[('1.2.3.4', False, b'user-control')])
            transaction.commit()
        connection.delete('cn=user1,o=test')
        search_request = self.server.requests_of('searchRequest')[0]
        self.assertEqual(search_request['controls'], dict())
        add_request = self.server.requests_of('addRequest')[0]
        self.assert_transaction_control(add_request)
        self.assertEqual(add_request['controls']['1.2.3.4']['value'], b'user-control')
        delete_request = self.server.requests_of('delRequest')[0]
        self.assertEqual(delete_request['controls'], dict())

    def test_async_commit_transaction(self):
        connection = self.get_connection(ASYNC)
        transaction = connection.extend.standard.transaction()
        transaction.start()
        add_message_id = transaction.add('cn=user1,o=test', 'inetOrgPerson', {'sn': 'user1'})
        modify_message_id = transaction.modify('cn=user1,o=test', {'givenName': (MODIFY_REPLACE, ['user1b'])})
        self.assertIn(add_message_id, transaction.operations)
        self.assertIn(modify_message_id, transaction.operations)
        _, result = connection.get_response(add_message_id)
        self.assertEqual(result['result'], RESULT_SUCCESS)
        _, result = connection.get_response(modify_message_id)
        self.assertEqual(result['result'], RESULT_SUCCESS)
        self.assertTrue(transaction.commit())
        self.assertTrue(transaction.committed)
        self.assertEqual(len(self.server.end_transaction_requests), 1)
        self.assertTrue(self.server.end_transaction_requests[0]['commit'])
        for request_type in ['addRequest', 'modifyRequest']:
            self.assert_transaction_control(self.server.requests_of(request_type)[0])

    def test_async_aborted_transaction_notice(self):
        self.server.abort_after_modify = True
        connection = self.get_connection(ASYNC)
        transaction = connection.extend.standard.transaction()
        transaction.start()
        modify_message_id = transaction.modify('cn=user1,o=test', {'givenName': (MODIFY_REPLACE, ['user1b'])})
        _, result = connection.get_response(modify_message_id)
        self.assertEqual(result['result'], RESULT_SUCCESS)
        for _ in range(50):  # waits for the Aborted Transaction Notice to be processed by the receiver thread
            if transaction.aborted:
                break
            time.sleep(0.1)
        self.assertTrue(transaction.aborted)
        self.assertTrue(transaction.server_aborted)
        self.assertRaises(LDAPTransactionError, transaction.commit)


if __name__ == '__main__':
    unittest.main()
