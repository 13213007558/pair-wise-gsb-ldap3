"""
"""

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

# a minimal in-process LDAP server speaking RFC5805 transactions, used as a
# local protocol stand-in for tests (no real directory server needed);
# clients reach it through socketpair() channels, so no network access is needed

import socket
import threading

from copy import deepcopy

from pyasn1.type.univ import OctetString

from ldap3.protocol.rfc4511 import LDAPMessage, ProtocolOp, MessageID, ResultCode, LDAPDN, LDAPString, BindResponse, AddRequest, DelRequest, ModifyRequest, ModifyDNRequest, AddResponse, DelResponse, ModifyResponse, ModifyDNResponse, ExtendedResponse, ResponseName, ResponseValue, Control
from ldap3.protocol.rfc5805 import START_TRANSACTION_OID, TRANSACTION_SPECIFICATION_OID, END_TRANSACTION_OID, ABORTED_TRANSACTION_NOTICE_OID, TxnEndRequestValue, TxnEndResponseValue, UpdateControlsSequence, UpdateControlEntry, UpdateControls, TransactionIdentifier
from ldap3.strategy.base import BaseStrategy
from ldap3.utils.asn1 import encode, decoder

RESULT_SUCCESS = 0
RESULT_PROTOCOL_ERROR = 2
RESULT_NO_SUCH_OBJECT = 32
RESULT_UNWILLING_TO_PERFORM = 53
RESULT_ENTRY_ALREADY_EXISTS = 68

ABORT_TRIGGER_VALUE = 'trigger-server-abort'  # an add containing description=trigger-server-abort aborts the transaction server-side
UPDATE_MARKER_CONTROL = '2.16.840.1.113730.3.4.2'  # ManageDsaIT, echoed back in the End Transaction response update controls


class RFC5805FakeServer(object):
    """
    A fake LDAP server with one thread per client channel.
    Update operations received with a Transaction Specification control are
    recorded and applied atomically when the End Transaction request commits;
    operations without the control are applied immediately. The received
    requests are logged in self.received as (message_id, operation, txn_id).
    """

    def __init__(self):
        self.dit = dict()  # dn -> {attribute: [values]}
        self.transactions = dict()  # txn_id -> [(message_id, operation, request)]
        self.aborted_transactions = set()
        self.received = []  # (message_id, operation, txn_id or None) for update requests
        self.received_controls = dict()  # message_id -> [control oids] for every request
        self.end_requests = []  # (txn_id, commit) for End Transaction requests
        self._txn_counter = 0
        self._sockets = []
        self.lock = threading.Lock()

    def open_channel(self):
        # returns the client end of a new socketpair connected to this fake server
        client_socket, server_socket = socket.socketpair()
        self._sockets.append(client_socket)
        self._sockets.append(server_socket)
        worker = threading.Thread(target=self._serve, args=(server_socket,))
        worker.daemon = True
        worker.start()
        return client_socket

    def stop(self):
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass

    def _serve(self, connection):
        buffer = b''
        try:
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                buffer += data
                while len(buffer) > 2:
                    size = BaseStrategy.compute_ldap_message_size(buffer)
                    if size == -1 or len(buffer) < size:
                        break
                    raw_message, buffer = buffer[:size], buffer[size:]
                    message, _ = decoder.decode(raw_message, asn1Spec=LDAPMessage())
                    response = self._handle(message, connection)
                    if response is not None:
                        connection.sendall(response)
        except OSError:
            pass
        finally:
            try:
                connection.close()
            except OSError:
                pass

    @staticmethod
    def _result_message(message_id, operation_name, component, result_code, diagnostic_message=''):
        component['resultCode'] = ResultCode(result_code)
        component['matchedDN'] = LDAPDN('')
        component['diagnosticMessage'] = LDAPString(diagnostic_message)
        message = LDAPMessage()
        message['messageID'] = MessageID(message_id)
        message['protocolOp'] = ProtocolOp().setComponentByName(operation_name, component)
        return encode(message)

    @staticmethod
    def _extract_transaction_id(message):
        controls = message['controls']
        if controls is not None and controls.hasValue():
            for control in controls:
                if str(control['controlType']) == TRANSACTION_SPECIFICATION_OID:
                    return bytes(decoder.decode(bytes(control['controlValue']), asn1Spec=OctetString())[0])
        return None

    def _handle(self, message, connection):
        message_id = int(message['messageID'])
        operation_name = message['protocolOp'].getName()
        request = message['protocolOp'].getComponent()
        controls = message['controls']
        self.received_controls[message_id] = [str(control['controlType']) for control in controls] if controls is not None and controls.hasValue() else []
        txn_id = self._extract_transaction_id(message)
        if operation_name in ('addRequest', 'delRequest', 'modifyRequest', 'modDNRequest'):
            self.received.append((message_id, operation_name, txn_id))
            return self._update(message_id, operation_name, request, txn_id, connection)
        if operation_name == 'bindRequest':
            return self._result_message(message_id, 'bindResponse', BindResponse(), RESULT_SUCCESS)
        if operation_name == 'unbindRequest':
            return None
        if operation_name == 'extendedReq':
            request_name = str(request['requestName'])
            if request_name == START_TRANSACTION_OID:
                return self._start_transaction(message_id)
            if request_name == END_TRANSACTION_OID:
                return self._end_transaction(message_id, request)
            return self._result_message(message_id, 'extendedResp', ExtendedResponse(), RESULT_PROTOCOL_ERROR, 'unknown extended request')
        return None

    def _start_transaction(self, message_id):
        with self.lock:
            self._txn_counter += 1
            txn_id = ('txn-%d' % self._txn_counter).encode('utf-8')
            self.transactions[txn_id] = []
        response = ExtendedResponse()
        response['responseName'] = ResponseName(START_TRANSACTION_OID)
        response['responseValue'] = ResponseValue(encode(TransactionIdentifier(txn_id)))
        return self._result_message(message_id, 'extendedResp', response, RESULT_SUCCESS)

    def _end_transaction(self, message_id, request):
        value, _ = decoder.decode(bytes(request['requestValue']), asn1Spec=TxnEndRequestValue())
        commit = bool(value['commit'])
        txn_id = bytes(value['identifier'])
        self.end_requests.append((txn_id, commit))
        response = ExtendedResponse()
        response['responseName'] = ResponseName(END_TRANSACTION_OID)
        if txn_id in self.aborted_transactions:
            self.transactions.pop(txn_id, None)
            return self._result_message(message_id, 'extendedResp', response, RESULT_UNWILLING_TO_PERFORM, 'transaction aborted')
        operations = self.transactions.pop(txn_id, None)
        if operations is None:
            return self._result_message(message_id, 'extendedResp', response, RESULT_PROTOCOL_ERROR, 'unknown transaction identifier')
        if not commit:
            return self._result_message(message_id, 'extendedResp', response, RESULT_SUCCESS)
        new_dit = deepcopy(self.dit)
        applied = []  # message ids of the updates successfully applied
        for op_message_id, operation_name, encoded_request in operations:
            op_request = self._decode_update_request(operation_name, encoded_request)
            result_code = self._apply(new_dit, operation_name, op_request)
            if result_code != RESULT_SUCCESS:
                end_value = TxnEndResponseValue()
                end_value['messageID'] = op_message_id
                end_value['updateControls'] = self._build_update_controls(applied)
                response['responseValue'] = ResponseValue(encode(end_value))
                return self._result_message(message_id, 'extendedResp', response, result_code, 'transaction update failed')
            applied.append(op_message_id)
        self.dit = new_dit
        end_value = TxnEndResponseValue()
        end_value['updateControls'] = self._build_update_controls(applied)
        response['responseValue'] = ResponseValue(encode(end_value))
        return self._result_message(message_id, 'extendedResp', response, RESULT_SUCCESS)

    @staticmethod
    def _build_update_controls(message_ids):
        update_controls = UpdateControlsSequence()
        for position, message_id in enumerate(message_ids):
            control = Control()
            control['controlType'] = UPDATE_MARKER_CONTROL
            control['controlValue'] = b'applied'
            controls = UpdateControls()
            controls.setComponentByPosition(0, control)
            entry = UpdateControlEntry()
            entry['messageID'] = message_id
            entry['controls'] = controls
            update_controls.setComponentByPosition(position, entry)
        return update_controls

    def _update(self, message_id, operation_name, request, txn_id, connection):
        response_name = {'addRequest': ('addResponse', AddResponse()),
                         'delRequest': ('delResponse', DelResponse()),
                         'modifyRequest': ('modifyResponse', ModifyResponse()),
                         'modDNRequest': ('modDNResponse', ModifyDNResponse())}[operation_name]
        if txn_id is None:  # not part of a transaction, applied immediately
            result_code = self._apply(self.dit, operation_name, request)
            return self._result_message(message_id, response_name[0], response_name[1], result_code)
        if txn_id not in self.transactions or txn_id in self.aborted_transactions:
            return self._result_message(message_id, response_name[0], response_name[1], RESULT_UNWILLING_TO_PERFORM, 'invalid transaction')
        if operation_name == 'addRequest' and self._is_abort_trigger(request):
            self.aborted_transactions.add(txn_id)
            connection.sendall(self._aborted_transaction_notice(txn_id))  # unsolicited notice sent before the response
            return self._result_message(message_id, response_name[0], response_name[1], RESULT_UNWILLING_TO_PERFORM, 'transaction aborted by server')
        self.transactions[txn_id].append((message_id, operation_name, encode(request)))  # request is decoded again at commit time
        return self._result_message(message_id, response_name[0], response_name[1], RESULT_SUCCESS)

    @staticmethod
    def _decode_update_request(operation_name, encoded_request):
        request_spec = {'addRequest': AddRequest(), 'delRequest': DelRequest(), 'modifyRequest': ModifyRequest(), 'modDNRequest': ModifyDNRequest()}[operation_name]
        request, _ = decoder.decode(encoded_request, asn1Spec=request_spec)
        return request

    @staticmethod
    def _is_abort_trigger(request):
        for attribute in request['attributes']:
            if str(attribute['type']).lower() == 'description':
                for value in attribute['vals']:
                    if str(value) == ABORT_TRIGGER_VALUE:
                        return True
        return False

    @staticmethod
    def _aborted_transaction_notice(txn_id):
        response = ExtendedResponse()
        response['responseName'] = ResponseName(ABORTED_TRANSACTION_NOTICE_OID)
        response['responseValue'] = ResponseValue(encode(TransactionIdentifier(txn_id)))
        return RFC5805FakeServer._result_message(0, 'extendedResp', response, RESULT_UNWILLING_TO_PERFORM, 'transaction aborted')

    @staticmethod
    def _apply(dit, operation_name, request):
        if operation_name == 'addRequest':
            dn = str(request['entry'])
            if dn in dit:
                return RESULT_ENTRY_ALREADY_EXISTS
            attributes = dict()
            for attribute in request['attributes']:
                attributes[str(attribute['type'])] = [str(value) for value in attribute['vals']]
            dit[dn] = attributes
            return RESULT_SUCCESS
        if operation_name == 'delRequest':
            dn = str(request)
            if dn not in dit:
                return RESULT_NO_SUCH_OBJECT
            del dit[dn]
            return RESULT_SUCCESS
        if operation_name == 'modifyRequest':
            dn = str(request['object'])
            if dn not in dit:
                return RESULT_NO_SUCH_OBJECT
            for change in request['changes']:
                operation = int(change['operation'])
                attribute_name = str(change['modification']['type'])
                values = [str(value) for value in change['modification']['vals']]
                if operation == 0:  # add
                    dit[dn].setdefault(attribute_name, []).extend(values)
                elif operation == 1:  # delete
                    if values:
                        dit[dn][attribute_name] = [value for value in dit[dn].get(attribute_name, []) if value not in values]
                    else:
                        dit[dn].pop(attribute_name, None)
                elif operation == 2:  # replace
                    dit[dn][attribute_name] = values
            return RESULT_SUCCESS
        if operation_name == 'modDNRequest':
            dn = str(request['entry'])
            if dn not in dit:
                return RESULT_NO_SUCH_OBJECT
            new_rdn = str(request['newrdn'])
            if request['newSuperior'].hasValue():
                new_dn = new_rdn + ',' + str(request['newSuperior'])
            else:
                new_dn = new_rdn + ',' + ','.join(dn.split(',')[1:])
            dit[new_dn] = dit.pop(dn)
            if bool(request['deleteoldrdn']):
                old_rdn_attr, _, old_rdn_value = dn.split(',')[0].partition('=')
                if old_rdn_attr in dit[new_dn] and old_rdn_value in dit[new_dn][old_rdn_attr]:
                    dit[new_dn][old_rdn_attr].remove(old_rdn_value)
            return RESULT_SUCCESS
        return RESULT_PROTOCOL_ERROR
