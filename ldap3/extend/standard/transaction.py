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

# Implements LDAP Transactions as per RFC5805

from ...core.exceptions import LDAPTransactionError, LDAPExtensionError
from ...core.results import RESULT_SUCCESS
from ...extend.operation import ExtendedOperation
from ...protocol.controls import build_control
from ...protocol.rfc5805 import START_TRANSACTION_REQUEST_NAME, TRANSACTION_SPECIFICATION_CONTROL, END_TRANSACTION_REQUEST_NAME, TransactionIdentifier, EndTransactionRequestValue, EndTransactionResponseValue
from ...utils.asn1 import decoder


class StartTransaction(ExtendedOperation):
    def config(self):
        self.request_name = START_TRANSACTION_REQUEST_NAME
        self.response_name = None  # the responseName is absent in the Start Transaction Response as per RFC5805
        self.request_value = None  # the requestValue is absent in the Start Transaction Request as per RFC5805
        self.asn1_spec = TransactionIdentifier()

    def populate_result(self):
        self.result['transaction_id'] = bytes(self.decoded_response) if self.decoded_response is not None else None

    def set_response(self):
        self.response_value = self.result['transaction_id'] if self.result else None
        if not self.connection.strategy.thread_safe:
            self.connection.response = self.response_value


class EndTransaction(ExtendedOperation):
    def config(self):
        self.request_name = END_TRANSACTION_REQUEST_NAME
        self.response_name = None  # the responseName is absent in the End Transaction Response as per RFC5805
        self.request_value = EndTransactionRequestValue()
        self.asn1_spec = EndTransactionResponseValue()

    def __init__(self, connection, transaction_id, commit=True, controls=None):
        ExtendedOperation.__init__(self, connection, controls)  # calls super __init__()
        self.request_value['identifier'] = TransactionIdentifier(transaction_id)
        self.request_value['commit'] = commit

    def decode_response(self, response=None):
        # the End Transaction Response can carry a responseValue even when the result is not success
        # (it holds the messageID of the failed update request) so it is decoded regardless of the result code
        if not response:
            response = self.result
        if not response:
            return None
        if response['responseValue']:
            decoded, unprocessed = decoder.decode(response['responseValue'], asn1Spec=self.asn1_spec)
            if unprocessed:
                raise LDAPExtensionError('error decoding extended response value')
            self.decoded_response = decoded

    def populate_result(self):
        self.result['failed_message_id'] = None
        if self.decoded_response is not None and self.decoded_response['messageID'].hasValue():
            self.result['failed_message_id'] = int(self.decoded_response['messageID'])

    def set_response(self):
        self.response_value = self.result['failed_message_id'] if self.result else None
        if not self.connection.strategy.thread_safe:
            self.connection.response = self.response_value


class Transaction(object):
    """Context manager for RFC5805 LDAP transactions.

    Usage::

        with connection.extend.standard.transaction() as transaction:
            transaction.add('cn=user1,o=test', 'inetOrgPerson', {'sn': 'user1'})
            transaction.modify('cn=user2,o=test', {'givenName': (MODIFY_REPLACE, ['user2'])})
            transaction.commit()  # or transaction.abort()

    If the with-block is exited with an exception and the transaction has not been
    committed yet, an abort (End Transaction with commit=FALSE) is automatically sent.

    The Transaction Specification Control is attached only to the requests issued
    through this object, it never leaks to unrelated requests on the same connection.
    """

    def __init__(self, connection, controls=None):
        self.connection = connection
        self.controls = controls
        self.transaction_id = None
        self.active = False
        self.committed = False
        self.aborted = False
        self.server_aborted = False
        self.failed_message_id = None
        self.operations = dict()  # message_id -> operation description, for failed operation attribution
        self.result = None

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.active and not self.committed and not self.aborted:
            try:
                self.abort()
            except LDAPTransactionError:
                pass
        return False  # never swallow exceptions from the with-block

    def start(self):
        if self.active:
            raise LDAPTransactionError('transaction already started')
        self.transaction_id = StartTransaction(self.connection, self.controls).send()
        if not self.transaction_id:
            raise LDAPTransactionError('unable to start transaction')
        self.active = True
        self.connection._rfc5805_transaction = self  # register to be notified of an Aborted Transaction Notice
        return self

    def commit(self, controls=None):
        self._check_active()
        operation = EndTransaction(self.connection, self.transaction_id, commit=True, controls=controls)
        try:
            operation.send()
        finally:
            self._close()
        self.result = operation.result
        self.committed = self.result['result'] == RESULT_SUCCESS
        self.failed_message_id = self.result.get('failed_message_id')
        return self.committed

    def abort(self, controls=None):
        self._check_active()
        operation = EndTransaction(self.connection, self.transaction_id, commit=False, controls=controls)
        try:
            operation.send()
        finally:
            self.aborted = True
            self._close()
        self.result = operation.result
        return True

    @property
    def failed_operation(self):
        # description of the update request that caused the commit to fail, if reported by the server
        if self.failed_message_id is not None:
            return self.operations.get(self.failed_message_id)
        return None

    def add(self, dn, object_class=None, attributes=None, controls=None):
        self._check_active()
        result = self.connection.add(dn, object_class, attributes, controls=self._transaction_controls(controls))
        self._record_operation('addRequest', dn, result)
        return result

    def modify(self, dn, changes, controls=None):
        self._check_active()
        result = self.connection.modify(dn, changes, controls=self._transaction_controls(controls))
        self._record_operation('modifyRequest', dn, result)
        return result

    def delete(self, dn, controls=None):
        self._check_active()
        result = self.connection.delete(dn, controls=self._transaction_controls(controls))
        self._record_operation('delRequest', dn, result)
        return result

    def modify_dn(self, dn, relative_dn, delete_old_dn=True, new_superior=None, controls=None):
        self._check_active()
        result = self.connection.modify_dn(dn, relative_dn, delete_old_dn, new_superior, controls=self._transaction_controls(controls))
        self._record_operation('modDNRequest', dn, result)
        return result

    def _transaction_controls(self, controls):
        # builds a fresh control list for each request so that the Transaction Specification
        # Control is never shared with (or leaked to) unrelated requests on this connection
        transaction_control = build_control(TRANSACTION_SPECIFICATION_CONTROL, True, TransactionIdentifier(self.transaction_id), encode_control_value=True)
        if controls:
            return [transaction_control] + list(controls)
        return [transaction_control]

    def _check_active(self):
        if self.server_aborted:
            raise LDAPTransactionError('transaction aborted by server')
        if not self.active:
            raise LDAPTransactionError('transaction not active')

    def _record_operation(self, operation_type, dn, result):
        if self.connection.strategy.sync:  # synchronous strategies, the message id of the last sent request is tracked by the connection
            message_id = self.connection.last_message_id
        elif isinstance(result, int):  # asynchronous strategies return the message id
            message_id = result
        else:
            message_id = None
        if message_id is not None:
            self.operations[message_id] = {'type': operation_type, 'dn': dn}

    def _notify_aborted(self):
        # called by the connection strategy when an Aborted Transaction Notice is received
        self.aborted = True
        self.server_aborted = True
        self.active = False
        if getattr(self.connection, '_rfc5805_transaction', None) is self:
            self.connection._rfc5805_transaction = None

    def _close(self):
        self.active = False
        if getattr(self.connection, '_rfc5805_transaction', None) is self:
            self.connection._rfc5805_transaction = None
