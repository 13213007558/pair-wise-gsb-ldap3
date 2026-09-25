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

# implements RFC5805 - Lightweight Directory Access Protocol (LDAP) Transactions

from ...core.exceptions import LDAPTransactionError
from ...core.results import RESULT_SUCCESS
from ...protocol.rfc5805 import build_transaction_control
from ...utils.log import log, log_enabled, ERROR
from .startTransaction import StartTransaction
from .endTransaction import EndTransaction


class Transaction(object):
    """
    Manage an RFC5805 LDAP transaction on a single connection.

    Add, delete, modify and modify_dn requests issued through this object
    carry the Transaction Specification control with the opaque transaction
    identifier returned by the server; requests issued directly on the
    connection are not affected. The transaction is ended with commit() or
    abort(). Can be used as a context manager: the transaction is committed
    on a clean exit and aborted when the body raises an exception.
    """

    def __init__(self, connection, controls=None):
        self.connection = connection
        self.controls = controls  # controls for the Start and End Transaction extended requests
        self.transaction_id = None
        self.message_ids = []  # (message_id, operation description) of the updates sent in this transaction
        self.result = None
        self.failed_message_id = None
        self.update_controls = None
        self.committed = False
        self._started = False
        self._ended = False
        self._aborted = False

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if not self._started or self._ended:
            return False
        if exc_type is not None:
            try:
                self.abort()
            except Exception as e:
                if log_enabled(ERROR):
                    log(ERROR, 'error <%s> aborting transaction after exception via <%s>', e, self.connection)
        else:
            self.commit()
        return False

    @property
    def server_aborted(self):
        # True when the server sent an Aborted Transaction Notice for this transaction
        return self.transaction_id is not None and self.transaction_id in self.connection.aborted_transaction_notices

    @property
    def aborted(self):
        return self._aborted or self.server_aborted

    @property
    def active(self):
        return self._started and not self._ended and not self.aborted

    def operation_for(self, message_id):
        # returns the description of the update operation with the given message id, for failure attribution
        for operation_message_id, description in self.message_ids:
            if operation_message_id == message_id:
                return description
        return None

    @property
    def failed_operation(self):
        return self.operation_for(self.failed_message_id) if self.failed_message_id is not None else None

    def _check_active(self):
        if not self._started:
            self.connection.last_error = 'transaction not started'
            raise LDAPTransactionError(self.connection.last_error)
        if self._ended:
            self.connection.last_error = 'transaction already ended'
            raise LDAPTransactionError(self.connection.last_error)
        if self.server_aborted:
            self.connection.last_error = 'transaction aborted by server'
            raise LDAPTransactionError(self.connection.last_error)

    def _transaction_controls(self, controls):
        # builds a new control sequence with the Transaction Specification control appended,
        # the caller's controls sequence is never modified and nothing is stored on the
        # connection, so the control cannot leak into unrelated requests
        transaction_control = build_transaction_control(self.transaction_id)
        if controls is None:
            return [transaction_control]
        merged_controls = list(controls)
        merged_controls.append(transaction_control)
        return merged_controls

    def _execute(self, description, operation, *args, **kwargs):
        self._check_active()
        kwargs['controls'] = self._transaction_controls(kwargs.get('controls', None))
        if self.connection.strategy.sync:
            # captures the message id of the update request for failure attribution;
            # the connection lock (re-entrant) prevents interleaving with other threads
            captured_message_ids = []
            original_send = self.connection.send

            def send_wrapper(message_type, request, controls=None):
                message_id = original_send(message_type, request, controls)
                captured_message_ids.append(message_id)
                return message_id

            with self.connection.connection_lock:
                self.connection.send = send_wrapper
                try:
                    result = operation(*args, **kwargs)
                finally:
                    self.connection.send = original_send
            message_id = captured_message_ids[-1] if captured_message_ids else None
        else:
            result = operation(*args, **kwargs)
            message_id = result if isinstance(result, int) else None  # asynchronous strategies return the message id
        if message_id is not None:
            self.message_ids.append((message_id, description))
        return result

    def start(self):
        if self._started:
            self.connection.last_error = 'transaction already started'
            raise LDAPTransactionError(self.connection.last_error)
        start_transaction = StartTransaction(self.connection, self.controls)
        start_transaction.send()
        self.transaction_id = start_transaction.response_value
        if self.transaction_id is None:
            self.connection.last_error = 'no transaction identifier received'
            raise LDAPTransactionError(self.connection.last_error)
        self._started = True
        return self

    def add(self, dn, object_class=None, attributes=None, controls=None):
        return self._execute('add ' + str(dn), self.connection.add, dn, object_class, attributes, controls=controls)

    def delete(self, dn, controls=None):
        return self._execute('delete ' + str(dn), self.connection.delete, dn, controls=controls)

    def modify(self, dn, changes, controls=None):
        return self._execute('modify ' + str(dn), self.connection.modify, dn, changes, controls=controls)

    def modify_dn(self, dn, relative_dn, delete_old_dn=True, new_superior=None, controls=None):
        return self._execute('modify_dn ' + str(dn), self.connection.modify_dn, dn, relative_dn, delete_old_dn, new_superior, controls=controls)

    def _end(self, commit, controls):
        self._check_active()
        end_transaction = EndTransaction(self.connection, self.transaction_id, commit=commit, controls=controls if controls is not None else self.controls)
        end_transaction.send()
        self._ended = True
        self.result = end_transaction.result
        self.failed_message_id = self.result.get('failed_message_id') if self.result else None
        self.update_controls = self.result.get('update_controls') if self.result else None
        return self.result is not None and self.result['result'] == RESULT_SUCCESS

    def commit(self, controls=None):
        success = self._end(True, controls)
        self.committed = success
        if not success:
            self._aborted = True  # the server rolled back the transaction
        return success

    def abort(self, controls=None):
        success = self._end(False, controls)
        self._aborted = True
        return success
