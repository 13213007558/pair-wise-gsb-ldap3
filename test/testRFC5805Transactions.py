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

import time
import unittest

from ldap3 import Server, Connection, SYNC, ASYNC, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPTransactionError
from ldap3.protocol.rfc5805 import TRANSACTION_SPECIFICATION_OID
from test.transaction_server import RFC5805FakeServer, ABORT_TRIGGER_VALUE, UPDATE_MARKER_CONTROL


class TestRFC5805Transactions(unittest.TestCase):
    def setUp(self):
        self.server = RFC5805FakeServer()
        self.connections = []

    def tearDown(self):
        for connection in self.connections:
            try:
                connection.unbind()
            except Exception:
                pass
        self.server.stop()

    def get_connection(self, strategy=SYNC):
        server = Server('127.0.0.1', get_info=None)
        connection = Connection(server, 'cn=admin,o=test', 'password', client_strategy=strategy)
        # injects a socketpair channel to the fake server in place of a real network socket
        connection.socket = self.server.open_channel()
        connection.closed = False
        connection.strategy._outstanding = dict()
        if not connection.strategy.sync:
            connection.strategy._responses = dict()
            connection.strategy._requests = dict()
        connection.strategy._start_listen()
        connection.bind()
        self.connections.append(connection)
        return connection

    def wait_for_server_abort(self, transaction, timeout=5):
        # waits for the Aborted Transaction Notice to be received (asynchronous strategies use a receiver thread)
        start_time = time.time()
        while time.time() - start_time < timeout:
            if transaction.server_aborted:
                return True
            time.sleep(0.05)
        return False

    def test_start_transaction_returns_opaque_identifier(self):
        connection = self.get_connection()
        transaction_id = connection.extend.standard.start_transaction()
        self.assertIsNotNone(transaction_id)
        self.assertTrue(transaction_id.startswith(b'txn-'))
        connection.extend.standard.end_transaction(transaction_id, commit=False)

    def test_commit_transaction_sync(self):
        connection = self.get_connection()
        self.server.dit['cn=keep,o=test'] = {'objectClass': ['inetOrgPerson'], 'cn': ['keep'], 'sn': ['keep']}
        self.server.dit['cn=remove,o=test'] = {'objectClass': ['inetOrgPerson'], 'cn': ['remove'], 'sn': ['remove']}
        self.server.dit['cn=rename,o=test'] = {'objectClass': ['inetOrgPerson'], 'cn': ['rename'], 'sn': ['rename']}
        transaction = connection.extend.standard.transaction().start()
        self.assertTrue(transaction.add('cn=new,o=test', 'inetOrgPerson', {'sn': ['new'], 'givenName': ['old']}))
        self.assertTrue(transaction.modify('cn=new,o=test', {'givenName': (MODIFY_REPLACE, ['changed'])}))
        self.assertTrue(transaction.delete('cn=remove,o=test'))
        self.assertTrue(transaction.modify_dn('cn=rename,o=test', 'cn=renamed'))
        self.assertEqual(len(transaction.message_ids), 4)
        self.assertTrue(transaction.commit())
        self.assertTrue(transaction.committed)
        self.assertFalse(transaction.aborted)
        # all updates applied atomically at commit time
        self.assertEqual(self.server.dit['cn=new,o=test']['givenName'], ['changed'])
        self.assertNotIn('cn=remove,o=test', self.server.dit)
        self.assertIn('cn=renamed,o=test', self.server.dit)
        # every update request carried the Transaction Specification control with the opaque identifier
        update_message_ids = [message_id for message_id, _ in transaction.message_ids]
        for message_id, operation, txn_id in self.server.received:
            self.assertEqual(txn_id, transaction.transaction_id)
        self.assertEqual(sorted(message_id for message_id, _, _ in self.server.received), sorted(update_message_ids))
        self.assertEqual(self.server.end_requests, [(transaction.transaction_id, True)])
        # commit response carries the per-update response controls
        self.assertEqual(sorted(uc['message_id'] for uc in transaction.update_controls), sorted(update_message_ids))
        for update_control in transaction.update_controls:
            self.assertIn(UPDATE_MARKER_CONTROL, update_control['controls'])

    def test_abort_transaction_sync(self):
        connection = self.get_connection()
        transaction = connection.extend.standard.transaction().start()
        self.assertTrue(transaction.add('cn=new,o=test', 'inetOrgPerson', {'sn': ['new']}))
        self.assertTrue(transaction.abort())
        self.assertTrue(transaction.aborted)
        self.assertFalse(transaction.committed)
        self.assertNotIn('cn=new,o=test', self.server.dit)
        self.assertEqual(self.server.end_requests, [(transaction.transaction_id, False)])

    def test_context_manager_commits_on_clean_exit(self):
        connection = self.get_connection()
        with connection.extend.standard.transaction() as transaction:
            transaction.add('cn=new,o=test', 'inetOrgPerson', {'sn': ['new']})
        self.assertTrue(transaction.committed)
        self.assertIn('cn=new,o=test', self.server.dit)
        self.assertEqual(self.server.end_requests, [(transaction.transaction_id, True)])

    def test_context_manager_aborts_on_exception(self):
        connection = self.get_connection()
        with self.assertRaises(RuntimeError):
            with connection.extend.standard.transaction() as transaction:
                transaction.add('cn=new,o=test', 'inetOrgPerson', {'sn': ['new']})
                raise RuntimeError('simulated failure')
        self.assertTrue(transaction.aborted)
        self.assertFalse(transaction.committed)
        self.assertNotIn('cn=new,o=test', self.server.dit)
        self.assertEqual(self.server.end_requests, [(transaction.transaction_id, False)])

    def test_transaction_control_not_leaked_to_other_requests(self):
        connection = self.get_connection()
        user_controls = [('2.16.840.1.113730.3.4.2', True, None)]  # ManageDsaIT
        transaction = connection.extend.standard.transaction().start()
        transaction.add('cn=txn,o=test', 'inetOrgPerson', {'sn': ['txn']}, controls=user_controls)
        transaction.commit()
        # the caller's controls sequence is not modified by the transaction
        self.assertEqual(len(user_controls), 1)
        # a subsequent unrelated request on the same connection carries no transaction control
        self.assertTrue(connection.add('cn=plain,o=test', 'inetOrgPerson', {'sn': ['plain']}))
        self.assertIn('cn=plain,o=test', self.server.dit)
        plain_message_id = [message_id for message_id, _, txn_id in self.server.received if txn_id is None]
        self.assertEqual(len(plain_message_id), 1)
        for message_id, _, txn_id in self.server.received:
            control_oids = self.server.received_controls[message_id]
            if txn_id is None:
                self.assertNotIn(TRANSACTION_SPECIFICATION_OID, control_oids)
            else:
                self.assertIn(TRANSACTION_SPECIFICATION_OID, control_oids)
        # the user control was sent together with the transaction control
        txn_message_id = [message_id for message_id, _, txn_id in self.server.received if txn_id is not None][0]
        self.assertIn('2.16.840.1.113730.3.4.2', self.server.received_controls[txn_message_id])

    def test_commit_failure_attribution_sync(self):
        connection = self.get_connection()
        transaction = connection.extend.standard.transaction().start()
        transaction.add('cn=new,o=test', 'inetOrgPerson', {'sn': ['new']})
        transaction.delete('cn=missing,o=test')  # fails at commit time, entry does not exist
        self.assertFalse(transaction.commit())
        self.assertFalse(transaction.committed)
        self.assertTrue(transaction.aborted)
        # the failed message id points to the delete operation sent by this transaction
        delete_message_id = [message_id for message_id, description in transaction.message_ids if description.startswith('delete')][0]
        self.assertEqual(transaction.failed_message_id, delete_message_id)
        self.assertEqual(transaction.failed_operation, 'delete cn=missing,o=test')
        # the per-update controls cover the successfully applied update
        add_message_id = [message_id for message_id, description in transaction.message_ids if description.startswith('add')][0]
        self.assertEqual([uc['message_id'] for uc in transaction.update_controls], [add_message_id])
        self.assertIn(UPDATE_MARKER_CONTROL, transaction.update_controls[0]['controls'])
        # nothing was applied
        self.assertNotIn('cn=new,o=test', self.server.dit)

    def test_server_aborted_transaction_notice_sync(self):
        connection = self.get_connection()
        transaction = connection.extend.standard.transaction().start()
        transaction.add('cn=first,o=test', 'inetOrgPerson', {'sn': ['first']})
        # the server aborts the transaction and sends an Aborted Transaction Notice
        self.assertFalse(transaction.add('cn=second,o=test', 'inetOrgPerson', {'sn': ['second'], 'description': [ABORT_TRIGGER_VALUE]}))
        self.assertTrue(transaction.server_aborted)
        self.assertTrue(transaction.aborted)
        self.assertIn(transaction.transaction_id, connection.aborted_transaction_notices)
        with self.assertRaises(LDAPTransactionError):
            transaction.commit()
        self.assertNotIn('cn=first,o=test', self.server.dit)

    def test_transaction_async(self):
        connection = self.get_connection(ASYNC)
        self.server.dit['cn=ghost,o=test'] = {'objectClass': ['inetOrgPerson'], 'cn': ['ghost'], 'sn': ['ghost']}
        transaction = connection.extend.standard.transaction().start()
        add_message_id = transaction.add('cn=async,o=test', 'inetOrgPerson', {'sn': ['async']})
        modify_message_id = transaction.modify('cn=async,o=test', {'givenName': (MODIFY_REPLACE, ['changed'])})
        delete_message_id = transaction.delete('cn=ghost,o=test')
        self.assertEqual([message_id for message_id, _ in transaction.message_ids], [add_message_id, modify_message_id, delete_message_id])
        for message_id in (add_message_id, modify_message_id, delete_message_id):
            _, result = connection.get_response(message_id)
            self.assertEqual(result['result'], 0, result)
        self.assertTrue(transaction.commit())
        self.assertEqual(self.server.dit['cn=async,o=test']['givenName'], ['changed'])
        self.assertNotIn('cn=ghost,o=test', self.server.dit)
        self.assertEqual(self.server.end_requests, [(transaction.transaction_id, True)])

    def test_abort_transaction_async(self):
        connection = self.get_connection(ASYNC)
        transaction = connection.extend.standard.transaction().start()
        add_message_id = transaction.add('cn=async,o=test', 'inetOrgPerson', {'sn': ['async']})
        _, result = connection.get_response(add_message_id)
        self.assertEqual(result['result'], 0, result)
        self.assertTrue(transaction.abort())
        self.assertTrue(transaction.aborted)
        self.assertNotIn('cn=async,o=test', self.server.dit)
        self.assertEqual(self.server.end_requests, [(transaction.transaction_id, False)])

    def test_server_aborted_transaction_notice_async(self):
        connection = self.get_connection(ASYNC)
        transaction = connection.extend.standard.transaction().start()
        add_message_id = transaction.add('cn=async,o=test', 'inetOrgPerson', {'sn': ['async'], 'description': [ABORT_TRIGGER_VALUE]})
        _, result = connection.get_response(add_message_id)
        self.assertEqual(result['result'], 53, result)  # unwillingToPerform
        self.assertTrue(self.wait_for_server_abort(transaction))
        self.assertTrue(transaction.aborted)
        self.assertIn(transaction.transaction_id, connection.aborted_transaction_notices)
        with self.assertRaises(LDAPTransactionError):
            transaction.commit()
        self.assertNotIn('cn=async,o=test', self.server.dit)


if __name__ == '__main__':
    unittest.main()
