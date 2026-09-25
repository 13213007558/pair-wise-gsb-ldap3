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

# implements RFC5805 - End Transaction Extended Request

from ...extend.operation import ExtendedOperation
from ...core.exceptions import LDAPExtensionError
from ...protocol.rfc5805 import END_TRANSACTION_OID, TxnEndRequestValue, TxnEndResponseValue
from ...strategy.base import BaseStrategy
from ...utils.asn1 import decoder


class EndTransaction(ExtendedOperation):
    def config(self):
        self.request_name = END_TRANSACTION_OID
        self.response_name = END_TRANSACTION_OID
        self.request_value = TxnEndRequestValue()
        self.asn1_spec = TxnEndResponseValue()

    def __init__(self, connection, transaction_id, commit=True, controls=None):
        ExtendedOperation.__init__(self, connection, controls)  # calls super __init__()
        self.transaction_id = transaction_id
        self.request_value['commit'] = commit
        self.request_value['identifier'] = transaction_id

    def decode_response(self, response=None):
        # the response value must be decoded even when the End Transaction
        # operation fails, because it carries the message id of the failed
        # update and the response controls of the other updates (RFC5805 sect. 4)
        if not response:
            response = self.result
        if not response:
            return None
        if response['responseName'] and response['responseName'] != self.response_name:
            raise LDAPExtensionError('invalid response name received')
        if response['responseValue']:
            decoded, unprocessed = decoder.decode(response['responseValue'], asn1Spec=self.asn1_spec)
            if unprocessed:
                raise LDAPExtensionError('error decoding extended response value')
            self.decoded_response = decoded

    def populate_result(self):
        self.result['transaction_id'] = self.transaction_id
        self.result['commit'] = bool(self.request_value['commit'])
        failed_message_id = None
        update_controls = []
        if self.decoded_response is not None:
            if self.decoded_response['messageID'].hasValue():
                failed_message_id = int(self.decoded_response['messageID'])
            for update_control in self.decoded_response['updateControls']:
                controls = dict()
                for control in update_control['controls']:
                    decoded_control = BaseStrategy.decode_control(control)
                    controls[decoded_control[0]] = decoded_control[1]
                update_controls.append({'message_id': int(update_control['messageID']), 'controls': controls})
        self.result['failed_message_id'] = failed_message_id
        self.result['update_controls'] = update_controls

    def set_response(self):
        self.response_value = self.result
