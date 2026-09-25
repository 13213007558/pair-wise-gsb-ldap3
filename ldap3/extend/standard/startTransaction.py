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

# implements RFC5805 - Start Transaction Extended Request

from ...extend.operation import ExtendedOperation
from ...protocol.rfc5805 import START_TRANSACTION_OID, TransactionIdentifier


class StartTransaction(ExtendedOperation):
    def config(self):
        self.request_name = START_TRANSACTION_OID
        self.response_name = START_TRANSACTION_OID
        self.request_value = None  # the Start Transaction request has no value
        self.asn1_spec = TransactionIdentifier()  # the response value is the opaque transaction identifier

    def populate_result(self):
        try:
            self.result['transaction_id'] = bytes(self.decoded_response)
        except TypeError:
            self.result['transaction_id'] = None

    def set_response(self):
        self.response_value = self.result['transaction_id'] if self.result else None
