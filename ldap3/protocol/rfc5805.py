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

# ASN.1 definitions for RFC5805 - Lightweight Directory Access Protocol (LDAP) Transactions

from pyasn1.type.univ import OctetString, Sequence, Boolean
from pyasn1.type.namedtype import NamedType, NamedTypes, OptionalNamedType, DefaultedNamedType

from .rfc4511 import MessageID

START_TRANSACTION_REQUEST_NAME = '1.3.6.1.1.21.1'  # Start Transaction Extended Request
TRANSACTION_SPECIFICATION_CONTROL = '1.3.6.1.1.21.2'  # Transaction Specification Control
END_TRANSACTION_REQUEST_NAME = '1.3.6.1.1.21.3'  # End Transaction Extended Request
ABORTED_TRANSACTION_NOTICE = '1.3.6.1.1.21.4'  # Aborted Transaction Notice (unsolicited)


class TransactionIdentifier(OctetString):
    pass


class EndTransactionRequestValue(Sequence):
    componentType = NamedTypes(NamedType('identifier', TransactionIdentifier()),
                               DefaultedNamedType('commit', Boolean(True))
                               )


class EndTransactionResponseValue(Sequence):
    componentType = NamedTypes(OptionalNamedType('messageID', MessageID())
                               )
