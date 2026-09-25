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

from pyasn1.type.univ import Sequence, SequenceOf, OctetString, Boolean
from pyasn1.type.namedtype import NamedTypes, NamedType, DefaultedNamedType, OptionalNamedType

from .rfc4511 import MessageID, Control
from .controls import build_control

START_TRANSACTION_OID = '1.3.6.1.1.21.1'  # Start Transaction Extended Request
TRANSACTION_SPECIFICATION_OID = '1.3.6.1.1.21.2'  # Transaction Specification Control
END_TRANSACTION_OID = '1.3.6.1.1.21.3'  # End Transaction Extended Request
ABORTED_TRANSACTION_NOTICE_OID = '1.3.6.1.1.21.4'  # Aborted Transaction Notice (unsolicited)


class TransactionIdentifier(OctetString):
    # Transaction Identifier ::= OCTET STRING
    pass


class TxnEndRequestValue(Sequence):
    # txnEndReqValue ::= SEQUENCE {
    #     commit          BOOLEAN DEFAULT TRUE,
    #     identifier      OCTET STRING }
    componentType = NamedTypes(DefaultedNamedType('commit', Boolean(True)),
                               NamedType('identifier', TransactionIdentifier()))


class UpdateControls(SequenceOf):
    # Controls ::= SEQUENCE OF control Control  (as per RFC4511, without the LDAPMessage context tag)
    componentType = Control()


class UpdateControlEntry(Sequence):
    # SEQUENCE {
    #     messageID       MessageID,
    #     controls        Controls }
    componentType = NamedTypes(NamedType('messageID', MessageID()),
                               NamedType('controls', UpdateControls()))


class UpdateControlsSequence(SequenceOf):
    componentType = UpdateControlEntry()


class TxnEndResponseValue(Sequence):
    # txnEndResValue ::= SEQUENCE {
    #     messageID       MessageID OPTIONAL,
    #     -- msgid of the failed update
    #     updateControls  SEQUENCE OF SEQUENCE {
    #         messageID   MessageID,
    #         controls    Controls } OPTIONAL }
    componentType = NamedTypes(OptionalNamedType('messageID', MessageID()),
                               OptionalNamedType('updateControls', UpdateControlsSequence()))


def build_transaction_control(transaction_id, criticality=True):
    # Transaction Specification Control: controlValue is the BER-encoded transaction identifier
    return build_control(TRANSACTION_SPECIFICATION_OID, criticality, TransactionIdentifier(transaction_id), encode_control_value=True)
