"""
"""

# Created on 2026.11.10
#
# Author: Giovanni Cannata
#
# Copyright 2013 - 2025 Giovanni Cannata
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

from .. import ANONYMOUS

# referral credential policy decisions
REFERRAL_CREDENTIALS_DENY = 'DENY'  # do not follow the referral
REFERRAL_CREDENTIALS_ANONYMOUS = 'ANONYMOUS'  # follow the referral with an anonymous bind
REFERRAL_CREDENTIALS_ALLOW = 'ALLOW'  # follow the referral passing the original connection credentials

REFERRAL_CREDENTIALS_DECISIONS = (REFERRAL_CREDENTIALS_DENY, REFERRAL_CREDENTIALS_ANONYMOUS, REFERRAL_CREDENTIALS_ALLOW)


class ReferralCredentialPolicy(object):
    """
    Decides how the credentials of a connection are handled when a
    referral to another server is followed.

    The decide() method receives the original Connection object and a
    description of the referral target with the following keys:

    * scheme: 'ldap' or 'ldaps'
    * host: target server host name or address
    * port: target server port
    * ssl: True if the target connection uses TLS from the first byte (ldaps)
    * authentication: authentication method of the original connection (SIMPLE, SASL, NTLM or ANONYMOUS)
    * sasl_mechanism: SASL mechanism of the original connection, if any
    * anonymousBindOnly: True when allowed_referral_hosts marks the target as anonymous only

    It must return one of:

    * REFERRAL_CREDENTIALS_DENY: the referral is not followed
    * REFERRAL_CREDENTIALS_ANONYMOUS: the referral is followed with an anonymous bind,
      no credential of the original connection is sent to the target server
    * REFERRAL_CREDENTIALS_ALLOW: the referral is followed with the same
      credentials (and SASL context) of the original connection
    """

    def decide(self, connection, referral):
        raise NotImplementedError


class DefaultReferralCredentialPolicy(ReferralCredentialPolicy):
    """
    Default referral credential policy, backward compatible with the
    allowed_referral_hosts server parameter:

    * targets marked with allow_auth False in allowed_referral_hosts are
      followed anonymously
    * anonymous connections are always followed anonymously
    * a TLS downgrade (the original connection is on a secure ldaps channel
      while the referral target is cleartext ldap) is followed anonymously,
      so credentials are never silently sent over a weaker channel
    * any other referral allowed by allowed_referral_hosts is followed with
      the original connection credentials
    """

    def decide(self, connection, referral):
        if referral.get('anonymousBindOnly'):
            return REFERRAL_CREDENTIALS_ANONYMOUS
        if connection.authentication == ANONYMOUS:
            return REFERRAL_CREDENTIALS_ANONYMOUS
        if connection.server.ssl and not referral['ssl']:  # TLS downgrade, never silently carry credentials
            return REFERRAL_CREDENTIALS_ANONYMOUS
        return REFERRAL_CREDENTIALS_ALLOW
