"""
"""

# Created on 2026.09.25
#
# Author: Giovanni Cannata
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


import json
import unittest

from ldap3 import Server, Connection, MOCK_SYNC, MOCK_ASYNC, SUBTREE
from ldap3.core.exceptions import LDAPInappropriateMatchingResult
from ldap3.protocol.rfc4512 import SchemaInfo, DsaInfo

# a custom schema with attribute type inheritance (SUP without own SYNTAX or EQUALITY),
# aliases, multi-valued attributes and the standard matching rules used by the tests
custom_schema = {
    'raw': {
        'attributeTypes': [
            "( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
            "( 2.5.4.3 NAME ( 'cn' 'commonName' ) SUP name )",
            "( 2.5.4.4 NAME ( 'sn' 'surname' ) SUP name )",
            "( 2.5.4.10 NAME ( 'o' 'organizationName' ) SUP name )",
            "( 2.5.4.11 NAME ( 'ou' 'organizationalUnitName' ) SUP name )",
            "( 2.5.4.12 NAME 'title' SUP name )",
            "( 1.3.6.1.4.1.99999.1.1 NAME 'nickname' SUP name )",
            "( 1.3.6.1.4.1.99999.1.2 NAME 'score' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
            "( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )",
            "( 2.5.4.49 NAME ( 'distinguishedName' 'dn' ) EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
            "( 2.5.4.31 NAME 'member' SUP distinguishedName )"
        ],
        'matchingRules': [
            "( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
            "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            "( 2.5.13.5 NAME 'caseExactMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            "( 2.5.13.14 NAME 'integerMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )"
        ]
    },
    'type': 'SchemaInfo',
    'schema_entry': 'cn=schema'
}

USER1_DN = 'cn=smith,ou=people,o=lab'
USER2_DN = 'cn=Doe\\, John,ou=people,o=lab'
GROUP1_DN = 'cn=admins,ou=groups,o=lab'


class ExtensibleMatchTests(object):
    client_strategy = None

    def setUp(self):
        schema = SchemaInfo.from_json(json.dumps(custom_schema))
        info = DsaInfo({}, {})
        server = Server.from_definition('MockExtensibleMatchServer', info, schema)
        self.connection = Connection(server, user='cn=smith,ou=people,o=lab', password='test1111', client_strategy=self.client_strategy)
        self.connection_raise = Connection(server, user='cn=smith,ou=people,o=lab', password='test1111', client_strategy=self.client_strategy, raise_exceptions=True)
        # creates fixtures
        self.connection.strategy.add_entry(USER1_DN, {'cn': 'smith', 'sn': 'Smith', 'nickname': 'Smitty', 'score': 10, 'title': ['Senior Dev', 'Lead'], 'userPassword': 'test1111'})
        self.connection.strategy.add_entry(USER2_DN, {'cn': 'Doe\\, John', 'sn': 'Doe', 'score': -3})
        self.connection.strategy.add_entry(GROUP1_DN, {'cn': 'admins', 'member': ['cn=smith,ou=people,o=lab', 'CN=Doe\\, John,OU=people,O=lab']})
        self.connection.bind()

    def tearDown(self):
        self.connection.unbind()
        self.assertFalse(self.connection.bound)

    def matched_dns(self, connection, search_filter):
        result = connection.search('o=lab', search_filter, search_scope=SUBTREE, attributes=['cn', 'sn'])
        if not connection.strategy.sync:
            response, result = connection.get_response(result)
        else:
            response = connection.response
            result = connection.result
        return result, [entry['dn'] for entry in response]

    def test_case_ignore_match(self):
        result, dns = self.matched_dns(self.connection, '(sn:caseIgnoreMatch:=SMITH)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])

    def test_case_exact_match(self):
        result, dns = self.matched_dns(self.connection, '(sn:caseExactMatch:=Smith)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])
        result, dns = self.matched_dns(self.connection, '(sn:caseExactMatch:=SMITH)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [])

    def test_integer_match(self):
        result, dns = self.matched_dns(self.connection, '(score:integerMatch:=10)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])
        result, dns = self.matched_dns(self.connection, '(score:integerMatch:=11)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [])

    def test_integer_match_negative_value(self):
        result, dns = self.matched_dns(self.connection, '(score:integerMatch:=-3)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER2_DN])

    def test_distinguished_name_match(self):
        # the member value is stored with a different but equivalent DN representation
        result, dns = self.matched_dns(self.connection, '(member:distinguishedNameMatch:=CN=Smith,OU=People,O=Lab)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [GROUP1_DN])

    def test_distinguished_name_match_escaped_comma_in_rdn(self):
        result, dns = self.matched_dns(self.connection, '(member:distinguishedNameMatch:=cn=Doe\\, John,ou=people,o=lab)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [GROUP1_DN])
        # a different value with the escape removed must not match
        result, dns = self.matched_dns(self.connection, '(member:distinguishedNameMatch:=cn=Doe\\,John,ou=people,o=lab)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [])

    def test_matching_rule_by_oid(self):
        result, dns = self.matched_dns(self.connection, '(member:2.5.13.1:=cn=smith,ou=people,o=lab)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [GROUP1_DN])

    def test_omitted_attribute_type(self):
        result, dns = self.matched_dns(self.connection, '(:caseIgnoreMatch:=SMITTY)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])

    def test_omitted_attribute_type_only_applicable_syntax(self):
        # integerMatch applies to the score attribute only, string attributes are skipped
        result, dns = self.matched_dns(self.connection, '(:integerMatch:=-3)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER2_DN])

    def test_dn_attributes(self):
        result, dns = self.matched_dns(self.connection, '(ou:dn:caseIgnoreMatch:=GROUPS)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [GROUP1_DN])

    def test_dn_attributes_escaped_comma_in_rdn(self):
        result, dns = self.matched_dns(self.connection, '(cn:dn:caseIgnoreMatch:=Doe\\, John)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER2_DN])

    def test_dn_attributes_omitted_attribute_type(self):
        result, dns = self.matched_dns(self.connection, '(:dn:caseIgnoreMatch:=people)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(sorted(dns), sorted([USER1_DN, USER2_DN]))

    def test_attribute_alias(self):
        result, dns = self.matched_dns(self.connection, '(commonName:caseIgnoreMatch:=SMITH)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])
        result, dns = self.matched_dns(self.connection, '(surname:caseIgnoreMatch:=smith)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])

    def test_multi_valued_attribute(self):
        result, dns = self.matched_dns(self.connection, '(title:caseIgnoreMatch:=LEAD)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])

    def test_inherited_syntax_applicable(self):
        # nickname inherits the Directory String syntax from its superior name
        result, dns = self.matched_dns(self.connection, '(nickname:caseIgnoreMatch:=SMITTY)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])

    def test_inherited_syntax_not_applicable(self):
        # integerMatch is not applicable to the inherited Directory String syntax of nickname
        result, dns = self.matched_dns(self.connection, '(nickname:integerMatch:=10)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [])

    def test_not_applicable_rule_no_string_fallback(self):
        # caseIgnoreMatch is not applicable to the Integer syntax of score, the value
        # must not be compared as a case insensitive string
        result, dns = self.matched_dns(self.connection, '(score:caseIgnoreMatch:=10)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [])

    def test_unrecognized_matching_rule(self):
        result, dns = self.matched_dns(self.connection, '(sn:unknownMatchingRule:=smith)')
        self.assertEqual(result['result'], 18)
        self.assertEqual(result['description'], 'inappropriateMatching')
        self.assertEqual(dns, [])

    def test_unrecognized_matching_rule_raises(self):
        self.connection_raise.bind()
        if self.connection_raise.strategy.sync:
            with self.assertRaises(LDAPInappropriateMatchingResult):
                self.connection_raise.search('o=lab', '(sn:unknownMatchingRule:=smith)', search_scope=SUBTREE, attributes=['cn'])
        else:
            message_id = self.connection_raise.search('o=lab', '(sn:unknownMatchingRule:=smith)', search_scope=SUBTREE, attributes=['cn'])
            with self.assertRaises(LDAPInappropriateMatchingResult):
                self.connection_raise.get_response(message_id)
        self.connection_raise.unbind()

    def test_default_equality_matching_rule(self):
        # the equality matching rule of the attribute, possibly inherited, is used
        result, dns = self.matched_dns(self.connection, '(nickname:=SMITTY)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])
        result, dns = self.matched_dns(self.connection, '(member:=CN=Smith,OU=People,O=Lab)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [GROUP1_DN])
        result, dns = self.matched_dns(self.connection, '(score:=-3)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER2_DN])

    def test_extensible_match_in_and(self):
        result, dns = self.matched_dns(self.connection, '(&(sn:caseIgnoreMatch:=smith)(score:integerMatch:=10))')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])

    def test_extensible_match_in_not(self):
        result, dns = self.matched_dns(self.connection, '(&(cn:dn:caseIgnoreMatch:=doe\\, john)(score:integerMatch:=-3))')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER2_DN])
        result, dns = self.matched_dns(self.connection, '(&(sn:caseIgnoreMatch:=smith)(!(score:integerMatch:=-3)))')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(dns, [USER1_DN])


class TestMockSyncExtensibleMatch(ExtensibleMatchTests, unittest.TestCase):
    client_strategy = MOCK_SYNC


class TestMockAsyncExtensibleMatch(ExtensibleMatchTests, unittest.TestCase):
    client_strategy = MOCK_ASYNC


if __name__ == '__main__':
    unittest.main()
