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


import unittest

from ldap3 import Server, Connection, MOCK_SYNC, MOCK_ASYNC, SUBTREE
from ldap3.core.exceptions import LDAPOperationResult
from ldap3.protocol.rfc4512 import SchemaInfo, DsaInfo
from ldap3.protocol.schemas.slapd24 import slapd_2_4_schema, slapd_2_4_dsa_info
from test.config import random_id

testcase_id = ''


class Test(unittest.TestCase):
    client_strategy = MOCK_SYNC

    def setUp(self):
        global testcase_id
        testcase_id = random_id()
        schema = SchemaInfo.from_json(slapd_2_4_schema)
        info = DsaInfo.from_json(slapd_2_4_dsa_info, schema)
        server_1 = Server.from_definition('MockExtensibleServer', info, schema)
        self.connection_1 = Connection(server_1, user='cn=admin,ou=test,o=lab', password='test', client_strategy=self.client_strategy)
        self.connection_1c = Connection(server_1, user='cn=admin,ou=test,o=lab', password='test', client_strategy=self.client_strategy, raise_exceptions=True)
        server_3 = Server('dummy')  # no schema
        self.connection_3 = Connection(server_3, user='cn=admin,ou=test,o=lab', password='test', client_strategy=self.client_strategy)
        # creates fixtures
        for connection in (self.connection_1, self.connection_3):
            connection.strategy.add_entry('cn=admin,ou=test,o=lab', {'sn': 'Admin', 'cn': 'admin', 'userPassword': 'test'})
            connection.strategy.add_entry('cn=smith,ou=test,o=lab', {'sn': 'Smith', 'cn': 'smith', 'uidNumber': 1000, 'title': ['title1', 'title2', 'title3'], 'userPassword': 'x'})
            connection.strategy.add_entry('cn=doe\\, john,ou=test,o=lab', {'sn': 'Doe', 'uidNumber': -5, 'userPassword': 'x'})
            connection.strategy.add_entry('cn=group1,ou=test,o=lab', {'member': ['CN=Smith, OU=test, O=lab', 'cn=doe\\, john,ou=test,o=lab'], 'userPassword': 'x'})
            connection.strategy.add_entry('cn=group2,ou=test,o=lab', {'member': 'cn=ref1,ou=test,o=lab', 'userPassword': 'x'})
        self.connection_1.bind()
        self.connection_1c.bind()
        self.connection_3.bind()

    def tearDown(self):
        self.connection_1.unbind()
        self.assertFalse(self.connection_1.bound)
        self.connection_1c.unbind()
        self.assertFalse(self.connection_1c.bound)
        self.connection_3.unbind()
        self.assertFalse(self.connection_3.bound)

    def _search(self, connection, search_filter, attributes=None):
        result = connection.search('o=lab', search_filter, search_scope=SUBTREE, attributes=attributes or ['cn'])
        if not connection.strategy.sync:
            response, result = connection.get_response(result)
        else:
            response = connection.response
            result = connection.result
        matched_dns = [entry['dn'] for entry in response] if response else []
        return result, matched_dns

    def test_case_ignore_match(self):
        result, matched = self._search(self.connection_1, '(sn:caseIgnoreMatch:=SMITH)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=smith,ou=test,o=lab'])

    def test_case_exact_match(self):
        result, matched = self._search(self.connection_1, '(sn:caseExactMatch:=Smith)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=smith,ou=test,o=lab'])

    def test_case_exact_match_different_case_not_matched(self):
        result, matched = self._search(self.connection_1, '(sn:caseExactMatch:=SMITH)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, [])

    def test_case_ignore_match_inherited_syntax(self):
        # cn has no syntax of its own in the slapd schema, it inherits it from the name attribute type
        result, matched = self._search(self.connection_1, '(cn:caseIgnoreMatch:=SMITH)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=smith,ou=test,o=lab'])

    def test_case_ignore_match_alias(self):
        # surname is an alias of sn, values are stored under the sn attribute
        result, matched = self._search(self.connection_1, '(surname:caseIgnoreMatch:=smith)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=smith,ou=test,o=lab'])

    def test_case_exact_match_multivalued_attribute(self):
        result, matched = self._search(self.connection_1, '(title:caseExactMatch:=title2)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=smith,ou=test,o=lab'])

    def test_integer_match(self):
        result, matched = self._search(self.connection_1, '(uidNumber:integerMatch:=1000)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=smith,ou=test,o=lab'])

    def test_integer_match_negative_value(self):
        result, matched = self._search(self.connection_1, '(uidNumber:integerMatch:=-5)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=doe\\, john,ou=test,o=lab'])

    def test_distinguished_name_match_differently_written_dn(self):
        # the stored value is 'CN=Smith, OU=test, O=lab', the assertion uses a different spacing and casing
        result, matched = self._search(self.connection_1, '(member:distinguishedNameMatch:=cn=smith,ou=test,o=lab)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=group1,ou=test,o=lab'])

    def test_distinguished_name_match_escaped_comma_in_rdn(self):
        result, matched = self._search(self.connection_1, '(member:distinguishedNameMatch:=cn=Doe\\, John,ou=test,o=lab)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=group1,ou=test,o=lab'])

    def test_distinguished_name_match_by_rule_oid(self):
        result, matched = self._search(self.connection_1, '(member:2.5.13.1:=cn=ref1,ou=test,o=lab)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=group2,ou=test,o=lab'])

    def test_distinguished_name_match_not_matched(self):
        result, matched = self._search(self.connection_1, '(member:distinguishedNameMatch:=cn=smith,o=lab)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, [])

    def test_extensible_match_without_attribute(self):
        # the rule is applied to all the attributes it is appropriate for
        result, matched = self._search(self.connection_1, '(:caseIgnoreMatch:=title2)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=smith,ou=test,o=lab'])

    def test_extensible_match_without_attribute_dn_only_value_not_matched(self):
        # 'test' only appears in the entry dns, without dnAttributes no entry matches
        result, matched = self._search(self.connection_1, '(:caseIgnoreMatch:=test)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, [])

    def test_extensible_match_dn_attributes(self):
        result, matched = self._search(self.connection_1, '(:dn:caseIgnoreMatch:=test)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(len(matched), 5)

    def test_extensible_match_dn_attributes_with_attribute(self):
        result, matched = self._search(self.connection_1, '(ou:dn:caseIgnoreMatch:=TEST)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(len(matched), 5)

    def test_extensible_match_dn_attributes_escaped_comma_in_rdn(self):
        result, matched = self._search(self.connection_1, '(cn:dn:caseIgnoreMatch:=doe, john)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=doe\\, john,ou=test,o=lab'])

    def test_extensible_match_without_matching_rule(self):
        # without a matching rule the equality rule of the attribute is used
        result, matched = self._search(self.connection_1, '(uidNumber:dn:=-5)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=doe\\, john,ou=test,o=lab'])

    def test_extensible_match_in_and_filter(self):
        result, matched = self._search(self.connection_1, '(&(uidNumber:integerMatch:=-5)(sn:caseIgnoreMatch:=doe))')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=doe\\, john,ou=test,o=lab'])

    def test_extensible_match_in_or_filter(self):
        result, matched = self._search(self.connection_1, '(|(uidNumber:integerMatch:=-5)(sn:caseExactMatch:=Smith))')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(len(matched), 2)

    def test_extensible_match_in_not_filter(self):
        result, matched = self._search(self.connection_1, '(!(sn:caseExactMatch:=Smith))')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(len(matched), 4)
        self.assertNotIn('cn=smith,ou=test,o=lab', matched)

    def test_extensible_match_no_schema(self):
        result, matched = self._search(self.connection_3, '(sn:caseIgnoreMatch:=SMITH)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=smith,ou=test,o=lab'])

    def test_extensible_match_no_schema_integer(self):
        result, matched = self._search(self.connection_3, '(uidNumber:integerMatch:=-5)')
        self.assertEqual(result['description'], 'success')
        self.assertEqual(matched, ['cn=doe\\, john,ou=test,o=lab'])

    def test_unrecognized_matching_rule(self):
        result, matched = self._search(self.connection_1, '(sn:unknownMatchingRule:=smith)')
        self.assertEqual(result['result'], 18)
        self.assertEqual(result['description'], 'inappropriateMatching')
        self.assertEqual(matched, [])

    def test_unrecognized_matching_rule_raises_when_exceptions(self):
        try:
            self._search(self.connection_1c, '(sn:unknownMatchingRule:=smith)')
            self.assertTrue(False, 'should have raised LDAPOperationResult')
        except LDAPOperationResult as e:
            self.assertEqual(e.result, 18)

    def test_matching_rule_not_applicable_to_attribute(self):
        # uidNumber has Integer syntax, caseIgnoreMatch applies to Directory String only
        result, matched = self._search(self.connection_1, '(uidNumber:caseIgnoreMatch:=1000)')
        self.assertEqual(result['result'], 18)
        self.assertEqual(result['description'], 'inappropriateMatching')
        self.assertEqual(matched, [])

    def test_integer_match_not_applicable_to_string_attribute(self):
        result, matched = self._search(self.connection_1, '(sn:integerMatch:=1)')
        self.assertEqual(result['result'], 18)
        self.assertEqual(result['description'], 'inappropriateMatching')
        self.assertEqual(matched, [])

    def test_invalid_integer_assertion(self):
        result, matched = self._search(self.connection_1, '(:integerMatch:=notanumber)')
        self.assertEqual(result['result'], 18)
        self.assertEqual(result['description'], 'inappropriateMatching')
        self.assertEqual(matched, [])


class TestAsync(Test):
    client_strategy = MOCK_ASYNC
