"""
"""

# Created on 2026.09.25
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

from ldap3 import Server, Connection, MOCK_SYNC, SUBTREE, OFFLINE_SLAPD_2_4
from ldap3.strategy.mockBase import MockBaseStrategy
from ldap3.utils.conv import to_unicode


def reverse_match(assertion_value, attribute_value):
    # a custom matching rule used to test the registration of additional rules
    return to_unicode(assertion_value, 'utf-8')[::-1] == to_unicode(attribute_value, 'utf-8')


class Test(unittest.TestCase):
    def setUp(self):
        server = Server('dummy', get_info=OFFLINE_SLAPD_2_4)
        self.connection = Connection(server, user='cn=admin,dc=example,dc=org', password='password', client_strategy=MOCK_SYNC)
        self.connection.bind()
        add_entry = self.connection.strategy.add_entry
        # entry with case and whitespace differences in the stored values
        add_entry('cn=Alice,ou=People,dc=example,dc=org', {'objectClass': 'person',
                                                           'cn': 'Alice',
                                                           'sn': 'Smith',
                                                           'uidNumber': '1001',
                                                           'title': 'System  Administrator'})
        # entry with a multi-valued RDN
        add_entry('cn=Bob+sn=Jones,ou=People,dc=example,dc=org', {'objectClass': 'person',
                                                                  'cn': 'Bob',
                                                                  'sn': 'Jones',
                                                                  'uidNumber': '1002'})
        # entry with an escaped comma in the RDN (cn attribute holds the escaped value)
        add_entry('cn=Doe\\, John,ou=People,dc=example,dc=org', {'objectClass': 'person',
                                                                  'sn': 'Doe'})
        # group whose members are stored with case/whitespace differences and an escaped comma
        add_entry('cn=staff,ou=Groups,dc=example,dc=org', {'objectClass': 'groupOfNames',
                                                           'cn': 'staff',
                                                           'member': ['CN=alice, OU=People,dc=example,dc=org',
                                                                      'cn=Doe\\, John,ou=People,dc=example,dc=org']})
        # entry with a value that cannot be prepared as an integer
        add_entry('cn=Carol,ou=People,dc=example,dc=org', {'objectClass': 'person',
                                                           'cn': 'Carol',
                                                           'sn': 'Carol',
                                                           'uidNumber': 'unknown'}, validate=False)
        # a schema-less mock server, where assertion values are not validated against the schema
        schema_less_server = Server('dummy-no-schema')
        self.schema_less_connection = Connection(schema_less_server, user='cn=admin,dc=example,dc=org', password='password', client_strategy=MOCK_SYNC)
        self.schema_less_connection.bind()
        self.schema_less_connection.strategy.add_entry('cn=Alice,ou=People,dc=example,dc=org', {'cn': 'Alice', 'uidNumber': '1001'})
        self.schema_less_connection.strategy.add_entry('cn=Carol,ou=People,dc=example,dc=org', {'cn': 'Carol', 'uidNumber': 'unknown'}, validate=False)

    def tearDown(self):
        self.connection.unbind()
        self.schema_less_connection.unbind()
        MockBaseStrategy.extensible_match_evaluators.pop('reversematch', None)
        MockBaseStrategy.extensible_match_evaluators.pop('1.2.3.4.5', None)

    def search_dns(self, search_filter, connection=None):
        connection = connection or self.connection
        connection.search('dc=example,dc=org', search_filter, search_scope=SUBTREE, attributes=['cn'])
        self.assertEqual(connection.result['description'], 'success')
        return sorted(entry['dn'] for entry in connection.response)

    def test_extensible_match_distinguished_name_by_oid(self):
        matched = self.search_dns('(member:dn:2.5.13.1:=cn=Alice,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, ['cn=staff,ou=Groups,dc=example,dc=org'])

    def test_extensible_match_distinguished_name_by_name(self):
        matched = self.search_dns('(member:distinguishedNameMatch:=cn=Alice,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, ['cn=staff,ou=Groups,dc=example,dc=org'])

    def test_extensible_match_distinguished_name_with_escaped_comma(self):
        matched = self.search_dns('(member:distinguishedNameMatch:=cn=Doe\\5c, John,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, ['cn=staff,ou=Groups,dc=example,dc=org'])

    def test_extensible_match_case_ignore(self):
        matched = self.search_dns('(cn:caseIgnoreMatch:=ALICE)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_extensible_match_case_ignore_whitespace(self):
        matched = self.search_dns('(title:caseIgnoreMatch:=system administrator)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_extensible_match_case_exact(self):
        matched = self.search_dns('(cn:caseExactMatch:=Alice)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_extensible_match_case_exact_different_case_not_matched(self):
        matched = self.search_dns('(cn:caseExactMatch:=ALICE)')
        self.assertEqual(matched, [])

    def test_extensible_match_case_exact_whitespace_insignificant(self):
        matched = self.search_dns('(title:caseExactMatch:=System Administrator)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_extensible_match_integer(self):
        matched = self.search_dns('(uidNumber:integerMatch:=1001)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_extensible_match_matching_rule_only(self):
        matched = self.search_dns('(:caseIgnoreMatch:=smith)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_extensible_match_dn_attributes_multi_valued_rdn(self):
        matched = self.search_dns('(:dn:caseIgnoreMatch:=jones)')
        self.assertEqual(matched, ['cn=Bob+sn=Jones,ou=People,dc=example,dc=org'])

    def test_extensible_match_dn_attributes_escaped_comma(self):
        matched = self.search_dns('(:dn:caseExactMatch:=Doe, John)')
        self.assertEqual(matched, ['cn=Doe\\, John,ou=People,dc=example,dc=org'])

    def test_extensible_match_without_dn_attributes_escaped_comma_not_matched(self):
        # the stored cn attribute holds the escaped value 'Doe\\, John' that doesn't match
        matched = self.search_dns('(:caseExactMatch:=Doe, John)')
        self.assertEqual(matched, [])

    def test_extensible_match_unknown_rule_is_undefined(self):
        matched = self.search_dns('(cn:2.5.13.99:=Alice)')
        self.assertEqual(matched, [])

    def test_extensible_match_not_of_unknown_rule_is_not_true(self):
        matched = self.search_dns('(!(cn:2.5.13.99:=Alice))')
        self.assertEqual(matched, [])

    def test_extensible_match_attribute_not_applicable_is_undefined(self):
        # distinguishedNameMatch doesn't apply to the cn attribute as per the schema matchingRuleUse
        matched = self.search_dns('(cn:2.5.13.1:=cn=Alice,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, [])

    def test_extensible_match_not_of_not_applicable_is_not_true(self):
        matched = self.search_dns('(!(cn:2.5.13.1:=cn=Alice,ou=People,dc=example,dc=org))')
        self.assertEqual(matched, [])

    def test_extensible_match_unpreparable_stored_value_is_undefined(self):
        # 'unknown' cannot be prepared as an integer, so Carol is Undefined, not FALSE
        matched = self.search_dns('(!(uidNumber:integerMatch:=1001))')
        self.assertEqual(matched, ['cn=Bob+sn=Jones,ou=People,dc=example,dc=org'])

    def test_extensible_match_unpreparable_assertion_is_undefined(self):
        matched = self.search_dns('(uidNumber:integerMatch:=notanumber)', connection=self.schema_less_connection)
        self.assertEqual(matched, [])

    def test_extensible_match_not_of_unpreparable_assertion_is_not_true(self):
        matched = self.search_dns('(!(uidNumber:integerMatch:=notanumber))', connection=self.schema_less_connection)
        self.assertEqual(matched, [])

    def test_extensible_match_no_rule_uses_attribute_equality(self):
        matched = self.search_dns('(uidNumber:=1001)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_extensible_match_no_rule_walks_up_attribute_hierarchy(self):
        # member has no own EQUALITY rule, it inherits distinguishedNameMatch from distinguishedName
        matched = self.search_dns('(member:=cn=Alice,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, ['cn=staff,ou=Groups,dc=example,dc=org'])

    def test_extensible_match_or_with_undefined_is_true_when_other_is_true(self):
        matched = self.search_dns('(|(uidNumber:integerMatch:=1001)(cn:2.5.13.99:=x))')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_extensible_match_and_with_undefined_is_not_true(self):
        matched = self.search_dns('(&(uidNumber:integerMatch:=1001)(cn:2.5.13.99:=x))')
        self.assertEqual(matched, [])

    def test_extensible_match_or_with_not_of_undefined(self):
        matched = self.search_dns('(|(!(cn:2.5.13.99:=x))(cn=Alice))')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_extensible_match_not_of_true_is_false(self):
        matched = self.search_dns('(!(member:dn:2.5.13.1:=cn=Alice,ou=People,dc=example,dc=org))')
        self.assertEqual(matched, [])

    def test_register_additional_matching_rule(self):
        MockBaseStrategy.register_matching_rule(['1.2.3.4.5', 'reverseMatch'], reverse_match)
        matched = self.search_dns('(sn:reverseMatch:=htimS)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])
        matched = self.search_dns('(sn:1.2.3.4.5:=htimS)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])
