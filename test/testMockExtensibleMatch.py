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

from ldap3 import SchemaInfo, DsaInfo, Server, Connection, MOCK_SYNC
from ldap3.protocol.schemas.slapd24 import slapd_2_4_schema, slapd_2_4_dsa_info


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = SchemaInfo.from_json(slapd_2_4_schema)
        info = DsaInfo.from_json(slapd_2_4_dsa_info, cls.schema)
        cls.server = Server.from_definition('MockExtensibleMatchServer', info, cls.schema)
        cls.connection = Connection(cls.server, user='cn=Alice,ou=People,dc=example,dc=org', password='alice1', client_strategy=MOCK_SYNC)

        # create fixtures
        cls.connection.strategy.add_entry('cn=Alice,ou=People,dc=example,dc=org', {'objectClass': ['person'], 'cn': 'Alice', 'sn': 'Alisson', 'uidNumber': 1001, 'userPassword': 'alice1'})
        cls.connection.strategy.add_entry('cn=Bob+uid=bob01,ou=People,dc=example,dc=org', {'objectClass': ['person'], 'cn': 'Bob', 'sn': 'Bobson', 'uid': 'bob01', 'uidNumber': 1002, 'userPassword': 'bob01'})
        cls.connection.strategy.add_entry('cn=Doe\\, John,ou=People,dc=example,dc=org', {'objectClass': ['person'], 'cn': 'Doe, John', 'sn': 'Doe', 'uidNumber': 1003, 'userPassword': 'doe123'})
        cls.connection.strategy.add_entry('cn=Weird,ou=People,dc=example,dc=org', {'objectClass': ['person'], 'cn': 'Weird', 'sn': 'Weirdson', 'uidNumber': 'notanumber', 'userPassword': 'weird1'}, validate=False)
        cls.connection.strategy.add_entry('cn=admins,ou=Groups,dc=example,dc=org', {'objectClass': ['groupOfNames'], 'cn': 'admins', 'member': ['CN=alice, OU=People,DC=example,DC=org',
                                                                                                                                                            'uid=bob01+cn=Bob,ou=People,dc=example,dc=org',
                                                                                                                                                            'cn=Doe\\, John, ou=People, dc=example, dc=org',
                                                                                                                                                            'cn=Ghost,ou=People,dc=example,dc=org']})
        cls.connection.bind()

    @classmethod
    def tearDownClass(cls):
        cls.connection.unbind()

    def _search_dns(self, search_base, search_filter):
        self.connection.search(search_base, search_filter, attributes=['cn'])
        return sorted(entry['dn'] for entry in self.connection.response)

    def test_distinguished_name_match_with_oid_and_dn_attributes(self):
        matched = self._search_dns('ou=Groups,dc=example,dc=org', '(member:dn:2.5.13.1:=cn=Alice,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, ['cn=admins,ou=Groups,dc=example,dc=org'])

    def test_distinguished_name_match_with_rule_name(self):
        matched = self._search_dns('ou=Groups,dc=example,dc=org', '(member:distinguishedNameMatch:=CN=ALICE, ou=People, dc=example, dc=org)')
        self.assertEqual(matched, ['cn=admins,ou=Groups,dc=example,dc=org'])

    def test_distinguished_name_match_multi_valued_rdn(self):
        # the stored member value has the AVAs of the multi-valued RDN in reverse order
        matched = self._search_dns('ou=Groups,dc=example,dc=org', '(member:dn:2.5.13.1:=cn=Bob+uid=bob01,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, ['cn=admins,ou=Groups,dc=example,dc=org'])

    def test_distinguished_name_match_escaped_comma(self):
        matched = self._search_dns('ou=Groups,dc=example,dc=org', '(member:dn:2.5.13.1:=cn=Doe\\5c, John,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, ['cn=admins,ou=Groups,dc=example,dc=org'])

    def test_distinguished_name_match_without_matching_rule_uses_attribute_equality(self):
        matched = self._search_dns('ou=Groups,dc=example,dc=org', '(member:=cn=Alice,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, ['cn=admins,ou=Groups,dc=example,dc=org'])

    def test_case_ignore_match(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(cn:caseIgnoreMatch:=ALICE)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_case_ignore_match_insignificant_spaces(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(cn:caseIgnoreMatch:=Doe,   John)')
        self.assertEqual(matched, ['cn=Doe\\, John,ou=People,dc=example,dc=org'])

    def test_case_exact_match(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(cn:caseExactMatch:=Alice)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_case_exact_match_is_case_sensitive(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(cn:caseExactMatch:=ALICE)')
        self.assertEqual(matched, [])

    def test_integer_match(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(uidNumber:integerMatch:=1001)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_integer_match_with_oid(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(uidNumber:2.5.13.14:=1002)')
        self.assertEqual(matched, ['cn=Bob+uid=bob01,ou=People,dc=example,dc=org'])

    def test_matching_rule_only_evaluates_applicable_attributes(self):
        # matches the admins entry (member attribute) and the Alice entry itself (entryDN operational attribute)
        matched = self._search_dns('dc=example,dc=org', '(:distinguishedNameMatch:=cn=Alice,ou=People,dc=example,dc=org)')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org', 'cn=admins,ou=Groups,dc=example,dc=org'])

    def test_dn_attributes_evaluates_entry_dn(self):
        matched = self._search_dns('ou=Groups,dc=example,dc=org', '(:dn:caseIgnoreMatch:=admins)')
        self.assertEqual(matched, ['cn=admins,ou=Groups,dc=example,dc=org'])

    def test_unknown_matching_rule_is_undefined(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(cn:nonExistentMatch:=Alice)')
        self.assertEqual(matched, [])

    def test_not_of_unknown_matching_rule_is_not_true(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(!(cn:nonExistentMatch:=Alice))')
        self.assertEqual(matched, [])

    def test_not_applicable_attribute_is_undefined(self):
        # caseIgnoreMatch cannot be applied to the integer syntax of uidNumber
        matched = self._search_dns('ou=People,dc=example,dc=org', '(uidNumber:caseIgnoreMatch:=1001)')
        self.assertEqual(matched, [])

    def test_not_of_not_applicable_attribute_is_not_true(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(!(uidNumber:caseIgnoreMatch:=1001))')
        self.assertEqual(matched, [])

    def test_unpreparable_value_is_undefined(self):
        # cn=Weird has a non-integer uidNumber, its evaluation is Undefined so NOT cannot make it TRUE
        matched = self._search_dns('ou=People,dc=example,dc=org', '(!(uidNumber:integerMatch:=1001))')
        self.assertEqual(matched, ['cn=Bob+uid=bob01,ou=People,dc=example,dc=org', 'cn=Doe\\, John,ou=People,dc=example,dc=org'])

    def test_and_with_undefined_operand_is_undefined(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(&(uidNumber:caseIgnoreMatch:=1001)(cn=Alice))')
        self.assertEqual(matched, [])

    def test_or_with_undefined_operand_keeps_true(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(|(uidNumber:caseIgnoreMatch:=1001)(cn=Alice))')
        self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])

    def test_custom_matching_rule_registration(self):
        matched = self._search_dns('ou=People,dc=example,dc=org', '(cn:startsWithMatch:=Al)')
        self.assertEqual(matched, [])  # unknown rule evaluates to Undefined

        self.connection.strategy.register_extensible_match_rule('startsWithMatch', lambda assertion, value: value.decode('utf-8').startswith(assertion.decode('utf-8')))
        try:
            matched = self._search_dns('ou=People,dc=example,dc=org', '(cn:startsWithMatch:=Al)')
            self.assertEqual(matched, ['cn=Alice,ou=People,dc=example,dc=org'])
        finally:
            del self.connection.strategy.extensible_match_rules['startswithmatch']
