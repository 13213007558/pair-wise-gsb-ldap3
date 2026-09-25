"""
"""

# Created on 2026.09.25
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

import unittest

from io import StringIO, BytesIO

from ldap3.core.exceptions import LDAPLDIFParseError
from ldap3.protocol.rfc2849 import operation_to_ldif, add_ldif_header, ldif_change_records


def records(source, **kwargs):
    return list(ldif_change_records(source, **kwargs))


class Test(unittest.TestCase):
    def test_parse_add_record(self):
        ldif = 'version: 1\n\ndn: cn=add1,dc=example,dc=org\nchangetype: add\nobjectClass: inetOrgPerson\nsn: Rossi\nsn: Bianchi\n'
        ops = records(StringIO(ldif))
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]['operation'], 'add')
        self.assertEqual(ops[0]['dn'], 'cn=add1,dc=example,dc=org')
        self.assertEqual(ops[0]['controls'], [])
        self.assertEqual(ops[0]['attributes'], {'objectClass': ['inetOrgPerson'], 'sn': ['Rossi', 'Bianchi']})

    def test_parse_delete_record(self):
        ldif = 'dn: cn=del1,dc=example,dc=org\nchangetype: delete\n'
        ops = records(StringIO(ldif))
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0], {'operation': 'delete', 'dn': 'cn=del1,dc=example,dc=org', 'controls': []})

    def test_parse_modify_record_separator_ends_only_current_block(self):
        ldif = 'dn: cn=mod1,dc=example,dc=org\nchangetype: modify\nadd: sn\nsn: one\nsn: two\n-\ndelete: description\n-\nreplace: seeAlso\nseeAlso: cn=other,dc=example,dc=org\n-\n'
        ops = records(StringIO(ldif))
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]['operation'], 'modify')
        self.assertEqual(ops[0]['changes'], [('add', 'sn', ['one', 'two']), ('delete', 'description', []), ('replace', 'seeAlso', ['cn=other,dc=example,dc=org'])])

    def test_parse_modify_value_that_is_a_dash(self):
        ldif = 'dn: cn=mod1,dc=example,dc=org\nchangetype: modify\nreplace: description\ndescription: -\n-\n'
        ops = records(StringIO(ldif))
        self.assertEqual(ops[0]['changes'], [('replace', 'description', ['-'])])

    def test_parse_modrdn_record(self):
        ldif = 'dn: cn=rdn1,dc=example,dc=org\nchangetype: modrdn\nnewrdn: cn=rdn2\ndeleteoldrdn: 1\nnewsuperior: ou=people,dc=example,dc=org\n'
        ops = records(StringIO(ldif))
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]['operation'], 'modrdn')
        self.assertEqual(ops[0]['new_rdn'], 'cn=rdn2')
        self.assertEqual(ops[0]['delete_old_rdn'], True)
        self.assertEqual(ops[0]['new_superior'], 'ou=people,dc=example,dc=org')

    def test_parse_moddn_record_without_newsuperior(self):
        ldif = 'dn: cn=rdn1,dc=example,dc=org\nchangetype: moddn\nnewrdn: cn=rdn2\ndeleteoldrdn: 0\n'
        ops = records(StringIO(ldif))
        self.assertEqual(ops[0]['operation'], 'modrdn')
        self.assertEqual(ops[0]['delete_old_rdn'], False)
        self.assertEqual(ops[0]['new_superior'], None)

    def test_modrdn_missing_deleteoldrdn_raises(self):
        ldif = 'dn: cn=rdn1,dc=example,dc=org\nchangetype: modrdn\nnewrdn: cn=rdn2\n'
        self.assertRaises(LDAPLDIFParseError, records, StringIO(ldif))

    def test_folding_unfolds_before_base64_decoding(self):
        ldif = 'dn: cn=folded,dc=example,dc=org\nchangetype: add\ndescription: first part\n second part\nsn:: w6D\n DsA==\n'
        ops = records(StringIO(ldif))
        self.assertEqual(ops[0]['attributes']['description'], ['first partsecond part'])
        self.assertEqual(ops[0]['attributes']['sn'], [b'\xc3\xa0\xc3\xb0'])

    def test_binary_values_kept_as_bytes(self):
        ldif = 'dn: cn=bin,dc=example,dc=org\nchangetype: add\njpegPhoto:: /9j/4AAQ\nuserCertificate;binary:: MIIB\n'
        ops = records(StringIO(ldif))
        self.assertEqual(ops[0]['attributes']['jpegPhoto'], [b'\xff\xd8\xff\xe0\x00\x10'])
        self.assertEqual(ops[0]['attributes']['userCertificate;binary'], [b'0\x82\x01'])

    def test_controls_preserved(self):
        ldif = 'dn: cn=c,dc=example,dc=org\ncontrol: 2.16.840.1.113719.1.27.103.7 true: givenName\ncontrol: 1.3.6.1.4.1.42.2.27.8.5.1 false:: w6DDoA==\ncontrol: 1.2.3.4\nchangetype: delete\n'
        ops = records(StringIO(ldif))
        controls = ops[0]['controls']
        self.assertEqual(controls[0], ('2.16.840.1.113719.1.27.103.7', True, 'givenName'))
        self.assertEqual(controls[1], ('1.3.6.1.4.1.42.2.27.8.5.1', False, b'\xc3\xa0\xc3\xa0'))
        self.assertEqual(controls[2], ('1.2.3.4', None, None))

    def test_keyword_like_content_is_not_a_new_record(self):
        ldif = '# changetype: delete\n# dn: cn=evil,dc=example,dc=org\ndn: cn=changetype: add,dc=example,dc=org\nchangetype: add\ndescription: version: 1\nseeAlso: dn: cn=other\n'
        ops = records(StringIO(ldif))
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]['operation'], 'add')
        self.assertEqual(ops[0]['dn'], 'cn=changetype: add,dc=example,dc=org')
        self.assertEqual(ops[0]['attributes']['description'], ['version: 1'])
        self.assertEqual(ops[0]['attributes']['seeAlso'], ['dn: cn=other'])

    def test_folded_line_looking_like_keyword_is_unfolded(self):
        ldif = 'dn: cn=a,dc=example,dc=org\nchangetype: add\ndescription: foo\n changetype: delete\n'
        ops = records(StringIO(ldif))
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]['attributes']['description'], ['foochangetype: delete'])

    def test_url_value_requires_resolver(self):
        ldif = 'dn: cn=u,dc=example,dc=org\nchangetype: add\njpegPhoto:< file:///tmp/photo.jpg\n'
        try:
            records(StringIO(ldif))
            self.fail('URL value without resolver must raise')
        except LDAPLDIFParseError as e:
            self.assertIn('resolver', str(e))

    def test_url_value_uses_caller_resolver(self):
        requested = []

        def resolver(url):
            requested.append(url)
            return b'\xff\xd8\xff'

        ldif = 'dn: cn=u,dc=example,dc=org\nchangetype: add\njpegPhoto:< file:///tmp/photo.jpg\n'
        ops = records(StringIO(ldif), url_resolver=resolver)
        self.assertEqual(requested, ['file:///tmp/photo.jpg'])
        self.assertEqual(ops[0]['attributes']['jpegPhoto'], [b'\xff\xd8\xff'])

    def test_error_carries_line_and_record_numbers(self):
        ldif = 'version: 1\n\ndn: cn=a,dc=example,dc=org\nchangetype: add\nsn: ok\n\ndn: cn=b,dc=example,dc=org\nchangetype: add\nsn:: !!!not-base64!!!\n'
        try:
            records(StringIO(ldif))
            self.fail('invalid base64 must raise')
        except LDAPLDIFParseError as e:
            self.assertEqual(e.record_number, 2)
            self.assertEqual(e.line_number, 9)
            self.assertIn('record 2', str(e))
            self.assertIn('line 9', str(e))

    def test_unclosed_record_is_not_emitted(self):
        ldif = 'dn: cn=ok,dc=example,dc=org\nchangetype: delete\n\ndn: cn=bad,dc=example,dc=org\nchangetype: modify\nadd: sn\nsn: x\n'
        iterator = ldif_change_records(StringIO(ldif))
        op = next(iterator)
        self.assertEqual(op['operation'], 'delete')
        try:
            next(iterator)
            self.fail('unclosed modify record must raise')
        except LDAPLDIFParseError as e:
            self.assertEqual(e.record_number, 2)
        self.assertRaises(StopIteration, next, iterator)

    def test_missing_changetype_raises(self):
        ldif = 'dn: cn=a,dc=example,dc=org\nsn: Rossi\n'
        self.assertRaises(LDAPLDIFParseError, records, StringIO(ldif))

    def test_continuation_without_previous_line_raises(self):
        self.assertRaises(LDAPLDIFParseError, records, StringIO(' folded first line\n'))

    def test_single_byte_chunks_match_whole_file(self):
        ldif = 'version: 1\n\ndn: cn=\xe9t\xe9,dc=example,dc=org\nchangetype: add\ndescription: a very long value that is folded acr\n oss multiple physical lines\nsn:: w6DDsA==\n\ndn: cn=x,dc=example,dc=org\nchangetype: modify\nreplace: sn\nsn: nouv\n eau\n-\n'
        whole = records(StringIO(ldif))
        whole_bytes = records(BytesIO(ldif.encode('utf-8')))
        single_bytes = records(iter([bytes([b]) for b in ldif.encode('utf-8')]))
        single_chars = records(iter(list(ldif)))
        self.assertEqual(whole, whole_bytes)
        self.assertEqual(whole, single_bytes)
        self.assertEqual(whole, single_chars)
        self.assertEqual(whole[0]['dn'], 'cn=\xe9t\xe9,dc=example,dc=org')
        self.assertEqual(whole[1]['changes'], [('replace', 'sn', ['nouveau'])])

    def test_round_trip_with_writer(self):
        long_value = 'x' * 200  # forces the writer to fold the line
        add_entry = {'entry': 'cn=round,dc=example,dc=org',
                     'controls': [('2.16.840.1.113719.1.27.103.7', True, 'givenName')],
                     'attributes': {'objectClass': ['inetOrgPerson'], 'sn': ['Rossi', long_value], 'jpegPhoto': [b'\xff\xd8\xff\xe0']}}
        delete_entry = {'entry': 'cn=round2,dc=example,dc=org', 'controls': None}
        modify_entry = {'entry': 'cn=round3,dc=example,dc=org',
                        'controls': None,
                        'changes': [{'operation': 0, 'attribute': {'type': 'sn', 'value': ['one', 'two']}},
                                    {'operation': 1, 'attribute': {'type': 'description', 'value': []}},
                                    {'operation': 2, 'attribute': {'type': 'seeAlso', 'value': ['cn=other,dc=example,dc=org']}}]}
        moddn_entry = {'entry': 'cn=round4,dc=example,dc=org', 'controls': None, 'newRdn': 'cn=round5', 'deleteOldRdn': True, 'newSuperior': 'ou=people,dc=example,dc=org'}

        ldif_lines = add_ldif_header(operation_to_ldif('addRequest', add_entry)) + ['']
        ldif_lines += operation_to_ldif('delRequest', delete_entry) + ['']
        ldif_lines += operation_to_ldif('modifyRequest', modify_entry) + ['']
        ldif_lines += operation_to_ldif('modDNRequest', moddn_entry) + ['']
        ldif_text = '\n'.join(ldif_lines) + '\n'

        ops = records(StringIO(ldif_text))
        self.assertEqual(len(ops), 4)

        self.assertEqual(ops[0]['operation'], 'add')
        self.assertEqual(ops[0]['dn'], add_entry['entry'])
        self.assertEqual(ops[0]['controls'], [('2.16.840.1.113719.1.27.103.7', True, 'givenName')])
        self.assertEqual(ops[0]['attributes']['objectClass'], ['inetOrgPerson'])
        self.assertEqual(ops[0]['attributes']['sn'], ['Rossi', long_value])
        self.assertEqual(ops[0]['attributes']['jpegPhoto'], [b'\xff\xd8\xff\xe0'])

        self.assertEqual(ops[1], {'operation': 'delete', 'dn': delete_entry['entry'], 'controls': []})

        self.assertEqual(ops[2]['operation'], 'modify')
        self.assertEqual(ops[2]['changes'], [('add', 'sn', ['one', 'two']),
                                             ('delete', 'description', []),
                                             ('replace', 'seeAlso', ['cn=other,dc=example,dc=org'])])

        self.assertEqual(ops[3]['operation'], 'modrdn')
        self.assertEqual(ops[3]['new_rdn'], 'cn=round5')
        self.assertEqual(ops[3]['delete_old_rdn'], True)
        self.assertEqual(ops[3]['new_superior'], 'ou=people,dc=example,dc=org')


if __name__ == '__main__':
    unittest.main()
