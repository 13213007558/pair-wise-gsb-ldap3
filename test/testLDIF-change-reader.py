"""
"""

import io
import os
import tempfile
import unittest

from ldap3 import Connection, LDIF
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT
from ldap3 import LDAPLDIFParseError
from ldap3.protocol.ldifChangeReader import AddChangeRecord
from ldap3.protocol.ldifChangeReader import DeleteChangeRecord
from ldap3.protocol.ldifChangeReader import ModifyChangeRecord
from ldap3.protocol.ldifChangeReader import ModifyDNChangeRecord
from ldap3.protocol.ldifChangeReader import parse_ldif_change_records


CHANGE_LDIF = b'''version: 1
# comment before first record: changetype: delete

dn: cn=Add,ou=users,dc=example,dc=com
control: 1.2.3.4 false: plain control
control: 1.2.3.5 true:: Y3RybA==
changetype: add
objectClass: inetOrgPerson
cn: Add User
description: line one
 continuation
jpegPhoto:: AAEC
 hww=
homepage:<https://example.test/add
changetype: a value
dn: cn=not-a-record

dn: cn=Delete,ou=users,dc=example,dc=com
changetype: delete

dn: cn=Modify,ou=users,dc=example,dc=com
changetype: modify
add: description
description: added
-
delete: title
-
replace: mail
mail: a@example.com
mail:: YmFAdGVzdA==
-
increment: uidNumber
uidNumber: 1
-

dn: cn=Old,ou=users,dc=example,dc=com
changetype: modrdn
newrdn: cn=New
deleteoldrdn: 1
newsuperior: ou=staff,dc=example,dc=com
'''


class OneByteStream(object):
    def __init__(self, stream):
        self.stream = stream

    def read(self, size=-1):
        return self.stream.read(1)


class FakeConnection(object):
    def __init__(self):
        self.calls = []

    def add(self, dn, object_class, attributes, controls=None):
        self.calls.append(('add', dn, object_class, attributes, controls))

    def delete(self, dn, controls=None):
        self.calls.append(('delete', dn, controls))

    def modify(self, dn, changes, controls=None):
        self.calls.append(('modify', dn, changes, controls))

    def modify_dn(self, dn, relative_dn, delete_old_dn=True, new_superior=None, controls=None):
        self.calls.append(('modify_dn', dn, relative_dn, delete_old_dn, new_superior, controls))


def resolver(url):
    if url == 'https://example.test/add':
        return b'https-page'
    raise ValueError(url)


def expected_records():
    return [
        AddChangeRecord(
            'cn=Add,ou=users,dc=example,dc=com',
            {
                'objectClass': ['inetOrgPerson'],
                'cn': ['Add User'],
                'description': ['line onecontinuation'],
                'jpegPhoto': [b'\x00\x01\x02\x87\x0c'],
                'homepage': [b'https-page'],
                'changetype': ['a value'],
                'dn': ['cn=not-a-record'],
            },
            [
                ('1.2.3.4', False, 'plain control'),
                ('1.2.3.5', True, b'ctrl'),
            ],
            4,
            1),
        DeleteChangeRecord(
            'cn=Delete,ou=users,dc=example,dc=com',
            [],
            18,
            2),
        ModifyChangeRecord(
            'cn=Modify,ou=users,dc=example,dc=com',
            [
                (MODIFY_ADD, 'description', ['added']),
                (MODIFY_DELETE, 'title', []),
                (MODIFY_REPLACE, 'mail', ['a@example.com', b'ba@test']),
                (MODIFY_INCREMENT, 'uidNumber', ['1']),
            ],
            [],
            21,
            3),
        ModifyDNChangeRecord(
            'cn=Old,ou=users,dc=example,dc=com',
            'cn=New',
            True,
            'ou=staff,dc=example,dc=com',
            [],
            36,
            4),
    ]


class TestLDIFChangeReader(unittest.TestCase):
    def test_records_can_be_executed_by_caller(self):
        records = list(parse_ldif_change_records(io.BytesIO(CHANGE_LDIF), resolver))
        connection = FakeConnection()
        for record in records:
            record.execute(connection)

        self.assertEqual('add', connection.calls[0][0])
        self.assertEqual('cn=Add,ou=users,dc=example,dc=com', connection.calls[0][1])
        self.assertIsNone(connection.calls[0][2])
        self.assertEqual([('MODIFY_ADD', ['added'])], connection.calls[2][2]['description'])
        self.assertEqual(('modify_dn',
                          'cn=Old,ou=users,dc=example,dc=com',
                          'cn=New',
                          True,
                          'ou=staff,dc=example,dc=com',
                          []), connection.calls[3])

    def test_single_byte_stream_matches_normal_stream(self):
        normal = list(parse_ldif_change_records(io.BytesIO(CHANGE_LDIF), resolver))
        one_byte = list(parse_ldif_change_records(io.BytesIO(CHANGE_LDIF), resolver, chunk_size=1))

        self.assertEqual(expected_records(), normal)
        self.assertEqual(normal, one_byte)

    def test_normal_file_and_one_byte_file_wrapper(self):
        path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.ldif') as ldif_file:
                ldif_file.write(CHANGE_LDIF)
                path = ldif_file.name

            with open(path, 'rb') as ldif_file:
                normal = list(parse_ldif_change_records(ldif_file, resolver))

            with open(path, 'rb') as ldif_file:
                one_byte = list(parse_ldif_change_records(OneByteStream(ldif_file), resolver))

            self.assertEqual(expected_records(), normal)
            self.assertEqual(normal, one_byte)
        finally:
            if path:
                os.remove(path)

    def test_unclosed_modify_does_not_emit_half_record(self):
        data = b'''version: 1
dn: cn=unclosed,dc=example,dc=com
changetype: modify
add: cn
cn: value
'''
        records = []
        generator = parse_ldif_change_records(io.BytesIO(data))
        with self.assertRaises(LDAPLDIFParseError) as cm:
            for record in generator:
                records.append(record)

        self.assertEqual([], records)
        self.assertEqual(5, cm.exception.line_number)
        self.assertEqual(1, cm.exception.record_number)

    def test_folded_invalid_base64_reports_physical_line(self):
        data = b'''dn: cn=invalid,dc=example,dc=com
changetype: add
objectClass: person
cn:: AAAA
 !!!!
'''
        with self.assertRaises(LDAPLDIFParseError) as cm:
            list(parse_ldif_change_records(io.BytesIO(data)))

        self.assertEqual(5, cm.exception.line_number)
        self.assertEqual(1, cm.exception.record_number)

    def test_url_without_resolver_does_not_access_file_or_network(self):
        data = b'''dn: cn=url,dc=example,dc=com
changetype: add
objectClass: person
cn:<file:///etc/passwd
'''
        with self.assertRaises(LDAPLDIFParseError) as cm:
            list(parse_ldif_change_records(io.BytesIO(data)))

        self.assertEqual(4, cm.exception.line_number)
        self.assertEqual(1, cm.exception.record_number)

    def test_writer_round_trip(self):
        connection = Connection(server=None, client_strategy=LDIF)
        connection.open()
        connection.strategy.line_separator = '\n'

        controls = [('1.2.3.4', True, b'\x00ctrl'), ('1.2.3.4', False, 'plain')]
        dn_add = 'cn=writer-add,ou=users,dc=example,dc=com'
        dn_delete = 'cn=writer-delete,ou=users,dc=example,dc=com'
        dn_modify = 'cn=writer-modify,ou=users,dc=example,dc=com'
        dn_modrdn = 'cn=writer-old,ou=users,dc=example,dc=com'

        connection.add(dn_add,
                       'inetOrgPerson',
                       {
                           'objectClass': 'inetOrgPerson',
                           'sn': 'writer-add',
                           'jpegPhoto': b'\x00\x01\x02\x87\x0c',
                       },
                       controls=controls)
        connection.delete(dn_delete)
        connection.modify(dn_modify,
                          {
                              'description': (MODIFY_ADD, ['one']),
                              'title': (MODIFY_DELETE, []),
                              'mail': (MODIFY_REPLACE, ['a@example.com']),
                              'uidNumber': (MODIFY_INCREMENT, ['1']),
                          })
        connection.modify_dn(dn_modrdn,
                             'cn=writer-new',
                             delete_old_dn=False,
                             new_superior='ou=staff,dc=example,dc=com')

        ldif_bytes = connection.stream.getvalue().encode('utf-8')
        records = list(parse_ldif_change_records(io.BytesIO(ldif_bytes)))

        self.assertEqual(4, len(records))
        self.assertIsInstance(records[0], AddChangeRecord)
        self.assertEqual(dn_add, records[0].dn)
        self.assertEqual([b'\x00\x01\x02\x87\x0c'], records[0].attributes['jpegPhoto'])
        self.assertEqual([('1.2.3.4', True, b'\x00ctrl'), ('1.2.3.4', False, 'plain')],
                         records[0].controls)

        self.assertIsInstance(records[1], DeleteChangeRecord)
        self.assertEqual(dn_delete, records[1].dn)

        self.assertIsInstance(records[2], ModifyChangeRecord)
        self.assertEqual(dn_modify, records[2].dn)
        self.assertEqual([
            (MODIFY_ADD, 'description', ['one']),
            (MODIFY_DELETE, 'title', []),
            (MODIFY_REPLACE, 'mail', ['a@example.com']),
            (MODIFY_INCREMENT, 'uidNumber', ['1']),
        ], records[2].changes)

        self.assertIsInstance(records[3], ModifyDNChangeRecord)
        self.assertEqual(dn_modrdn, records[3].dn)
        self.assertEqual('cn=writer-new', records[3].new_rdn)
        self.assertFalse(records[3].delete_old_rdn)
        self.assertEqual('ou=staff,dc=example,dc=com', records[3].new_superior)

        connection.unbind()


if __name__ == '__main__':
    unittest.main()
