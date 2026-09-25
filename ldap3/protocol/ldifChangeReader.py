"""
"""

# LDIF-CHANGE reader as per RFC 2849.

from base64 import b64decode
import binascii
import re

from .. import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT
from ..core.exceptions import LDAPLDIFParseError


_MODIFY_OPERATIONS = {
    'add': MODIFY_ADD,
    'delete': MODIFY_DELETE,
    'replace': MODIFY_REPLACE,
    'increment': MODIFY_INCREMENT,
}

_BASE64_RE = re.compile(b'^[A-Za-z0-9+/]*={0,2}$')
_OID_RE = re.compile(br'^[0-9]+(?:\.[0-9]+)*$')
_DESCRIPTOR_RE = re.compile(r'^[A-Za-z][A-Za-z0-9-]*(?:;[A-Za-z0-9-]+)*$|^[0-9]+(?:\.[0-9]+)*$')
_EMPTY = bytes(0)
_ZERO = bytes([48])
_ONE = bytes([49])


def _physical_lines(stream, chunk_size):
    pending = bytearray()
    line_number = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        if isinstance(chunk, str):
            raise LDAPLDIFParseError('LDIF stream must be opened in binary mode')
        pending.extend(chunk)
        while True:
            line_feed = pending.find(b'\n')
            if line_feed < 0:
                break
            line = bytes(pending[:line_feed])
            del pending[:line_feed + 1]
            line_number += 1
            if line.endswith(b'\r'):
                line = line[:-1]
            yield line_number, line

    if pending:
        line_number += 1
        yield line_number, bytes(pending)


def _logical_lines(stream, chunk_size):
    buffered_number = None
    buffered_end = None
    buffered_line = None
    non_empty = False
    for line_number, line in _physical_lines(stream, chunk_size):
        if line.startswith(b' '):
            if buffered_line is None or not non_empty:
                raise LDAPLDIFParseError('folded line without a previous line', line_number)
            buffered_line.extend(line[1:])
            buffered_end = line_number
            continue

        if buffered_line is not None:
            yield buffered_number, buffered_end, bytes(buffered_line)
        buffered_number = line_number
        buffered_end = line_number
        buffered_line = bytearray(line)
        non_empty = line != _EMPTY

    if buffered_line is not None:
        yield buffered_number, buffered_end, bytes(buffered_line)


def _split_spec(line):
    colon = line.find(b':')
    if colon < 0:
        return line, 'bare', _EMPTY

    descriptor = line[:colon]
    rest = line[colon + 1:]
    if rest.startswith(b':'):
        return descriptor, 'base64', rest[1:].lstrip(b' ')
    if rest.startswith(b'<'):
        return descriptor, 'url', rest[1:].lstrip(b' ')
    return descriptor, 'plain', rest.lstrip(b' ')


class LDIFChangeRecord(object):
    def __init__(self, dn, controls=None, line_number=None, record_number=None):
        self.dn = dn
        self.controls = controls or []
        self.line_number = line_number
        self.record_number = record_number

    def execute(self, connection):
        raise NotImplementedError()

    def __eq__(self, other):
        return type(self) == type(other) and self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.dn)


class AddChangeRecord(LDIFChangeRecord):
    change_type = 'add'

    def __init__(self, dn, attributes, controls=None, line_number=None, record_number=None):
        super(AddChangeRecord, self).__init__(dn, controls, line_number, record_number)
        self.attributes = attributes

    def execute(self, connection):
        return connection.add(self.dn, None, self.attributes, controls=self.controls)


class DeleteChangeRecord(LDIFChangeRecord):
    change_type = 'delete'

    def execute(self, connection):
        return connection.delete(self.dn, controls=self.controls)


class ModifyChangeRecord(LDIFChangeRecord):
    change_type = 'modify'

    def __init__(self, dn, changes, controls=None, line_number=None, record_number=None):
        super(ModifyChangeRecord, self).__init__(dn, controls, line_number, record_number)
        self.changes = changes

    @property
    def changes_dict(self):
        changes = dict()
        for operation, attribute, values in self.changes:
            changes.setdefault(attribute, []).append((operation, list(values)))
        return changes

    def execute(self, connection):
        return connection.modify(self.dn, self.changes_dict, controls=self.controls)


class ModifyDNChangeRecord(LDIFChangeRecord):
    change_type = 'modrdn'

    def __init__(self, dn, new_rdn, delete_old_rdn, new_superior=None, controls=None,
                 line_number=None, record_number=None):
        super(ModifyDNChangeRecord, self).__init__(dn, controls, line_number, record_number)
        self.new_rdn = new_rdn
        self.delete_old_rdn = delete_old_rdn
        self.new_superior = new_superior

    def execute(self, connection):
        return connection.modify_dn(self.dn,
                                    self.new_rdn,
                                    delete_old_dn=self.delete_old_rdn,
                                    new_superior=self.new_superior,
                                    controls=self.controls)


ModrdnChangeRecord = ModifyDNChangeRecord
ModifyDnChangeRecord = ModifyDNChangeRecord
LDIFAddChangeRecord = AddChangeRecord
LDIFDeleteChangeRecord = DeleteChangeRecord
LDIFModifyChangeRecord = ModifyChangeRecord
LDIFModifyDNChangeRecord = ModifyDNChangeRecord


class _LDIFChangeRecordParser(object):
    def __init__(self, resolver=None):
        self.resolver = resolver
        self.version_seen = False
        self.record_started = False
        self.record_number = 0
        self.record = None
        self.last_line_number = None

    def error(self, message, line_number=None):
        raise LDAPLDIFParseError(message, line_number, self.record_number)

    def decode_name(self, mode, value, line_number, description):
        if mode == 'bare':
            self.error('%s requires a value specification' % description, line_number)
        if mode == 'url':
            self.error('%s cannot be loaded from a URL' % description, line_number)
        raw_value = self.decode_base64(value, line_number) if mode == 'base64' else value
        try:
            return raw_value.decode('utf-8')
        except UnicodeDecodeError:
            self.error('%s is not valid UTF-8' % description, line_number)

    def decode_base64(self, value, line_number):
        if not _BASE64_RE.match(value) or len(value) % 4:
            self.error('invalid base64 value', line_number)
        try:
            return b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            self.error('invalid base64 value', line_number)

    def resolve_url(self, value, line_number):
        if self.resolver is None:
            self.error('URL value requires a resolver', line_number)
        try:
            url = value.decode('utf-8')
        except UnicodeDecodeError:
            self.error('URL is not valid UTF-8', line_number)
        try:
            resolved = self.resolver(url)
        except LDAPLDIFParseError:
            raise
        except Exception as exc:
            self.error('URL resolver failed for %s: %s' % (url, exc), line_number)
        if not isinstance(resolved, (bytes, bytearray)):
            self.error('URL resolver must return bytes', line_number)
        return bytes(resolved)

    def materialize_value(self, mode, value, line_number):
        if mode == 'base64':
            return self.decode_base64(value, line_number)
        if mode == 'url':
            return self.resolve_url(value, line_number)
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            self.error('value is not valid UTF-8', line_number)

    def parse_control(self, mode, value, line_number):
        if mode != 'plain':
            self.error('invalid control specification', line_number)

        colon = value.find(b':')
        head = value if colon < 0 else value[:colon]
        tokens = head.split(b' ')
        tokens = [token for token in tokens if token]
        if not tokens or not _OID_RE.match(tokens[0]):
            self.error('invalid control OID', line_number)
        if len(tokens) == 1:
            criticality = False
        elif len(tokens) == 2 and tokens[1] in (b'true', b'false'):
            criticality = tokens[1] == b'true'
        else:
            self.error('invalid control criticality', line_number)

        spec = None
        if colon >= 0:
            rest = value[colon + 1:]
            if rest.startswith(b':'):
                spec = ('base64', rest[1:].lstrip(b' '), line_number)
            elif rest.startswith(b'<'):
                spec = ('url', rest[1:].lstrip(b' '), line_number)
            else:
                spec = ('plain', rest.lstrip(b' '), line_number)

        return {'oid': tokens[0].decode('ascii'), 'criticality': criticality, 'spec': spec}

    def start_record(self, mode, value, start_number, end_number):
        if self.record is not None:
            self.error('unexpected DN in an open record', end_number)
        dn = self.decode_name(mode, value, end_number, 'DN')
        self.record_started = True
        self.record_number += 1
        self.record = {
            'dn': dn,
            'line_number': start_number,
            'controls': [],
            'changetype': None,
        }

    def validate_descriptor(self, descriptor, line_number):
        if descriptor == _EMPTY:
            self.error('invalid attribute descriptor', line_number)
        try:
            text_descriptor = descriptor.decode('ascii')
        except UnicodeDecodeError:
            self.error('invalid attribute descriptor', line_number)
        if not _DESCRIPTOR_RE.match(text_descriptor):
            self.error('invalid attribute descriptor', line_number)
        return text_descriptor

    def parse_logical_line(self, start_number, end_number, line):
        line_number = end_number
        self.last_line_number = end_number
        if line == _EMPTY:
            return self.close_record(line_number)
        if line.startswith(b'#'):
            return None

        descriptor_bytes, mode, value = _split_spec(line)
        if descriptor_bytes == b'-':
            descriptor = '-'
        else:
            descriptor = self.validate_descriptor(descriptor_bytes, line_number)
        keyword = descriptor.lower()

        if self.record is None:
            if keyword == 'version':
                if self.record_started or self.version_seen:
                    self.error('unexpected LDIF version', line_number)
                if mode != 'plain' or value != b'1':
                    self.error('unsupported LDIF version', line_number)
                self.version_seen = True
                return None
            if keyword == 'dn':
                self.start_record(mode, value, start_number, end_number)
                return None
            self.error('LDIF record must start with a DN', line_number)

        record = self.record
        if record['changetype'] is None:
            if keyword == 'control':
                record['controls'].append(self.parse_control(mode, value, line_number))
                return None
            if keyword == 'changetype':
                changetype = self.materialize_value(mode, value, line_number)
                if mode != 'plain' or changetype not in ('add', 'delete', 'modify', 'modrdn', 'moddn'):
                    self.error('invalid changetype', line_number)
                record['changetype'] = changetype
                if changetype == 'add':
                    record['attributes'] = []
                elif changetype == 'modify':
                    record['changes'] = []
                    record['block'] = None
                elif changetype in ('modrdn', 'moddn'):
                    record['new_rdn'] = None
                    record['delete_old_rdn'] = None
                    record['new_superior'] = None
                return None
            self.error('missing changetype', line_number)

        changetype = record['changetype']
        if changetype == 'add':
            if descriptor == '-' or mode == 'bare':
                self.error('invalid attribute descriptor', line_number)
            record['attributes'].append((descriptor, self.materialize_value(mode, value, line_number)))
        elif changetype == 'delete':
            self.error('delete change record cannot contain attribute values', line_number)
        elif changetype == 'modify':
            self.parse_modify_line(descriptor, keyword, mode, value, line_number)
        else:
            self.parse_moddn_line(keyword, mode, value, line_number)
        return None

    def parse_modify_line(self, descriptor, keyword, mode, value, line_number):
        record = self.record
        if keyword in _MODIFY_OPERATIONS:
            if record['block'] is not None:
                self.error('missing modification separator', line_number)
            if mode != 'plain':
                self.error('invalid modification attribute', line_number)
            try:
                attribute = value.decode('utf-8')
            except UnicodeDecodeError:
                self.error('invalid modification attribute', line_number)
            if not _DESCRIPTOR_RE.match(attribute):
                self.error('invalid modification attribute', line_number)
            record['block'] = {
                'operation': _MODIFY_OPERATIONS[keyword],
                'attribute': attribute,
                'values': [],
            }
            return

        if keyword == '-':
            if mode != 'bare' or record['block'] is None:
                self.error('modification separator without a modification', line_number)
            self.finish_block()
            return

        if record['block'] is None:
            self.error('missing modification operation', line_number)
        block = record['block']
        if keyword != block['attribute'].lower():
            self.error('attribute %r does not belong to modification %r' % (descriptor, block['attribute']),
                       line_number)
        if mode == 'bare':
            self.error('attribute %s requires a value specification' % descriptor, line_number)
        block['values'].append(self.materialize_value(mode, value, line_number))

    def parse_moddn_line(self, keyword, mode, value, line_number):
        record = self.record
        if keyword == 'newrdn':
            if record['new_rdn'] is not None:
                self.error('duplicate newrdn', line_number)
            record['new_rdn'] = self.decode_name(mode, value, line_number, 'newrdn')
        elif keyword == 'deleteoldrdn':
            if record['delete_old_rdn'] is not None:
                self.error('duplicate deleteoldrdn', line_number)
            if mode != 'plain' or value not in (_ZERO, _ONE):
                self.error('deleteoldrdn must be 0 or 1', line_number)
            record['delete_old_rdn'] = value == _ONE
        elif keyword == 'newsuperior':
            if record['new_superior'] is not None:
                self.error('duplicate newsuperior', line_number)
            record['new_superior'] = self.decode_name(mode, value, line_number, 'newsuperior')
        else:
            self.error('unexpected line in modrdn record', line_number)

    def finish_block(self):
        block = self.record['block']
        self.record['changes'].append((block['operation'], block['attribute'], block['values']))
        self.record['block'] = None

    def materialize_controls(self):
        controls = []
        for control in self.record['controls']:
            if control['spec'] is None:
                value = None
            else:
                spec_mode, spec_value, line_number = control['spec']
                value = self.materialize_value(spec_mode, spec_value, line_number)
            controls.append((control['oid'], control['criticality'], value))
        return controls

    def build_record(self):
        record = self.record
        error_line = self.last_line_number if self.last_line_number is not None else record['line_number']
        changetype = record['changetype']
        if changetype is None:
            self.error('missing changetype', error_line)

        controls = self.materialize_controls()
        if changetype == 'add':
            if not record.get('attributes'):
                self.error('add record requires at least one attribute', error_line)
            attributes = dict()
            for attribute, value in record['attributes']:
                attributes.setdefault(attribute, []).append(value)
            operation = AddChangeRecord(record['dn'], attributes, controls,
                                        record['line_number'], self.record_number)
        elif changetype == 'delete':
            operation = DeleteChangeRecord(record['dn'], controls,
                                           record['line_number'], self.record_number)
        elif changetype == 'modify':
            if record['block'] is not None:
                self.error('missing modification separator', error_line)
            operation = ModifyChangeRecord(record['dn'], record['changes'], controls,
                                           record['line_number'], self.record_number)
        else:
            if record['new_rdn'] is None:
                self.error('missing newrdn', error_line)
            if record['delete_old_rdn'] is None:
                self.error('missing deleteoldrdn', error_line)
            operation = ModifyDNChangeRecord(record['dn'],
                                             record['new_rdn'],
                                             record['delete_old_rdn'],
                                             record['new_superior'],
                                             controls,
                                             record['line_number'],
                                             self.record_number)
        return operation

    def close_record(self, line_number):
        if self.record is None:
            return None
        if line_number is not None and line_number == self.record['line_number']:
            self.error('empty record cannot start with a blank line', line_number)
        operation = self.build_record()
        self.record = None
        return operation

    def end_stream(self):
        return self.close_record(None)


def parse_ldif_change_records(stream, resolver=None, chunk_size=4096):
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1:
        raise ValueError('chunk_size must be a positive integer')
    parser = _LDIFChangeRecordParser(resolver)
    for start_number, end_number, line in _logical_lines(stream, chunk_size):
        operation = parser.parse_logical_line(start_number, end_number, line)
        if operation is not None:
            yield operation
    operation = parser.end_stream()
    if operation is not None:
        yield operation


def read_ldif_change_records(stream, resolver=None, chunk_size=4096):
    return parse_ldif_change_records(stream, resolver, chunk_size)


class LDIFChangeRecordReader(object):
    def __init__(self, stream, resolver=None, chunk_size=4096):
        self.stream = stream
        self.resolver = resolver
        self.chunk_size = chunk_size

    def read_records(self):
        return parse_ldif_change_records(self.stream, self.resolver, self.chunk_size)

    def __iter__(self):
        return self.read_records()
