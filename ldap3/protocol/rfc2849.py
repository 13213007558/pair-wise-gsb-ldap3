"""
"""

# Created on 2013.12.08
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

from base64 import b64encode, b64decode
from binascii import Error as BinasciiError
from datetime import datetime

from .. import STRING_TYPES
from ..core.exceptions import LDAPLDIFError, LDAPLDIFParseError, LDAPExtensionError
from ..protocol.persistentSearch import EntryChangeNotificationControl
from ..utils.asn1 import decoder
from ..utils.config import get_config_parameter

# LDIF converter RFC 2849 compliant


def safe_ldif_string(bytes_value):
    if not bytes_value:
        return True

    # check SAFE-INIT-CHAR: < 127, not NUL, LF, CR, SPACE, COLON, LESS-THAN
    if bytes_value[0] > 127 or bytes_value[0] in [0, 10, 13, 32, 58, 60]:
        return False

    # check SAFE-CHAR: < 127 not NUL, LF, CR
    if 0 in bytes_value or 10 in bytes_value or 13 in bytes_value:
        return False

    # check last char for SPACE
    if bytes_value[-1] == 32:
        return False

    for byte in bytes_value:
        if byte > 127:
            return False

    return True


def _convert_to_ldif(descriptor, value, base64):
    if not value:
        value = ''
    if isinstance(value, STRING_TYPES):
        value = bytearray(value, encoding='utf-8')

    if base64 or not safe_ldif_string(value):
        try:
            encoded = b64encode(value)
        except TypeError:
            encoded = b64encode(str(value))  # patch for Python 2.6
        if not isinstance(encoded, str):  # in Python 3 b64encode returns bytes in Python 2 returns str
            encoded = str(encoded, encoding='ascii')  # Python 3
        line = descriptor + ':: ' + encoded
    else:
        if str is not bytes:  # Python 3
            value = str(value, encoding='ascii')
        else:  # Python 2
            value = str(value)
        line = descriptor + ': ' + value

    return line


def add_controls(controls, all_base64):
    lines = []
    if controls:
        for control in controls:
            line = 'control: ' + control[0]
            line += ' ' + ('true' if control[1] else 'false')
            if control[2]:
                lines.append(_convert_to_ldif(line, control[2], all_base64))

    return lines


def add_attributes(attributes, all_base64):
    lines = []
    oc_attr = None
    # objectclass first, even if this is not specified in the RFC
    for attr in attributes:
        if attr.lower() == 'objectclass':
            for val in attributes[attr]:
                lines.append(_convert_to_ldif(attr, val, all_base64))
            oc_attr = attr
            break

    # remaining attributes
    for attr in attributes:
        if attr != oc_attr and attr in attributes:
            for val in attributes[attr]:
                lines.append(_convert_to_ldif(attr, val, all_base64))

    return lines


def sort_ldif_lines(lines, sort_order):
    # sort lines as per custom sort_order
    # sort order is a list of descriptors, lines will be sorted following the same sequence
    return sorted(lines, key=lambda x: ldif_sort(x, sort_order)) if sort_order else lines


def search_response_to_ldif(entries, all_base64, sort_order=None):
    lines = []
    if entries:
        for entry in entries:
            if not entry or entry['type'] != 'searchResEntry':
                continue
            if 'dn' in entry:
                lines.append(_convert_to_ldif('dn', entry['dn'], all_base64))
                lines.extend(add_attributes(entry['raw_attributes'], all_base64))
            else:
                raise LDAPLDIFError('unable to convert to LDIF-CONTENT - missing DN')
            if sort_order:
                lines = sort_ldif_lines(lines, sort_order)
            lines.append('')

        if lines:
            lines.append('# total number of entries: ' + str(len(entries)))

    return lines


def add_request_to_ldif(entry, all_base64, sort_order=None):
    lines = []
    if 'entry' in entry:
        lines.append(_convert_to_ldif('dn', entry['entry'], all_base64))
        control_lines = add_controls(entry['controls'], all_base64)
        if control_lines:
            lines.extend(control_lines)
        lines.append('changetype: add')
        lines.extend(add_attributes(entry['attributes'], all_base64))
        if sort_order:
            lines = sort_ldif_lines(lines, sort_order)

    else:
        raise LDAPLDIFError('unable to convert to LDIF-CHANGE-ADD - missing DN ')

    return lines


def delete_request_to_ldif(entry, all_base64, sort_order=None):
    lines = []
    if 'entry' in entry:
        lines.append(_convert_to_ldif('dn', entry['entry'], all_base64))
        control_lines = add_controls(entry['controls'], all_base64)
        if control_lines:
            lines.extend(control_lines)
        lines.append('changetype: delete')
        if sort_order:
            lines = sort_ldif_lines(lines, sort_order)
    else:
        raise LDAPLDIFError('unable to convert to LDIF-CHANGE-DELETE - missing DN ')

    return lines


def modify_request_to_ldif(entry, all_base64, sort_order=None):
    lines = []
    if 'entry' in entry:
        lines.append(_convert_to_ldif('dn', entry['entry'], all_base64))
        control_lines = add_controls(entry['controls'], all_base64)
        if control_lines:
            lines.extend(control_lines)
        lines.append('changetype: modify')
        if 'changes' in entry:
            for change in entry['changes']:
                lines.append(['add', 'delete', 'replace', 'increment'][change['operation']] + ': ' + change['attribute']['type'])
                for value in change['attribute']['value']:
                    lines.append(_convert_to_ldif(change['attribute']['type'], value, all_base64))
                lines.append('-')
        if sort_order:
            lines = sort_ldif_lines(lines, sort_order)
    return lines


def modify_dn_request_to_ldif(entry, all_base64, sort_order=None):
    lines = []
    if 'entry' in entry:
        lines.append(_convert_to_ldif('dn', entry['entry'], all_base64))
        control_lines = add_controls(entry['controls'], all_base64)
        if control_lines:
            lines.extend(control_lines)
        lines.append('changetype: modrdn') if 'newSuperior' in entry and entry['newSuperior'] else lines.append('changetype: moddn')
        lines.append(_convert_to_ldif('newrdn', entry['newRdn'], all_base64))
        lines.append('deleteoldrdn: ' + ('1' if entry['deleteOldRdn'] else '0'))
        if 'newSuperior' in entry and entry['newSuperior']:
            lines.append(_convert_to_ldif('newsuperior', entry['newSuperior'], all_base64))
        if sort_order:
            lines = sort_ldif_lines(lines, sort_order)
    else:
        raise LDAPLDIFError('unable to convert to LDIF-CHANGE-MODDN - missing DN ')

    return lines


def operation_to_ldif(operation_type, entries, all_base64=False, sort_order=None):
    if operation_type == 'searchResponse':
        lines = search_response_to_ldif(entries, all_base64, sort_order)
    elif operation_type == 'addRequest':
        lines = add_request_to_ldif(entries, all_base64, sort_order)
    elif operation_type == 'delRequest':
        lines = delete_request_to_ldif(entries, all_base64, sort_order)
    elif operation_type == 'modifyRequest':
        lines = modify_request_to_ldif(entries, all_base64, sort_order)
    elif operation_type == 'modDNRequest':
        lines = modify_dn_request_to_ldif(entries, all_base64, sort_order)
    else:
        lines = []

    conf_ldif_line_length = get_config_parameter('LDIF_LINE_LENGTH')

    ldif_record = []
    # check max line length and split as per note 2 of RFC 2849
    for line in lines:
        if line:
            ldif_record.append(line[0:conf_ldif_line_length])
            ldif_record.extend([' ' + line[i: i + conf_ldif_line_length - 1] for i in range(conf_ldif_line_length, len(line), conf_ldif_line_length - 1)] if len(line) > conf_ldif_line_length else [])
        else:
            ldif_record.append('')

    return ldif_record


def add_ldif_header(ldif_lines):
    if ldif_lines:
        ldif_lines.insert(0, 'version: 1')

    return ldif_lines


def ldif_sort(line, sort_order):
    for i, descriptor in enumerate(sort_order):

        if line and line.startswith(descriptor):
            return i

    return len(sort_order) + 1


def decode_persistent_search_control(change):
    if 'controls' in change and '2.16.840.1.113730.3.4.7' in change['controls']:
        decoded = dict()
        decoded_control, unprocessed = decoder.decode(change['controls']['2.16.840.1.113730.3.4.7']['value'], asn1Spec=EntryChangeNotificationControl())
        if unprocessed:
            raise LDAPExtensionError('unprocessed value in EntryChangeNotificationControl')
        if decoded_control['changeType'] == 1:  # add
            decoded['changeType'] = 'add'
        elif decoded_control['changeType'] == 2:  # delete
            decoded['changeType'] = 'delete'
        elif decoded_control['changeType'] == 4:  # modify
            decoded['changeType'] = 'modify'
        elif decoded_control['changeType'] == 8:  # modify_dn
            decoded['changeType'] = 'modify dn'
        else:
            raise LDAPExtensionError('unknown Persistent Search changeType ' + str(decoded_control['changeType']))
        decoded['changeNumber'] = decoded_control['changeNumber'] if 'changeNumber' in decoded_control and decoded_control['changeNumber'] is not None and decoded_control['changeNumber'].hasValue() else None
        decoded['previousDN'] = decoded_control['previousDN'] if 'previousDN' in decoded_control and decoded_control['previousDN'] is not None and decoded_control['previousDN'].hasValue() else None
        return decoded

    return None


def persistent_search_response_to_ldif(change):
    ldif_lines = ['# ' + datetime.now().isoformat()]
    control = decode_persistent_search_control(change)
    if control:
        if control['changeNumber']:
            ldif_lines.append('# change number: ' + str(control['changeNumber']))
        ldif_lines.append(control['changeType'])
        if control['previousDN']:
            ldif_lines.append('# previous dn: ' + str(control['previousDN']))
    ldif_lines += operation_to_ldif('searchResponse', [change])

    return ldif_lines[:-1]  # removes "total number of entries"


# LDIF change records reader (RFC 2849), reverse of the *_to_ldif writers

_LDIF_MODIFY_OPERATIONS = ('add', 'delete', 'replace', 'increment')


def _iter_source_chunks(source):
    if hasattr(source, 'readline'):
        while True:
            chunk = source.readline()
            if not chunk:
                return
            yield chunk
    else:
        for chunk in source:
            yield chunk


def _iter_physical_lines(source, encoding):
    # yields (line_number, line_text) tuples, line numbers are 1-based
    # chunks are accumulated as bytes so that multi-byte characters split
    # across chunk boundaries are decoded only after a full line is read
    buffered = b''
    line_number = 0
    for chunk in _iter_source_chunks(source):
        if not isinstance(chunk, bytes):
            chunk = chunk.encode(encoding)
        buffered += chunk
        while True:
            pos = buffered.find(b'\n')
            if pos == -1:
                break
            raw_line = buffered[:pos]
            buffered = buffered[pos + 1:]
            line_number += 1
            yield line_number, _decode_physical_line(raw_line, encoding, line_number)
    if buffered:
        line_number += 1
        yield line_number, _decode_physical_line(buffered, encoding, line_number)


def _decode_physical_line(raw_line, encoding, line_number):
    if raw_line.endswith(b'\r'):
        raw_line = raw_line[:-1]
    try:
        return str(raw_line, encoding=encoding)
    except UnicodeDecodeError:
        raise LDAPLDIFParseError('invalid ' + encoding + ' encoding in LDIF stream', line_number=line_number)


def _iter_logical_lines(source, encoding):
    # unfolds continuation lines (a single leading space) before any decoding,
    # as per note 2 of RFC 2849; yields (line_number, line_text) tuples where
    # line_number is the physical line the logical line starts at
    pending_line = None
    pending_number = None
    for line_number, line in _iter_physical_lines(source, encoding):
        if line.startswith(' '):
            if pending_line is None:
                raise LDAPLDIFParseError('continuation line without a previous line', line_number=line_number)
            pending_line += line[1:]
            continue
        if pending_line is not None:
            yield pending_number, pending_line
        pending_number, pending_line = line_number, line
    if pending_line is not None:
        yield pending_number, pending_line


def _decode_base64_value(encoded_value, line_number, record_number):
    try:
        return b64decode(encoded_value, validate=True)
    except (BinasciiError, ValueError):
        raise LDAPLDIFParseError('invalid base64 value in LDIF stream', line_number=line_number, record_number=record_number)


def _resolve_url_value(url, url_resolver, line_number, record_number):
    if url_resolver is None:
        raise LDAPLDIFParseError('URL value requires a caller provided resolver: ' + url, line_number=line_number, record_number=record_number)
    value = url_resolver(url)
    if isinstance(value, STRING_TYPES):
        value = bytearray(value, encoding='utf-8')
    if not isinstance(value, (bytes, bytearray)):
        raise LDAPLDIFParseError('URL resolver must return bytes or string for: ' + url, line_number=line_number, record_number=record_number)
    return bytes(value)


def _value_from_suffix(suffix, url_resolver, line_number, record_number):
    # suffix starts with ':', handles plain, base64 (::) and URL (:<) values
    if suffix.startswith('::'):
        return _decode_base64_value(suffix[2:].lstrip(' '), line_number, record_number)
    if suffix.startswith(':<'):
        return _resolve_url_value(suffix[2:].lstrip(' '), url_resolver, line_number, record_number)
    return suffix[1:].lstrip(' ')


def _parse_value_spec(line, url_resolver, line_number, record_number):
    # returns (descriptor, value); value is str for plain values, bytes for base64 and URL values
    pos = line.find(':')
    if pos <= 0:
        raise LDAPLDIFParseError('invalid LDIF line, missing descriptor: ' + line, line_number=line_number, record_number=record_number)
    return line[:pos], _value_from_suffix(line[pos:], url_resolver, line_number, record_number)


def _parse_control_line(line, url_resolver, line_number, record_number):
    # control: oid [criticality] [value-spec], returns (oid, criticality, value)
    body = line[len('control'):]
    if not body.startswith(':'):
        raise LDAPLDIFParseError('invalid control line: ' + line, line_number=line_number, record_number=record_number)
    body = body[1:].lstrip(' ')
    oid, _, remainder = body.partition(' ')
    if not oid:
        raise LDAPLDIFParseError('missing OID in control line: ' + line, line_number=line_number, record_number=record_number)
    criticality = None
    value = None
    if remainder.startswith('true') and (len(remainder) == 4 or remainder[4] in ': '):
        criticality = True
        remainder = remainder[4:]
    elif remainder.startswith('false') and (len(remainder) == 5 or remainder[5] in ': '):
        criticality = False
        remainder = remainder[5:]
    remainder = remainder.lstrip(' ')
    if remainder:
        if not remainder.startswith(':'):
            raise LDAPLDIFParseError('invalid control value in line: ' + line, line_number=line_number, record_number=record_number)
        value = _value_from_suffix(remainder, url_resolver, line_number, record_number)
    return oid, criticality, value


def _as_text(value, description, line_number, record_number):
    if isinstance(value, STRING_TYPES):
        return value
    try:
        return str(value, encoding='utf-8')
    except UnicodeDecodeError:
        raise LDAPLDIFParseError('invalid utf-8 in ' + description, line_number=line_number, record_number=record_number)


def _parse_change_record(lines, records_seen, version_seen, url_resolver):
    # lines is a list of (line_number, text) logical lines of a single record,
    # returns (operation, version_seen); operation is None for a version-only chunk
    record_number = records_seen + 1
    pos = 0
    line_number, line = lines[0]
    descriptor, value = _parse_value_spec(line, url_resolver, line_number, record_number)
    if descriptor.lower() == 'version':
        if version_seen or records_seen:
            raise LDAPLDIFParseError('version directive must precede all change records', line_number=line_number, record_number=record_number)
        if _as_text(value, 'version', line_number, record_number).strip() != '1':
            raise LDAPLDIFParseError('unsupported LDIF version: ' + _as_text(value, 'version', line_number, record_number), line_number=line_number, record_number=record_number)
        version_seen = True
        pos = 1
        if pos == len(lines):
            return None, version_seen
        line_number, line = lines[pos]
        descriptor, value = _parse_value_spec(line, url_resolver, line_number, record_number)

    if descriptor.lower() != 'dn':
        raise LDAPLDIFParseError('change record must start with a dn line', line_number=line_number, record_number=record_number)
    dn = value
    pos += 1

    controls = []
    while pos < len(lines) and lines[pos][1].lower().startswith('control:'):
        control_line_number, control_line = lines[pos]
        controls.append(_parse_control_line(control_line, url_resolver, control_line_number, record_number))
        pos += 1

    if pos >= len(lines):
        raise LDAPLDIFParseError('missing changetype in change record', line_number=lines[-1][0], record_number=record_number)
    line_number, line = lines[pos]
    descriptor, value = _parse_value_spec(line, url_resolver, line_number, record_number)
    if descriptor.lower() != 'changetype':
        raise LDAPLDIFParseError('expected changetype in change record', line_number=line_number, record_number=record_number)
    change_type = _as_text(value, 'changetype', line_number, record_number).lower()
    pos += 1

    if change_type == 'add':
        operation = _parse_add_body(dn, controls, lines, pos, url_resolver, record_number)
    elif change_type == 'delete':
        if pos < len(lines):
            raise LDAPLDIFParseError('unexpected content in delete change record', line_number=lines[pos][0], record_number=record_number)
        operation = {'operation': 'delete', 'dn': dn, 'controls': controls}
    elif change_type == 'modify':
        operation = _parse_modify_body(dn, controls, lines, pos, url_resolver, record_number)
    elif change_type in ('modrdn', 'moddn'):
        operation = _parse_modrdn_body(dn, controls, lines, pos, url_resolver, record_number)
    else:
        raise LDAPLDIFParseError('unknown changetype: ' + change_type, line_number=line_number, record_number=record_number)

    return operation, version_seen


def _parse_add_body(dn, controls, lines, pos, url_resolver, record_number):
    attributes = dict()
    for line_number, line in lines[pos:]:
        descriptor, value = _parse_value_spec(line, url_resolver, line_number, record_number)
        attributes.setdefault(descriptor, []).append(value)
    return {'operation': 'add', 'dn': dn, 'controls': controls, 'attributes': attributes}


def _parse_modify_body(dn, controls, lines, pos, url_resolver, record_number):
    changes = []
    mod_operation = None
    mod_attribute = None
    mod_values = None
    mod_line_number = None
    for line_number, line in lines[pos:]:
        if line == '-':  # ends only the current modification block
            if mod_operation is None:
                raise LDAPLDIFParseError('separator without an open modification in modify record', line_number=line_number, record_number=record_number)
            changes.append((mod_operation, mod_attribute, mod_values))
            mod_operation = None
            continue
        if mod_operation is None:
            sep_pos = line.find(':')
            if sep_pos <= 0:
                raise LDAPLDIFParseError('invalid modification line in modify record: ' + line, line_number=line_number, record_number=record_number)
            mod_operation = line[:sep_pos].lower()
            if mod_operation not in _LDIF_MODIFY_OPERATIONS:
                raise LDAPLDIFParseError('unknown modification type: ' + line[:sep_pos], line_number=line_number, record_number=record_number)
            mod_attribute = line[sep_pos + 1:].lstrip(' ')
            mod_values = []
            mod_line_number = line_number
        else:
            descriptor, value = _parse_value_spec(line, url_resolver, line_number, record_number)
            if descriptor.lower() != mod_attribute.lower():
                raise LDAPLDIFParseError('attribute ' + descriptor + ' does not match modification attribute ' + mod_attribute, line_number=line_number, record_number=record_number)
            mod_values.append(value)
    if mod_operation is not None:
        raise LDAPLDIFParseError('unclosed modification in modify record', line_number=mod_line_number, record_number=record_number)
    return {'operation': 'modify', 'dn': dn, 'controls': controls, 'changes': changes}


def _parse_modrdn_body(dn, controls, lines, pos, url_resolver, record_number):
    new_rdn = None
    delete_old_rdn = None
    new_superior = None
    seen = set()
    for line_number, line in lines[pos:]:
        descriptor, value = _parse_value_spec(line, url_resolver, line_number, record_number)
        descriptor_lower = descriptor.lower()
        if descriptor_lower not in ('newrdn', 'deleteoldrdn', 'newsuperior'):
            raise LDAPLDIFParseError('unexpected line in modrdn change record: ' + descriptor, line_number=line_number, record_number=record_number)
        if descriptor_lower in seen:
            raise LDAPLDIFParseError('duplicated line in modrdn change record: ' + descriptor, line_number=line_number, record_number=record_number)
        seen.add(descriptor_lower)
        if descriptor_lower == 'newrdn':
            new_rdn = value
        elif descriptor_lower == 'newsuperior':
            new_superior = value
        else:
            flag = _as_text(value, 'deleteoldrdn', line_number, record_number).lower()
            if flag in ('1', 'true'):
                delete_old_rdn = True
            elif flag in ('0', 'false'):
                delete_old_rdn = False
            else:
                raise LDAPLDIFParseError('invalid deleteoldrdn value: ' + flag, line_number=line_number, record_number=record_number)
    if new_rdn is None:
        raise LDAPLDIFParseError('missing newrdn in modrdn change record', line_number=lines[-1][0], record_number=record_number)
    if delete_old_rdn is None:
        raise LDAPLDIFParseError('missing deleteoldrdn in modrdn change record', line_number=lines[-1][0], record_number=record_number)
    return {'operation': 'modrdn', 'dn': dn, 'controls': controls, 'new_rdn': new_rdn, 'delete_old_rdn': delete_old_rdn, 'new_superior': new_superior}


def ldif_change_records(source, url_resolver=None, encoding='utf-8'):
    """
    Reads an LDIF change stream (RFC 2849) and yields one operation dict per
    change record, in stream order. Nothing is sent to any server; the caller
    decides whether to execute each returned operation.

    source can be a file-like object (text or binary) or any iterable of
    str/bytes chunks. url_resolver, when provided, is called with the URL of
    every ":<" value and must return its content; without it URL values raise
    LDAPLDIFParseError and no network or file access is ever attempted.

    Operation dicts:
    add:    {'operation': 'add', 'dn': dn, 'controls': controls, 'attributes': {attr: [values]}}
    delete: {'operation': 'delete', 'dn': dn, 'controls': controls}
    modify: {'operation': 'modify', 'dn': dn, 'controls': controls, 'changes': [(op, attr, [values])]}
    modrdn: {'operation': 'modrdn', 'dn': dn, 'controls': controls, 'new_rdn': rdn,
             'delete_old_rdn': bool, 'new_superior': dn or None}

    controls is a list of (oid, criticality, value) tuples; criticality is
    None when not specified. Plain values are str, base64 and URL values are
    bytes. A record is yielded only when complete; malformed or unclosed
    records raise LDAPLDIFParseError with physical line and record numbers.
    """
    records_seen = 0
    version_seen = False
    pending = []
    for line_number, line in _iter_logical_lines(source, encoding):
        if not line:  # blank line closes the current record
            if pending:
                operation, version_seen = _parse_change_record(pending, records_seen, version_seen, url_resolver)
                pending = []
                if operation is not None:
                    records_seen += 1
                    yield operation
            continue
        if line.startswith('#'):  # comment lines never start a record
            continue
        pending.append((line_number, line))
    if pending:
        operation, version_seen = _parse_change_record(pending, records_seen, version_seen, url_resolver)
        if operation is not None:
            yield operation
