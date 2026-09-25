import unittest

from pyasn1.codec.ber import decoder

from ldap3.core.exceptions import LDAPExtensionError
from ldap3.extend.standard.VirtualListView import VLVSearch
from ldap3.extend import StandardExtendedOperations
from ldap3.protocol.rfc4511 import Control
from ldap3.protocol.rfc2891 import (
    SORT_REQUEST_CONTROL,
    SORT_RESPONSE_CONTROL,
    decode_sort_request,
    sort_request_control,
    sort_response_control,
)
from ldap3.protocol.rfc4511 import Controls, LDAPMessage, MessageID, ProtocolOp, SearchResultDone
from ldap3.protocol.virtualListView import (
    VLV_REQUEST_CONTROL,
    VLV_RESPONSE_CONTROL,
    decode_vlv_request,
    vlv_request_control,
    vlv_response_control,
)
from ldap3.strategy.base import BaseStrategy
from ldap3.utils.asn1 import decode_message_fast, encode, ldap_result_to_dict_fast


class FakeStrategy(object):
    def __init__(self):
        self.sync = True
        self.thread_safe = False


class FakeConnection(object):
    def __init__(self):
        self.strategy = FakeStrategy()
        self.check_names = False
        self.response = []
        self.result = None
        self.requests = []

    def search(self, **kwargs):
        self.requests.append(kwargs)
        return len(self.requests)


def decode_request_controls(controls):
    decoded = {}
    for control in controls:
        control_message, _ = decoder.decode(encode(control), asn1Spec=Control())
        control_type = str(control_message['controlType'])
        control_value = bytes(control_message['controlValue'])
        if control_type == SORT_REQUEST_CONTROL:
            decoded[control_type] = decode_sort_request(control_value)
        elif control_type == VLV_REQUEST_CONTROL:
            decoded[control_type] = decode_vlv_request(control_value)
    return decoded


def decoded_response_controls(controls):
    result = {}
    for control in controls:
        control_type, value = BaseStrategy.decode_control(control)
        result[control_type] = value['value']
    return result


def search_done_message(sort_code=0, vlv_code=0, target_position=51, content_count=100,
                        context_id=b'context-id', bad_attribute=None):
    search_result = SearchResultDone()
    search_result.setComponentByName('resultCode', 0)
    search_result.setComponentByName('matchedDN', '')
    search_result.setComponentByName('diagnosticMessage', '')

    controls = [
        sort_response_control(sort_code, bad_attribute),
        vlv_response_control(target_position, content_count, vlv_code, context_id)
    ]
    message = LDAPMessage()
    message.setComponentByName('messageID', MessageID(1))
    message.setComponentByName('protocolOp', ProtocolOp().setComponentByName('searchResDone', search_result))
    message_controls = Controls()
    for index, control in enumerate(controls):
        message_controls.setComponentByPosition(index, control)
    message.setComponentByName('controls', message_controls)
    return message


class TestVirtualListView(unittest.TestCase):
    def test_offset_request_encodes_multiple_and_reverse_sort_keys(self):
        controls = [
            sort_request_control(['cn', ('sn', True), ('uid', 'caseExactOrderingMatch', True)]),
            vlv_request_control(before_count=2, after_count=4, offset=51, content_count=0)
        ]

        decoded = decode_request_controls(controls)
        self.assertEqual([
            {'attribute_type': 'cn', 'ordering_rule': None, 'reverse_order': False},
            {'attribute_type': 'sn', 'ordering_rule': None, 'reverse_order': True},
            {'attribute_type': 'uid', 'ordering_rule': 'caseExactOrderingMatch', 'reverse_order': True}
        ], decoded[SORT_REQUEST_CONTROL])
        self.assertEqual({
            'before_count': 2,
            'after_count': 4,
            'offset': 51,
            'estimated_content_count': 0,
            'assertion_value': None,
            'context_id': None
        }, decoded[VLV_REQUEST_CONTROL])

    def test_assertion_request_encodes_context_id(self):
        controls = [
            sort_request_control(['sn', 'givenName']),
            vlv_request_control(before_count=1,
                                after_count=3,
                                assertion_value=b'jones',
                                context_id=b'context-id')
        ]

        decoded = decode_request_controls(controls)
        self.assertIsNone(decoded[VLV_REQUEST_CONTROL]['offset'])
        self.assertEqual(b'jones', decoded[VLV_REQUEST_CONTROL]['assertion_value'])
        self.assertEqual(b'context-id', decoded[VLV_REQUEST_CONTROL]['context_id'])

    def test_response_decodes_vlv_metadata_with_ber_and_fast_decoders(self):
        message = search_done_message()
        data = encode(message)

        regular_message, _ = decoder.decode(data, asn1Spec=LDAPMessage())
        regular_controls = decoded_response_controls(regular_message['controls'])
        self.assertEqual(0, regular_controls[SORT_RESPONSE_CONTROL]['result'])
        self.assertEqual(0, regular_controls[VLV_RESPONSE_CONTROL]['result'])
        self.assertEqual(51, regular_controls[VLV_RESPONSE_CONTROL]['target_position'])
        self.assertEqual(100, regular_controls[VLV_RESPONSE_CONTROL]['content_count'])
        self.assertEqual(b'context-id', regular_controls[VLV_RESPONSE_CONTROL]['context_id'])

        fast_message = decode_message_fast(data)
        search_result = ldap_result_to_dict_fast(fast_message['payload'])
        self.assertEqual(0, search_result['result'])
        fast_controls = {}
        for control in fast_message['controls']:
            control_type, control_value = BaseStrategy.decode_control_fast(control[3])
            fast_controls[control_type] = control_value['value']
        self.assertEqual(regular_controls, fast_controls)

    def test_search_success_does_not_hide_control_failures(self):
        message = search_done_message(sort_code=16,
                                      vlv_code=60,
                                      target_position=0,
                                      content_count=0,
                                      context_id=None,
                                      bad_attribute='badSortKey')
        regular_message, _ = decoder.decode(encode(message), asn1Spec=LDAPMessage())
        controls = decoded_response_controls(regular_message['controls'])

        self.assertEqual(16, controls[SORT_RESPONSE_CONTROL]['result'])
        self.assertEqual('badSortKey', controls[SORT_RESPONSE_CONTROL]['attribute_type'])
        self.assertEqual(60, controls[VLV_RESPONSE_CONTROL]['result'])

        fast_message = decode_message_fast(encode(message))
        fast_controls = {}
        for control in fast_message['controls']:
            control_type, control_value = BaseStrategy.decode_control_fast(control[3])
            fast_controls[control_type] = control_value['value']
        self.assertEqual(16, fast_controls[SORT_RESPONSE_CONTROL]['result'])
        self.assertEqual(60, fast_controls[VLV_RESPONSE_CONTROL]['result'])

        connection = FakeConnection()
        vlv = VLVSearch(connection, 'ou=people,dc=example,dc=com', '(objectClass=person)', ['badSortKey'])
        connection.result = {
            'result': 0,
            'controls': {
                SORT_RESPONSE_CONTROL: {'value': {'result': 16, 'attribute_type': 'badSortKey'}},
                VLV_RESPONSE_CONTROL: {'value': {
                    'target_position': 0,
                    'content_count': 0,
                    'result': 60,
                    'context_id': None
                }}}
        }
        vlv.search(before_count=1, after_count=1, offset=1)
        self.assertEqual(0, vlv.result['result'])
        self.assertEqual(16, vlv.sort_result_code)
        self.assertEqual(60, vlv.vlv_result_code)
        self.assertFalse(vlv.sort_ok)
        self.assertFalse(vlv.vlv_ok)

    def test_content_count_is_read_as_server_estimate_on_each_response(self):
        first = search_done_message(target_position=51, content_count=100, context_id=b'context-id')
        second = search_done_message(target_position=76, content_count=99, context_id=b'context-id')

        for message, expected_count in [(first, 100), (second, 99)]:
            decoded, _ = decoder.decode(encode(message), asn1Spec=LDAPMessage())
            controls = decoded_response_controls(decoded['controls'])
            self.assertEqual(expected_count, controls[VLV_RESPONSE_CONTROL]['content_count'])

    def test_vlv_search_reuses_context_until_scope_changes(self):
        connection = FakeConnection()
        vlv = VLVSearch(connection,
                        'ou=people,dc=example,dc=com',
                        '(objectClass=person)',
                        ['sn', ('givenName', True)])
        vlv.search(before_count=2, after_count=4, offset=51)

        controls = decode_request_controls(connection.requests[0]['controls'])
        self.assertIsNone(controls[VLV_REQUEST_CONTROL]['context_id'])

        connection.result = {
            'result': 0,
            'controls': {
                SORT_RESPONSE_CONTROL: {'value': {'result': 0, 'attribute_type': None}},
                VLV_RESPONSE_CONTROL: {'value': {
                    'target_position': 51,
                    'content_count': 100,
                    'result': 0,
                    'context_id': b'context-id'
                }}}
        }
        vlv._store_result([], connection.result)
        vlv.search(before_count=2, after_count=4, offset=76)
        controls = decode_request_controls(connection.requests[1]['controls'])
        self.assertEqual(b'context-id', controls[VLV_REQUEST_CONTROL]['context_id'])
        self.assertEqual(0, vlv.sort_result_code)
        self.assertEqual(0, vlv.vlv_result_code)
        self.assertEqual(51, vlv.target_position)
        self.assertEqual(100, vlv.content_count)
        self.assertEqual(b'context-id', vlv.context_id)

        vlv.search_base = 'ou=users,dc=example,dc=com'
        self.assertRaises(LDAPExtensionError, vlv.search, 2, 4, None, 0, None, None)
        vlv.search_base = 'ou=people,dc=example,dc=com'
        vlv.search_filter = '(objectClass=group)'
        self.assertRaises(LDAPExtensionError, vlv.search, 2, 4, None, 0, None, None)
        vlv.search_filter = '(objectClass=person)'
        vlv.sort_keys = ['uid']
        self.assertRaises(LDAPExtensionError, vlv.search, 2, 4, None, 0, None, None)
        self.assertEqual(2, len(connection.requests))

    def test_assertion_location_uses_greater_than_or_equal_choice(self):
        connection = FakeConnection()
        vlv = VLVSearch(connection, 'ou=people,dc=example,dc=com', '(objectClass=person)', ['sn'])
        vlv.search(before_count=1, after_count=2, greater_than_or_equal='jones')

        controls = decode_request_controls(connection.requests[0]['controls'])
        self.assertEqual(b'jones', controls[VLV_REQUEST_CONTROL]['assertion_value'])
        self.assertIsNone(controls[VLV_REQUEST_CONTROL]['offset'])

    def test_standard_extension_entry_builds_combined_controls(self):
        connection = FakeConnection()
        connection.result = {
            'result': 0,
            'controls': {
                VLV_RESPONSE_CONTROL: {'value': {
                    'target_position': 51,
                    'content_count': 100,
                    'result': 0,
                    'context_id': b'context-id'
                }}}
        }
        vlv = StandardExtendedOperations(connection).vlv_search(
            'ou=people,dc=example,dc=com',
            '(objectClass=person)',
            [('sn', True), 'givenName'],
            before_count=2,
            after_count=4,
            offset=51
        )

        self.assertIs(vlv.connection, connection)
        controls = decode_request_controls(connection.requests[0]['controls'])
        self.assertEqual('sn', controls[SORT_REQUEST_CONTROL][0]['attribute_type'])
        self.assertTrue(controls[SORT_REQUEST_CONTROL][0]['reverse_order'])
        self.assertEqual(51, controls[VLV_REQUEST_CONTROL]['offset'])

        vlv = StandardExtendedOperations(connection).vlv_search(
            'ou=people,dc=example,dc=com',
            '(objectClass=person)',
            [('sn', True), 'givenName'],
            before_count=2,
            after_count=4,
            offset=76,
            context_id='context-id'
        )
        controls = decode_request_controls(connection.requests[1]['controls'])
        self.assertEqual(b'context-id', controls[VLV_REQUEST_CONTROL]['context_id'])

        self.assertRaises(LDAPExtensionError,
                          StandardExtendedOperations(connection).vlv_search,
                          'ou=users,dc=example,dc=com',
                          '(objectClass=person)',
                          [('sn', True), 'givenName'],
                          before_count=2,
                          after_count=4,
                          offset=None,
                          estimated_content_count=0,
                          assertion_value=None,
                          context_id='context-id')
