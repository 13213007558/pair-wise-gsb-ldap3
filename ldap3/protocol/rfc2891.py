"""Server Side Sort controls as per RFC 2891."""

from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.type.univ import Enumerated, Integer, OctetString, Sequence, SequenceOf

from .controls import build_control
from ..utils.conv import to_raw

SORT_REQUEST_CONTROL = '1.2.840.113556.1.4.473'
SORT_RESPONSE_CONTROL = '1.2.840.113556.1.4.474'

SORT_RESULT_SUCCESS = 0
SORT_RESULT_OPERATIONS_ERROR = 1
SORT_RESULT_TIME_LIMIT_EXCEEDED = 3
SORT_RESULT_STRONGER_AUTH_REQUIRED = 8
SORT_RESULT_ADMIN_LIMIT_EXCEEDED = 11
SORT_RESULT_NO_SUCH_ATTRIBUTE = 16
SORT_RESULT_INAPPROPRIATE_MATCHING = 18
SORT_RESULT_INSUFFICIENT_ACCESS_RIGHTS = 50
SORT_RESULT_BUSY = 51
SORT_RESULT_UNWILLING_TO_PERFORM = 53
SORT_RESULT_OTHER = 80


class AttributeDescription(OctetString):
    pass


class MatchingRuleId(OctetString):
    pass


class SortKey(Sequence):
    componentType = NamedTypes(
        NamedType('attributeType', AttributeDescription()),
        OptionalNamedType('orderingRule', MatchingRuleId()),
        OptionalNamedType('reverseOrder', Integer())
    )


class SortKeyList(SequenceOf):
    componentType = SortKey()


class SortResult(Sequence):
    componentType = NamedTypes(
        NamedType('sortResult', Enumerated()),
        OptionalNamedType('attributeType', AttributeDescription())
    )


def normalize_sort_keys(sort_keys):
    if isinstance(sort_keys, (str, bytes)) or not isinstance(sort_keys, (list, tuple, set, SortKeyList)):
        sort_keys = [sort_keys]

    normalized = []
    for sort_key in sort_keys:
        if isinstance(sort_key, SortKey):
            normalized.append(sort_key)
        elif isinstance(sort_key, (list, tuple)):
            if not sort_key:
                raise ValueError('sort key cannot be empty')
            attribute_type = sort_key[0]
            ordering_rule = None
            reverse_order = False
            if len(sort_key) > 1:
                if isinstance(sort_key[1], bool):
                    reverse_order = sort_key[1]
                    if len(sort_key) > 2:
                        ordering_rule = sort_key[2]
                else:
                    ordering_rule = sort_key[1]
                    if len(sort_key) > 2:
                        reverse_order = sort_key[2]
            normalized.append(build_sort_key(attribute_type, ordering_rule, reverse_order))
        elif isinstance(sort_key, dict):
            normalized.append(build_sort_key(sort_key.get('attribute_type') or sort_key.get('attributeType'),
                                             sort_key.get('ordering_rule') or sort_key.get('orderingRule'),
                                             sort_key.get('reverse_order', sort_key.get('reverseOrder', False))))
        else:
            normalized.append(build_sort_key(sort_key))

    return normalized


def build_sort_key(attribute_type, ordering_rule=None, reverse_order=False):
    if not attribute_type:
        raise ValueError('sort key attribute type is required')

    sort_key = SortKey()
    sort_key.setComponentByName('attributeType', AttributeDescription(to_raw(attribute_type)))
    if ordering_rule:
        sort_key.setComponentByName('orderingRule', MatchingRuleId(to_raw(ordering_rule)))
    if reverse_order:
        sort_key.setComponentByName('reverseOrder', Integer(1))
    return sort_key


def sort_request_control(sort_keys, criticality=False):
    sort_key_list = SortKeyList()
    for index, sort_key in enumerate(normalize_sort_keys(sort_keys)):
        sort_key_list.setComponentByPosition(index, sort_key)

    return build_control(SORT_REQUEST_CONTROL, criticality, sort_key_list)


def sort_response_control(result, attribute_type=None, criticality=False):
    sort_result = SortResult()
    sort_result.setComponentByName('sortResult', Enumerated(result))
    if attribute_type is not None:
        sort_result.setComponentByName('attributeType', AttributeDescription(to_raw(attribute_type)))
    return build_control(SORT_RESPONSE_CONTROL, criticality, sort_result)


def decode_sort_request(control_value):
    from ..utils.asn1 import decoder

    sort_keys, unprocessed = decoder.decode(control_value, asn1Spec=SortKeyList())
    if unprocessed:
        raise ValueError('unprocessed sort request control value')

    result = []
    for sort_key in sort_keys:
        result.append({
            'attribute_type': bytes(sort_key['attributeType']).decode('utf-8'),
            'ordering_rule': bytes(sort_key['orderingRule']).decode('utf-8') if sort_key['orderingRule'].hasValue() else None,
            'reverse_order': bool(sort_key['reverseOrder']) if sort_key['reverseOrder'].hasValue() and int(sort_key['reverseOrder']) else False
        })
    return result


def decode_sort_response(control_value):
    from ..utils.asn1 import decoder

    sort_result, unprocessed = decoder.decode(control_value, asn1Spec=SortResult())
    if unprocessed:
        raise ValueError('unprocessed sort response control value')

    result = {
        'result': int(sort_result['sortResult']),
        'attribute_type': None
    }
    if sort_result['attributeType'].hasValue():
        result['attribute_type'] = bytes(sort_result['attributeType']).decode('utf-8')
    return result
