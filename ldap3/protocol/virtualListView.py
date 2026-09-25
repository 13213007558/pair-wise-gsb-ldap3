"""Virtual List View controls."""

from pyasn1.type import tag
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.type.univ import Choice, Enumerated, Integer, OctetString, Sequence

from .controls import build_control
from ..utils.conv import to_raw
from ..utils.asn1 import decoder as asn1_decoder

VLV_REQUEST_CONTROL = '2.16.840.1.113730.3.4.9'
VLV_RESPONSE_CONTROL = '2.16.840.1.113730.3.4.10'

VLV_RESULT_SUCCESS = 0
VLV_RESULT_OPERATIONS_ERROR = 1
VLV_RESULT_UNWILLING_TO_PERFORM = 53
VLV_RESULT_SORT_CONTROL_MISSING = 60
VLV_RESULT_OFFSET_RANGE_ERROR = 61
VLV_RESULT_OTHER = 80


class ContextID(OctetString):
    pass


class ByOffset(Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    componentType = NamedTypes(
        NamedType('offset', Integer()),
        NamedType('contentCount', Integer())
    )


class GreaterThanOrEqual(OctetString):
    tagSet = OctetString.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))


class VirtualListViewRequest(Sequence):
    componentType = NamedTypes(
        NamedType('beforeCount', Integer()),
        NamedType('afterCount', Integer()),
        NamedType('target', Choice(componentType=NamedTypes(
            NamedType('byOffset', ByOffset()),
            NamedType('greaterThanOrEqual', GreaterThanOrEqual())
        ))),
        OptionalNamedType('contextID', ContextID())
    )


class VirtualListViewResult(Enumerated):
    pass


class VirtualListViewResponse(Sequence):
    componentType = NamedTypes(
        NamedType('targetPosition', Integer()),
        NamedType('contentCount', Integer()),
        NamedType('virtualListViewResult', VirtualListViewResult()),
        OptionalNamedType('contextID', ContextID())
    )


def vlv_request_control(before_count=None,
                        after_count=None,
                        offset=None,
                        content_count=None,
                        assertion_value=None,
                        greater_than_or_equal=None,
                        context_id=None,
                        criticality=False):
    request = VirtualListViewRequest()
    request.setComponentByName('beforeCount', Integer(before_count))
    request.setComponentByName('afterCount', Integer(after_count))

    if assertion_value is None:
        assertion_value = greater_than_or_equal
    elif greater_than_or_equal is not None:
        raise ValueError('assertion_value and greater_than_or_equal cannot be used together')

    target = Choice(componentType=NamedTypes(
        NamedType('byOffset', ByOffset()),
        NamedType('greaterThanOrEqual', GreaterThanOrEqual())
    ))
    if assertion_value is not None:
        if offset is not None:
            raise ValueError('offset and assertion_value cannot be used together')
        target.setComponentByName('greaterThanOrEqual', GreaterThanOrEqual(to_raw(assertion_value)))
    else:
        if offset is None or content_count is None:
            raise ValueError('offset and content_count are required when assertion_value is not used')
        by_offset = ByOffset()
        by_offset.setComponentByName('offset', Integer(offset))
        by_offset.setComponentByName('contentCount', Integer(content_count))
        target.setComponentByName('byOffset', by_offset)

    request.setComponentByName('target', target)
    if context_id is not None:
        request.setComponentByName('contextID', ContextID(to_raw(context_id)))

    return build_control(VLV_REQUEST_CONTROL, criticality, request)


def vlv_response_control(target_position,
                         content_count,
                         result,
                         context_id=None,
                         criticality=False):
    response = VirtualListViewResponse()
    response.setComponentByName('targetPosition', Integer(target_position))
    response.setComponentByName('contentCount', Integer(content_count))
    response.setComponentByName('virtualListViewResult', VirtualListViewResult(result))
    if context_id is not None:
        response.setComponentByName('contextID', ContextID(to_raw(context_id)))
    return build_control(VLV_RESPONSE_CONTROL, criticality, response)


def decode_vlv_request(control_value):
    request, unprocessed = asn1_decoder.decode(control_value, asn1Spec=VirtualListViewRequest())
    if unprocessed:
        raise ValueError('unprocessed virtual list view request control value')

    target_name = request['target'].getName()
    target = request['target'].getComponent()
    result = {
        'before_count': int(request['beforeCount']),
        'after_count': int(request['afterCount']),
        'offset': None,
        'estimated_content_count': None,
        'assertion_value': None,
        'context_id': None
    }
    if target_name == 'byOffset':
        result['offset'] = int(target['offset'])
        result['estimated_content_count'] = int(target['contentCount'])
    else:
        result['assertion_value'] = bytes(target)

    if request['contextID'].hasValue():
        result['context_id'] = bytes(request['contextID'])
    return result


def decode_vlv_response(control_value):
    response, unprocessed = asn1_decoder.decode(control_value, asn1Spec=VirtualListViewResponse())
    if unprocessed:
        raise ValueError('unprocessed virtual list view response control value')

    result = {
        'target_position': int(response['targetPosition']),
        'content_count': int(response['contentCount']),
        'result': int(response['virtualListViewResult']),
        'context_id': None
    }
    if response['contextID'].hasValue():
        result['context_id'] = bytes(response['contextID'])
    return result
