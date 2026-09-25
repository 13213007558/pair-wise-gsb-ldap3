"""
LDAP Content Synchronization Operation (syncrepl) as per RFC 4533
"""

from pyasn1.codec.ber import decoder
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType, DefaultedNamedType
from pyasn1.type.namedval import NamedValues
from pyasn1.type.tag import Tag, tagClassContext, tagFormatSimple, tagFormatConstructed
from pyasn1.type.univ import Sequence, Boolean, Enumerated, OctetString, SetOf, Choice

from .controls import build_control
from ..core.exceptions import LDAPControlError

SYNC_REQUEST_CONTROL = '1.3.6.1.4.1.4203.1.9.1.1'
SYNC_STATE_CONTROL = '1.3.6.1.4.1.4203.1.9.1.2'
SYNC_DONE_CONTROL = '1.3.6.1.4.1.4203.1.9.1.3'
SYNC_INFO_MESSAGE = '1.3.6.1.4.1.4203.1.9.1.4'

REFRESH_ONLY = 'refreshOnly'
REFRESH_AND_PERSIST = 'refreshAndPersist'

SYNC_STATE_NAMES = {0: 'present', 1: 'add', 2: 'modify', 3: 'delete'}


class SyncRequestMode(Enumerated):
    # mode ENUMERATED {
    #     refreshOnly       (1),
    #     refreshAndPersist (3)
    # }
    namedValues = NamedValues(('refreshOnly', 1),
                              ('refreshAndPersist', 3))


class SyncRequestControlValue(Sequence):
    # syncRequestValue ::= SEQUENCE {
    #     mode         ENUMERATED { refreshOnly (1), refreshAndPersist (3) },
    #     cookie       syncCookie OPTIONAL,
    #     reloadHint   BOOLEAN DEFAULT FALSE
    # }
    componentType = NamedTypes(NamedType('mode', SyncRequestMode()),
                               OptionalNamedType('cookie', OctetString()),
                               DefaultedNamedType('reloadHint', Boolean(False))
                               )


class SyncStateValue(Enumerated):
    # state ENUMERATED {
    #     present (0),
    #     add     (1),
    #     modify  (2),
    #     delete  (3)
    # }
    namedValues = NamedValues(('present', 0),
                              ('add', 1),
                              ('modify', 2),
                              ('delete', 3))


class SyncStateControlValue(Sequence):
    # syncStateValue ::= SEQUENCE {
    #     state      ENUMERATED { present (0), add (1), modify (2), delete (3) },
    #     entryUUID  syncUUID,
    #     cookie     syncCookie OPTIONAL
    # }
    componentType = NamedTypes(NamedType('state', SyncStateValue()),
                               NamedType('entryUUID', OctetString()),
                               OptionalNamedType('cookie', OctetString())
                               )


class SyncDoneControlValue(Sequence):
    # syncDoneValue ::= SEQUENCE {
    #     cookie          syncCookie OPTIONAL,
    #     refreshDeletes  BOOLEAN DEFAULT FALSE
    # }
    componentType = NamedTypes(OptionalNamedType('cookie', OctetString()),
                               DefaultedNamedType('refreshDeletes', Boolean(False))
                               )


class RefreshPhaseValue(Sequence):
    # refreshDelete / refreshPresent SEQUENCE {
    #     cookie       syncCookie OPTIONAL,
    #     refreshDone  BOOLEAN DEFAULT TRUE
    # }
    componentType = NamedTypes(OptionalNamedType('cookie', OctetString()),
                               DefaultedNamedType('refreshDone', Boolean(True))
                               )


class SyncIdSetValue(Sequence):
    # syncIdSet SEQUENCE {
    #     cookie         syncCookie OPTIONAL,
    #     refreshDeletes BOOLEAN DEFAULT FALSE,
    #     syncUUIDs      SET OF syncUUID
    # }
    componentType = NamedTypes(OptionalNamedType('cookie', OctetString()),
                               DefaultedNamedType('refreshDeletes', Boolean(False)),
                               NamedType('syncUUIDs', SetOf(componentType=OctetString()))
                               )


class NewCookieInfo(OctetString):
    # newcookie [0] syncCookie
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 0))


class RefreshDeleteInfo(RefreshPhaseValue):
    # refreshDelete [1] RefreshPhaseValue
    tagSet = RefreshPhaseValue.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 1))


class RefreshPresentInfo(RefreshPhaseValue):
    # refreshPresent [2] RefreshPhaseValue
    tagSet = RefreshPhaseValue.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 2))


class SyncIdSetInfo(SyncIdSetValue):
    # syncIdSet [3] SyncIdSetValue
    tagSet = SyncIdSetValue.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 3))


class SyncInfoValue(Choice):
    # syncInfoValue ::= CHOICE {
    #     newcookie      [0] syncCookie,
    #     refreshDelete  [1] SEQUENCE { cookie syncCookie OPTIONAL, refreshDone BOOLEAN DEFAULT TRUE },
    #     refreshPresent [2] SEQUENCE { cookie syncCookie OPTIONAL, refreshDone BOOLEAN DEFAULT TRUE },
    #     syncIdSet      [3] SEQUENCE { cookie syncCookie OPTIONAL, refreshDeletes BOOLEAN DEFAULT FALSE, syncUUIDs SET OF syncUUID }
    # }
    componentType = NamedTypes(NamedType('newcookie', NewCookieInfo()),
                               NamedType('refreshDelete', RefreshDeleteInfo()),
                               NamedType('refreshPresent', RefreshPresentInfo()),
                               NamedType('syncIdSet', SyncIdSetInfo())
                               )


def sync_request_control(mode=REFRESH_ONLY, cookie=None, reload_hint=False, criticality=True):
    if mode not in (REFRESH_ONLY, REFRESH_AND_PERSIST):
        raise LDAPControlError('invalid content synchronization mode: %r' % (mode, ))
    control_value = SyncRequestControlValue()
    control_value['mode'] = SyncRequestMode(mode)
    if cookie is not None:
        control_value['cookie'] = OctetString(cookie)
    if reload_hint:
        control_value['reloadHint'] = Boolean(True)
    return build_control(SYNC_REQUEST_CONTROL, criticality, control_value)


def decode_sync_state_control_value(value):
    control_value, unprocessed = decoder.decode(value, asn1Spec=SyncStateControlValue())
    if unprocessed:
        raise LDAPControlError('unprocessed substrate in sync state control')
    return {'state': str(control_value['state']),
            'entry_uuid': bytes(control_value['entryUUID']),
            'cookie': bytes(control_value['cookie']) if control_value['cookie'].hasValue() else None}


def decode_sync_done_control_value(value):
    control_value, unprocessed = decoder.decode(value, asn1Spec=SyncDoneControlValue())
    if unprocessed:
        raise LDAPControlError('unprocessed substrate in sync done control')
    return {'cookie': bytes(control_value['cookie']) if control_value['cookie'].hasValue() else None,
            'refresh_deletes': bool(control_value['refreshDeletes']) if control_value['refreshDeletes'].hasValue() else False}


def decode_sync_info_value(value):
    info_value, unprocessed = decoder.decode(value, asn1Spec=SyncInfoValue())
    if unprocessed:
        raise LDAPControlError('unprocessed substrate in sync info message')
    choice_name = info_value.getName()
    component = info_value.getComponent()
    if choice_name == 'newcookie':
        return {'type': 'newcookie',
                'cookie': bytes(component)}
    if choice_name in ('refreshPresent', 'refreshDelete'):
        return {'type': choice_name,
                'cookie': bytes(component['cookie']) if component['cookie'].hasValue() else None,
                'refresh_done': bool(component['refreshDone']) if component['refreshDone'].hasValue() else True}
    if choice_name == 'syncIdSet':
        return {'type': 'syncIdSet',
                'cookie': bytes(component['cookie']) if component['cookie'].hasValue() else None,
                'refresh_deletes': bool(component['refreshDeletes']) if component['refreshDeletes'].hasValue() else False,
                'entry_uuids': [bytes(entry_uuid) for entry_uuid in component['syncUUIDs']]}
    raise LDAPControlError('unknown sync info message choice: %r' % (choice_name, ))


def sync_info_newcookie(cookie):
    info_value = SyncInfoValue()
    info_value['newcookie'] = NewCookieInfo(cookie)
    return info_value


def sync_info_refresh_present(cookie=None, refresh_done=True):
    value = RefreshPresentInfo()
    if cookie is not None:
        value['cookie'] = OctetString(cookie)
    value['refreshDone'] = Boolean(refresh_done)
    info_value = SyncInfoValue()
    info_value['refreshPresent'] = value
    return info_value


def sync_info_refresh_delete(cookie=None, refresh_done=True):
    value = RefreshDeleteInfo()
    if cookie is not None:
        value['cookie'] = OctetString(cookie)
    value['refreshDone'] = Boolean(refresh_done)
    info_value = SyncInfoValue()
    info_value['refreshDelete'] = value
    return info_value


def sync_info_id_set(entry_uuids, refresh_deletes=False, cookie=None):
    value = SyncIdSetInfo()
    if cookie is not None:
        value['cookie'] = OctetString(cookie)
    if refresh_deletes:
        value['refreshDeletes'] = Boolean(True)
    for position, entry_uuid in enumerate(entry_uuids):
        value['syncUUIDs'].setComponentByPosition(position, OctetString(entry_uuid))
    info_value = SyncInfoValue()
    info_value['syncIdSet'] = value
    return info_value
