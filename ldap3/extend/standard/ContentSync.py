"""
LDAP Content Synchronization Operation (syncrepl) as per RFC 4533
"""

from pyasn1.codec.ber import decoder

from ... import SEQUENCE_TYPES, STRING_TYPES, ALL_ATTRIBUTES, NO_ATTRIBUTES, SUBTREE, DEREF_NEVER
from ...core.exceptions import LDAPExtensionError, LDAPSocketReceiveError
from ...core.results import RESULT_SUCCESS, RESULT_E_SYNC_REFRESH_REQUIRED
from ...operation.search import search_operation
from ...protocol.rfc4511 import LDAPMessage
from ...protocol.rfc4533 import SYNC_STATE_CONTROL, SYNC_DONE_CONTROL, SYNC_INFO_MESSAGE, REFRESH_ONLY, REFRESH_AND_PERSIST, sync_request_control, decode_sync_info_value
from ...utils.asn1 import decode_message_fast
from ...utils.dn import safe_dn

LDAP_MESSAGE_TEMPLATE = LDAPMessage()


class ContentSync(object):
    """RFC 4533 LDAP Content Synchronization client.

    Iterating over events() yields directory events and phase markers;
    the caller decides how to persist them. Entry events are keyed by
    entryUUID and have a 'type' of 'present', 'add', 'modify' or
    'delete'. Marker events describe the refresh stage boundaries:
    'phase_begin'/'phase_end' (phase is 'present' or 'delete'),
    'id_set', 'new_cookie', 'persist_begin', 'sync_done',
    'refresh_required' and 'error'.

    Entries not seen in the current refresh must not be considered
    deleted until the refresh boundary is complete, that is when
    'sync_done' (refreshOnly) or 'persist_begin' (refreshAndPersist)
    is delivered.

    Cookies are opaque blobs returned to the server as-is. The
    resumable position (the cookie attribute) advances only when the
    caller confirms the delivered events with ack(), so a disconnect
    never leaves a stored cookie past unconfirmed events.
    """

    def __init__(self,
                 connection,
                 search_base,
                 search_filter='(objectclass=*)',
                 search_scope=None,
                 dereference_aliases=None,
                 attributes=None,
                 size_limit=0,
                 time_limit=0,
                 controls=None,
                 mode=REFRESH_ONLY,
                 cookie=None,
                 reload_hint=False,
                 criticality=True):
        if not connection.strategy.sync:
            raise LDAPExtensionError('Content Synchronization needs a synchronous connection')

        if mode not in (REFRESH_ONLY, REFRESH_AND_PERSIST):
            raise LDAPExtensionError('invalid content synchronization mode: %r' % (mode, ))

        if connection.check_names and search_base:
            search_base = safe_dn(search_base)

        self.connection = connection
        self.base = search_base
        self.filter = search_filter
        self.scope = SUBTREE if search_scope is None else search_scope
        self.dereference_aliases = DEREF_NEVER if dereference_aliases is None else dereference_aliases
        self.attributes = ALL_ATTRIBUTES if attributes is None else attributes
        self.size_limit = size_limit
        self.time_limit = time_limit
        self.mode = mode
        self.reload_hint = reload_hint
        self.criticality = criticality
        if not isinstance(controls, SEQUENCE_TYPES):
            self.controls = []
        else:
            self.controls = list(controls)
        self.message_id = None
        self.cookie = cookie  # last confirmed (resumable) cookie
        self._pending_cookie = cookie  # latest cookie received from the server
        self.in_refresh = True  # True while the refresh stage is in progress
        self.done = False
        self._delete_phase_open = False
        self._refresh_close_pending = False

    def start(self):
        if self.message_id is not None:  # content sync already started
            return

        if not self.connection.bound:
            self.connection.bind()

        attributes = self.attributes
        if not attributes:
            attributes = [NO_ATTRIBUTES]
        elif attributes == ALL_ATTRIBUTES:
            attributes = [ALL_ATTRIBUTES]
        if isinstance(attributes, STRING_TYPES):
            attributes = [attributes]

        request = search_operation(self.base,
                                   self.filter,
                                   self.scope,
                                   self.dereference_aliases,
                                   attributes,
                                   self.size_limit,
                                   self.time_limit,
                                   False,
                                   self.connection.auto_escape,
                                   self.connection.auto_encode,
                                   self.connection.server.schema if self.connection.server else None,
                                   validator=self.connection.server.custom_validator if self.connection.server else None,
                                   check_names=self.connection.check_names)
        controls = list(self.controls)
        controls.append(sync_request_control(self.mode, self.cookie, self.reload_hint, self.criticality))
        with self.connection.connection_lock:
            self.message_id = self.connection.strategy.send('searchRequest', request, controls)

    def stop(self):
        if self.message_id is not None and not self.done:
            self.connection.abandon(self.message_id)
        self.message_id = None

    def ack(self):
        """Confirm that all events delivered so far have been processed.

        Advances the resumable position (the cookie attribute) to the
        latest cookie received from the server. Events delivered but
        not yet acknowledged are never covered by the stored cookie.
        """
        self.cookie = self._pending_cookie

    def events(self):
        if self.done:
            return
        if self.message_id is None:
            self.start()
        for message in self._receive_messages():
            if message['type'] == 'searchResEntry':
                events = self._entry_events(message)
            elif message['type'] == 'intermediateResponse':
                events = self._sync_info_events(message)
            elif message['type'] == 'searchResDone':
                events = self._done_events(message)
                self.done = True
            else:  # searchResRef and unexpected messages are not content sync events
                events = []
            for event in events:
                yield event
            if self.done:
                return

    def __iter__(self):
        return self.events()

    def _receive_messages(self):
        while True:
            responses = self.connection.strategy.receiving()
            if not responses:
                self.connection.last_error = 'connection closed by server during content synchronization'
                raise LDAPSocketReceiveError(self.connection.last_error)
            for response in responses:
                if self.connection.usage:
                    self.connection._usage.update_received_message(len(response))
                if self.connection.fast_decoder:
                    ldap_message = decode_message_fast(response)
                    dict_response = self.connection.strategy.decode_response_fast(ldap_message)
                else:
                    ldap_message, _ = decoder.decode(response, asn1Spec=LDAP_MESSAGE_TEMPLATE)
                    dict_response = self.connection.strategy.decode_response(ldap_message)
                message_id = int(ldap_message['messageID'])
                if message_id == self.message_id:
                    yield dict_response
                elif message_id == 0:  # unsolicited notification, as per RFC4511 (paragraph 4.4)
                    if dict_response.get('responseName') == '1.3.6.1.4.1.1466.20036':  # Notice of Disconnection
                        self.connection.last_error = 'session terminated by server during content synchronization'
                        raise LDAPSocketReceiveError(self.connection.last_error)
                    raise LDAPExtensionError('unknown unsolicited notification from server during content synchronization')
                else:
                    raise LDAPExtensionError('unexpected message id %d received during content synchronization' % message_id)

    def _close_refresh_events(self):
        # the refresh stage is complete, its boundary has been fully received
        if not self.in_refresh:
            return []
        self.in_refresh = False
        self._refresh_close_pending = False
        if self.mode == REFRESH_AND_PERSIST:
            return [{'type': 'persist_begin',
                     'cookie': self._pending_cookie}]
        return []

    def _entry_events(self, message):
        controls = message.get('controls') or {}
        if SYNC_STATE_CONTROL not in controls:
            raise LDAPExtensionError('missing Sync State control in search result entry during content synchronization')
        sync_state = controls[SYNC_STATE_CONTROL]['value']
        cookie = sync_state['cookie']
        if cookie is not None:
            self._pending_cookie = cookie
        state = sync_state['state']
        events = []
        if self._refresh_close_pending or (self.in_refresh and self.mode == REFRESH_AND_PERSIST and state != 'present' and not self._delete_phase_open):
            # an add/modify/delete entry outside a delete phase means the persist stage has begun
            events.extend(self._close_refresh_events())
        events.append({'type': state,
                       'entry_uuid': self._format_uuid(sync_state['entry_uuid']),
                       'dn': message.get('dn'),
                       'attributes': message.get('attributes'),
                       'raw_attributes': message.get('raw_attributes'),
                       'cookie': self._pending_cookie})
        return events

    def _sync_info_events(self, message):
        if message.get('responseName') != SYNC_INFO_MESSAGE:
            return []  # not a Sync Info message, nothing to do
        info = decode_sync_info_value(message['responseValue'])
        info_type = info['type']
        if info_type == 'refreshDelete' and not info['refresh_done']:
            # a delete phase reopens the refresh stage after the present phase
            self._refresh_close_pending = False
            self._delete_phase_open = True
            if info['cookie'] is not None:
                self._pending_cookie = info['cookie']
            return [{'type': 'phase_begin',
                     'phase': 'delete',
                     'cookie': self._pending_cookie}]
        events = []
        if self._refresh_close_pending:
            events.extend(self._close_refresh_events())
        if info['cookie'] is not None:
            self._pending_cookie = info['cookie']
        if info_type == 'newcookie':
            events.append({'type': 'new_cookie',
                           'cookie': self._pending_cookie})
        elif info_type == 'refreshPresent':
            if info['refresh_done']:
                events.append({'type': 'phase_end',
                               'phase': 'present',
                               'cookie': self._pending_cookie})
                if self.mode == REFRESH_AND_PERSIST and not self._delete_phase_open:
                    # the refresh stage may be over, but a delete phase could still follow
                    self._refresh_close_pending = True
            else:
                events.append({'type': 'phase_begin',
                               'phase': 'present',
                               'cookie': self._pending_cookie})
        elif info_type == 'refreshDelete':  # refresh_done is True here
            self._delete_phase_open = False
            events.append({'type': 'phase_end',
                           'phase': 'delete',
                           'cookie': self._pending_cookie})
            events.extend(self._close_refresh_events())
        elif info_type == 'syncIdSet':
            events.append({'type': 'id_set',
                           'phase': 'delete' if info['refresh_deletes'] else 'present',
                           'entry_uuids': [self._format_uuid(entry_uuid) for entry_uuid in info['entry_uuids']],
                           'cookie': self._pending_cookie})
        return events

    def _done_events(self, message):
        events = []
        if self._refresh_close_pending:
            events.extend(self._close_refresh_events())
        controls = message.get('controls') or {}
        refresh_deletes = False
        if SYNC_DONE_CONTROL in controls:
            sync_done = controls[SYNC_DONE_CONTROL]['value']
            refresh_deletes = sync_done['refresh_deletes']
            if sync_done['cookie'] is not None:
                self._pending_cookie = sync_done['cookie']
        result_code = message['result']
        self.in_refresh = False
        if result_code == RESULT_SUCCESS:
            events.append({'type': 'sync_done',
                           'refresh_deletes': refresh_deletes,
                           'cookie': self._pending_cookie})
        elif result_code == RESULT_E_SYNC_REFRESH_REQUIRED:
            # the server requires a full re-refresh, the stored cookie is no longer usable
            self.cookie = None
            self._pending_cookie = None
            events.append({'type': 'refresh_required',
                           'result': result_code,
                           'description': message.get('description'),
                           'message': message.get('message'),
                           'cookie': None})
        else:
            events.append({'type': 'error',
                           'result': result_code,
                           'description': message.get('description'),
                           'message': message.get('message'),
                           'cookie': self._pending_cookie})
        return events

    @staticmethod
    def _format_uuid(entry_uuid):
        try:
            return entry_uuid.decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            return entry_uuid
