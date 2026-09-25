"""Server Side Sort and Virtual List View search."""

from ... import SUBTREE, DEREF_ALWAYS, SEQUENCE_TYPES
from ...core.exceptions import LDAPExtensionError
from ...protocol.rfc2891 import sort_request_control, SORT_RESPONSE_CONTROL, SortKey, normalize_sort_keys
from ...protocol.virtualListView import vlv_request_control, VLV_RESPONSE_CONTROL
from ...utils.conv import to_raw, to_unicode
from ...utils.dn import safe_dn


class VLVSearch(object):
    def __init__(self,
                 connection,
                 search_base,
                 search_filter,
                 sort_keys,
                 search_scope=SUBTREE,
                 dereference_aliases=DEREF_ALWAYS,
                 attributes=None,
                 size_limit=0,
                 time_limit=0,
                 types_only=False,
                 get_operational_attributes=False,
                 controls=None,
                 sort_criticality=False,
                 vlv_criticality=False,
                 context_id=None):
        self.connection = connection
        if connection.check_names and search_base:
            search_base = safe_dn(search_base)

        self.search_base = search_base
        self.search_filter = search_filter
        self.sort_keys = normalize_sort_keys(sort_keys)
        self.search_scope = search_scope
        self.dereference_aliases = dereference_aliases
        self.attributes = attributes
        self.size_limit = size_limit
        self.time_limit = time_limit
        self.types_only = types_only
        self.get_operational_attributes = get_operational_attributes
        self.controls = list(controls) if isinstance(controls, SEQUENCE_TYPES) else []
        self.sort_criticality = sort_criticality
        self.vlv_criticality = vlv_criticality
        self.context_id = context_id
        self._context_signature = None
        self.message_id = None
        self.response = []
        self.result = None
        self.sort_result = None
        self.vlv_result = None
        self._context_registry = getattr(connection, '_ldap3_vlv_contexts', None)
        if self._context_registry is None:
            self._context_registry = {}
            connection._ldap3_vlv_contexts = self._context_registry

    def _signature(self):
        return self._text(self.search_base), self._text(self.search_filter), tuple(self._sort_key_signature(sort_key) for sort_key in self.sort_keys)

    @staticmethod
    def _text(value):
        return to_unicode(value) if isinstance(value, (str, bytes)) else value

    @staticmethod
    def _sort_key_signature(sort_key):
        if isinstance(sort_key, SortKey):
            return (bytes(sort_key['attributeType']).decode('utf-8'),
                    bytes(sort_key['orderingRule']).decode('utf-8') if sort_key['orderingRule'].hasValue() else None,
                    sort_key['reverseOrder'].hasValue() and bool(int(sort_key['reverseOrder'])))
        if isinstance(sort_key, (str, bytes)):
            return to_unicode(sort_key), None, False
        if isinstance(sort_key, dict):
            return (to_unicode(sort_key.get('attribute_type') or sort_key.get('attributeType')),
                    to_unicode(sort_key.get('ordering_rule') or sort_key.get('orderingRule')) if sort_key.get('ordering_rule') or sort_key.get('orderingRule') else None,
                    bool(sort_key.get('reverse_order', sort_key.get('reverseOrder', False))))
        if isinstance(sort_key, SEQUENCE_TYPES):
            if len(sort_key) == 1:
                return to_unicode(sort_key[0]), None, False
            if isinstance(sort_key[1], bool):
                return to_unicode(sort_key[0]), (to_unicode(sort_key[2]) if len(sort_key) > 2 else None), sort_key[1]
            return to_unicode(sort_key[0]), to_unicode(sort_key[1]), (sort_key[2] if len(sort_key) > 2 else False)
        return sort_key, None, False

    def _validate_context(self):
        if self.context_id is None:
            return
        signature = self._signature()
        context_id = to_raw(self.context_id)
        if self._context_signature is not None and self._context_signature != signature:
            raise LDAPExtensionError('VLV context cannot be reused when sort key, search base or search filter changes')
        if context_id in self._context_registry and self._context_registry[context_id] != signature:
            raise LDAPExtensionError('VLV context cannot be reused when sort key, search base or search filter changes')

    def _build_controls(self, before_count, after_count, offset, estimated_content_count, assertion_value, context_id):
        controls = list(self.controls)
        controls.append(sort_request_control(self.sort_keys, self.sort_criticality))
        controls.append(vlv_request_control(before_count,
                                            after_count,
                                            offset=offset,
                                            content_count=estimated_content_count,
                                            assertion_value=assertion_value,
                                            context_id=context_id,
                                            criticality=self.vlv_criticality))
        return controls

    def search(self,
               before_count,
               after_count=None,
               offset=None,
               estimated_content_count=0,
               assertion_value=None,
               greater_than_or_equal=None,
               context_id=None,
               timeout=None):
        if after_count is None:
            after_count = before_count
        if assertion_value is None:
            assertion_value = greater_than_or_equal
        elif greater_than_or_equal is not None:
            raise ValueError('assertion_value and greater_than_or_equal cannot be used together')
        if context_id is not None:
            self.context_id = context_id
        self.sort_result = None
        self.vlv_result = None
        self._validate_context()

        controls = self._build_controls(before_count,
                                        after_count,
                                        offset,
                                        estimated_content_count,
                                        assertion_value,
                                        self.context_id)
        self.message_id = self.connection.search(search_base=self.search_base,
                                                 search_filter=self.search_filter,
                                                 search_scope=self.search_scope,
                                                 dereference_aliases=self.dereference_aliases,
                                                 attributes=self.attributes,
                                                 size_limit=self.size_limit,
                                                 time_limit=self.time_limit,
                                                 types_only=self.types_only,
                                                 get_operational_attributes=self.get_operational_attributes,
                                                 controls=controls)
        if self.connection.strategy.sync:
            self._store_result(*self._get_completed_response())
        return self

    def get_response(self, timeout=None):
        if self.connection.strategy.sync:
            return self.response, self.result
        response, result = self.connection.get_response(self.message_id, timeout=timeout)
        self._store_result(response, result)
        return self.response, self.result

    def _get_completed_response(self):
        if self.connection.strategy.thread_safe:
            _, result, response, _ = self.message_id
            return response, result
        return self.connection.response, self.connection.result

    def _store_result(self, response, result):
        self.response = response
        self.result = result
        controls = result.get('controls', {}) if result else {}
        sort_control = controls.get(SORT_RESPONSE_CONTROL) or {}
        vlv_control = controls.get(VLV_RESPONSE_CONTROL) or {}
        self.sort_result = sort_control.get('value')
        self.vlv_result = vlv_control.get('value')
        if self.vlv_result is not None and self.vlv_result.get('context_id') is not None:
            self.context_id = self.vlv_result['context_id']
            self._context_signature = self._signature()
            self._context_registry[self.context_id] = self._context_signature
        return self

    @property
    def target_position(self):
        return None if self.vlv_result is None else self.vlv_result.get('target_position')

    @property
    def content_count(self):
        return None if self.vlv_result is None else self.vlv_result.get('content_count')

    @property
    def sort_result_code(self):
        return None if self.sort_result is None else self.sort_result.get('result')

    @property
    def vlv_result_code(self):
        return None if self.vlv_result is None else self.vlv_result.get('result')

    @property
    def sort_ok(self):
        return self.sort_result_code == 0

    @property
    def vlv_ok(self):
        return self.vlv_result_code == 0
