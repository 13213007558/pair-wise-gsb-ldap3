"""
"""

# Created on 2014.07.08
#
# Author: Giovanni Cannata
#
# Copyright 2014 - 2025 Giovanni Cannata
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

from ... import SUBTREE, DEREF_ALWAYS
from ...utils.dn import safe_dn
from ...core.results import DO_NOT_RAISE_EXCEPTIONS, RESULT_SIZE_LIMIT_EXCEEDED, RESULT_SUCCESS
from ...core.exceptions import LDAPOperationResult, LDAPPagedSearchContextError, LDAPCommunicationError
from ...utils.log import log, log_enabled, ERROR, BASIC, PROTOCOL

# OID of the RFC 2696 Simple Paged Results control
PAGED_SEARCH_CONTROL_OID = '1.2.840.113556.1.4.319'

# Outcomes of a best-effort cursor release attempt (RFC 2696, size 0 + cookie)
CURSOR_RELEASED = 'released'        # the server acknowledged an empty cookie, the cursor is gone
CURSOR_DISCONNECTED = 'disconnected'  # the connection is down, the server state cannot be reached
CURSOR_UNKNOWN = 'unknown'          # the release was attempted but could not be confirmed


def _server_identity(connection):
    """Stable identifier of the server a connection is talking to, without exposing credentials."""
    server = getattr(connection, 'server', None)
    if server is None:
        return None
    host = getattr(server, 'host', None)
    port = getattr(server, 'port', None)
    use_ssl = getattr(server, 'ssl', False)
    return host, port, bool(use_ssl)


def _control_signature(controls):
    """Hashable snapshot of the request controls, excluding the paged control itself.

    Only control OIDs, criticality and (for non-paged controls) values are kept; the
    opaque paged cookie must never be part of the fixed request shape.
    """
    if not controls:
        return ()
    signature = []
    for control in controls:
        if not control:
            continue
        oid, criticality, value = control
        if oid == PAGED_SEARCH_CONTROL_OID:
            # the paged control is re-issued by the search loop, never a fixed part of the shape
            continue
        signature.append((oid, bool(criticality), repr(value)))
    return tuple(signature)


class PagedSearchContext(object):
    """Explicit, per-search context that owns the RFC 2696 paged-search cookie.

    A cookie is an opaque server-side cursor reference, so it is only meaningful
    for the exact search (base, scope, filter, attributes, controls and page size)
    running on the exact connection and bound identity that received it. The
    context freezes all of these when the paged search starts and validates every
    subsequent page against them, so a stale cookie can never be replayed by a
    different search, connection or bind.
    """

    def __init__(self,
                 connection,
                 search_base,
                 search_filter,
                 search_scope,
                 dereference_aliases,
                 attributes,
                 size_limit,
                 time_limit,
                 types_only,
                 get_operational_attributes,
                 controls,
                 paged_size,
                 paged_criticality):
        self.connection = connection
        self.search_base = search_base
        self.search_filter = search_filter
        self.search_scope = search_scope
        self.dereference_aliases = dereference_aliases
        self.attributes = tuple(attributes) if isinstance(attributes, (list, tuple)) else attributes
        self.size_limit = size_limit
        self.time_limit = time_limit
        self.types_only = types_only
        self.get_operational_attributes = get_operational_attributes
        self.controls_signature = _control_signature(controls)
        self.paged_size = paged_size
        self.paged_criticality = paged_criticality
        # fixed binding/connection identity captured at search start
        self.server_identity = _server_identity(connection)
        self.bound = bool(getattr(connection, 'bound', False))
        self.bound_identity = getattr(connection, 'user', None)
        self.authentication = getattr(connection, 'authentication', None)
        # cookie lifecycle state
        self.cookie = True  # True forces the first, cookie-less search request
        self.finished = False  # set when the server returns an empty cookie
        self.released = False  # set once the cursor is known to be released

    def describe(self):
        """Short, non-sensitive label usable in error messages (no entries, filter values or credentials)."""
        return 'paged search context base=%r scope=%r page_size=%r' % (
            self.search_base, self.search_scope, self.paged_size)

    def verify(self, connection):
        """Ensure the cookie can still be used on ``connection`` for this same search."""
        if connection is not self.connection:
            raise LDAPPagedSearchContextError(
                '%s cannot be continued on a different connection' % self.describe())
        if _server_identity(connection) != self.server_identity:
            raise LDAPPagedSearchContextError(
                '%s cannot be continued because the target server changed' % self.describe())
        if bool(getattr(connection, 'bound', False)) != self.bound or \
                getattr(connection, 'user', None) != self.bound_identity or \
                getattr(connection, 'authentication', None) != self.authentication:
            raise LDAPPagedSearchContextError(
                '%s cannot be continued because the bound identity changed (rebind)' % self.describe())

    def switch_connection(self, connection):
        """Move the context onto a referral connection.

        Unlike an arbitrary connection change this is an explicit, protocol-driven
        hop: the search shape is unchanged and only a server-issued continuation can
        trigger it. A cookie received from another search can never reach this path.
        """
        self.connection = connection
        self.server_identity = _server_identity(connection)
        self.bound = bool(getattr(connection, 'bound', False))
        self.bound_identity = getattr(connection, 'user', None)
        self.authentication = getattr(connection, 'authentication', None)

    def verify_request_shape(self,
                             search_base,
                             search_filter,
                             search_scope,
                             dereference_aliases,
                             attributes,
                             size_limit,
                             time_limit,
                             types_only,
                             get_operational_attributes,
                             controls):
        """Validate the fixed part of the request; the mutable page size is checked separately."""
        attributes_tuple = tuple(attributes) if isinstance(attributes, (list, tuple)) else attributes
        if (search_base, search_filter, search_scope, dereference_aliases,
                attributes_tuple, size_limit, time_limit, types_only,
                get_operational_attributes, _control_signature(controls)) != \
                (self.search_base, self.search_filter, self.search_scope, self.dereference_aliases,
                 self.attributes, self.size_limit, self.time_limit, self.types_only,
                 self.get_operational_attributes, self.controls_signature):
            raise LDAPPagedSearchContextError(
                '%s cannot be continued with a different search request shape' % self.describe())

    def update_page_size(self, paged_size):
        """Adopt a new page size, which RFC 2696 allows as long as it stays a positive int."""
        if not isinstance(paged_size, int) or isinstance(paged_size, bool) or paged_size <= 0:
            raise LDAPPagedSearchContextError(
                '%s page size must be a positive integer when paging' % self.describe())
        self.paged_size = paged_size

    def store_cookie(self, result):
        """Extract the cookie returned by the server and update the lifecycle state."""
        try:
            cookie = result['controls'][PAGED_SEARCH_CONTROL_OID]['value']['cookie']
        except (KeyError, TypeError):
            cookie = None
        if not cookie:  # empty cookie: server closed the result set
            self.cookie = None
            self.finished = True
            self.released = True
        else:
            self.cookie = cookie
        return self.cookie

    def release_cursor(self):
        """Best-effort release of an open server cursor (RFC 2696 abandon: size 0, same cookie).

        Returns one of CURSOR_RELEASED, CURSOR_DISCONNECTED or CURSOR_UNKNOWN. Once the
        cursor is known to be released (or the connection is gone) the context cannot be
        resumed, so a failed release never leaves a reusable cookie behind.
        """
        if self.released or self.finished or not self.cookie or self.cookie is True:
            self.released = True
            return CURSOR_RELEASED

        connection = self.connection
        if getattr(connection, 'closed', False) or not getattr(connection, 'listening', False):
            # nothing reachable server-side; invalidate locally so the cookie is never reused
            self._invalidate()
            return CURSOR_DISCONNECTED

        try:
            message_id = connection.search(self.search_base,
                                           self.search_filter,
                                           self.search_scope,
                                           self.dereference_aliases,
                                           self.attributes,
                                           self.size_limit,
                                           self.time_limit,
                                           self.types_only,
                                           self.get_operational_attributes,
                                           None,  # paged control is supplied explicitly below
                                           0,     # RFC 2696: size 0 tells the server to drop the cursor
                                           self.paged_criticality,
                                           self.cookie)
            if not connection.strategy.sync:
                _, release_result = connection.get_response(message_id)
            else:
                if connection.strategy.thread_safe:
                    _, release_result, _, _ = message_id
                else:
                    release_result = connection.result
        except LDAPCommunicationError:
            # connection-level failure (socket closed, timeout ...): server state cannot be reached
            self._invalidate()
            return CURSOR_DISCONNECTED
        except Exception as exc:  # any other failure leaves the release unconfirmed
            if log_enabled(ERROR):
                log(ERROR, 'paged search cursor release unconfirmed for <%s>: <%s>', self.describe(), exc)
            self._invalidate()
            return CURSOR_UNKNOWN

        if release_result and release_result.get('result') == RESULT_SUCCESS:
            self.released = True
            self.finished = True
            self.cookie = None
            return CURSOR_RELEASED

        # the server answered but did not acknowledge the release; do not trust the cookie any more
        self._invalidate()
        return CURSOR_UNKNOWN

    def _invalidate(self):
        """Drop every piece of server-side state so it cannot be picked up by a later search."""
        self.cookie = None
        self.finished = True
        self.released = False


def paged_search_generator(connection,
                           search_base,
                           search_filter,
                           search_scope=SUBTREE,
                           dereference_aliases=DEREF_ALWAYS,
                           attributes=None,
                           size_limit=0,
                           time_limit=0,
                           types_only=False,
                           get_operational_attributes=False,
                           controls=None,
                           paged_size=100,
                           paged_criticality=False):
    if connection.check_names and search_base:
        search_base = safe_dn(search_base)

    if not isinstance(paged_size, int) or isinstance(paged_size, bool) or paged_size <= 0:
        raise LDAPPagedSearchContextError('paged search page size must be a positive integer')

    context = PagedSearchContext(connection,
                                 search_base,
                                 search_filter,
                                 search_scope,
                                 dereference_aliases,
                                 attributes,
                                 size_limit,
                                 time_limit,
                                 types_only,
                                 get_operational_attributes,
                                 controls,
                                 paged_size,
                                 paged_criticality)

    responses = []
    original_connection = None
    original_auto_referrals = connection.auto_referrals
    connection.auto_referrals = False  # disable auto referrals because it cannot handle paged searches
    cachekey = None  # for referrals cache

    try:
        while context.cookie:
            # every page must run on the same connection, bind identity and fixed request shape
            context.verify(connection)
            context.verify_request_shape(search_base,
                                         search_filter,
                                         search_scope,
                                         dereference_aliases,
                                         attributes,
                                         size_limit,
                                         time_limit,
                                         types_only,
                                         get_operational_attributes,
                                         controls)

            result = connection.search(search_base,
                                       search_filter,
                                       search_scope,
                                       dereference_aliases,
                                       attributes,
                                       size_limit,
                                       time_limit,
                                       types_only,
                                       get_operational_attributes,
                                       controls,
                                       context.paged_size,
                                       paged_criticality,
                                       None if context.cookie is True else context.cookie)

            if not connection.strategy.sync:
                response, result = connection.get_response(result)
            else:
                if connection.strategy.thread_safe:
                    _, result, response, _ = result
                else:
                    response = connection.response
                    result = connection.result

            if result['referrals'] and original_auto_referrals:  # if referrals are returned start over the loop with a new connection to the referral
                if not original_connection:
                    original_connection = connection
                _, connection, cachekey = connection.strategy.create_referral_connection(result['referrals'])   # change connection to a valid referral
                context.switch_connection(connection)  # explicit, protocol-driven hop keeping the same search shape
                continue

            responses.extend(response)
            context.store_cookie(result)

            if connection.raise_exceptions and result and result['result'] not in DO_NOT_RAISE_EXCEPTIONS:
                if log_enabled(PROTOCOL):
                    log(PROTOCOL, 'paged search operation result <%s> for <%s>', result, connection)
                if result['result'] == RESULT_SIZE_LIMIT_EXCEEDED:
                    while responses:
                        yield responses.pop()
                raise LDAPOperationResult(result=result['result'], description=result['description'], dn=result['dn'], message=result['message'], response_type=result['type'])

            while responses:
                yield responses.pop()
    except GeneratorExit:
        # iterator closed before exhaustion: try to release the server-side cursor
        release_status = context.release_cursor()
        if release_status == CURSOR_UNKNOWN:
            if log_enabled(ERROR):
                log(ERROR, 'paged search cursor release could not be confirmed for <%s>', context.describe())
        elif log_enabled(BASIC):
            log(BASIC, 'paged search cursor release status <%s> for <%s>', release_status, context.describe())
        raise
    finally:
        if original_connection:
            connection = original_connection
            if connection.use_referral_cache and cachekey:
                connection.strategy.referral_cache[cachekey] = connection
            else:
                connection.unbind()

        connection.auto_referrals = original_auto_referrals
        connection.response = None


def paged_search_accumulator(connection,
                             search_base,
                             search_filter,
                             search_scope=SUBTREE,
                             dereference_aliases=DEREF_ALWAYS,
                             attributes=None,
                             size_limit=0,
                             time_limit=0,
                             types_only=False,
                             get_operational_attributes=False,
                             controls=None,
                             paged_size=100,
                             paged_criticality=False):
    if connection.check_names and search_base:
        search_base = safe_dn(search_base)

    responses = []
    for response in paged_search_generator(connection,
                                           search_base,
                                           search_filter,
                                           search_scope,
                                           dereference_aliases,
                                           attributes,
                                           size_limit,
                                           time_limit,
                                           types_only,
                                           get_operational_attributes,
                                           controls,
                                           paged_size,
                                           paged_criticality):
        responses.append(response)

    connection.response = responses
    return responses
