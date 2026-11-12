"""
Tests for the explicit context that scopes an RFC 2696 paged-search cookie.

A paged-search cookie is an opaque server-side cursor reference: it may only be
replayed by the same search (base, scope, filter, attributes, controls and page
size) on the same connection and bound identity that received it. These tests use
the in-memory mock server and a request recorder that captures every wire request,
so two searches can be interleaved and identical cookie bytes can be injected into
different contexts without a real directory.
"""

import unittest

from ldap3 import Server, Connection, MOCK_SYNC, MOCK_ASYNC, SUBTREE, BASE, DEREF_ALWAYS
from ldap3.core.exceptions import LDAPPagedSearchContextError
from ldap3.extend.standard.PagedSearch import PagedSearchContext, CURSOR_RELEASED, CURSOR_DISCONNECTED, CURSOR_UNKNOWN

PAGED_OID = '1.2.840.113556.1.4.319'


class RequestRecorder(object):
    """Wraps connection.send/search to keep a decoded copy of every request and response cookie."""

    def __init__(self, connection):
        self.connection = connection
        self.recorded = []
        self.response_cookies = []  # cookies handed back by each paged-search response
        self._original_send = connection.send
        self._original_search = connection.search
        connection.send = self._send
        connection.search = self._search

    def _send(self, message_type, request, controls=None):
        payload = self._original_send(message_type, request, controls)
        decoded = self.connection.strategy.decode_request(message_type, request, controls)
        self.recorded.append((message_type, decoded, controls))
        return payload

    def _search(self, *args, **kwargs):
        result = self._original_search(*args, **kwargs)
        # post_send_search has now populated connection.result with the response controls
        try:
            self.response_cookies.append(
                self.connection.result['controls'][PAGED_OID]['value']['cookie'])
        except (KeyError, TypeError):
            self.response_cookies.append(None)
        return result

    def paged_requests(self):
        """List of (page_size, cookie) carried by each paged-search control."""
        paged = []
        for message_type, _, controls in self.recorded:
            if message_type != 'searchRequest' or not controls:
                continue
            for control in controls:
                decoded = self.connection.strategy.decode_control(control)
                if decoded[0] == PAGED_OID:
                    paged.append((decoded[1]['value']['size'], decoded[1]['value']['cookie']))
        return paged

    def search_requests(self):
        return [(message_type, request) for message_type, request, _ in self.recorded
                if message_type == 'searchRequest']

    def detach(self):
        self.connection.send = self._original_send
        self.connection.search = self._original_search


def build_connection(strategy=MOCK_SYNC, entries=10, user='cn=admin,o=lab', password='secret-pw'):
    server = Server('dummy-host')
    connection = Connection(server, user=user, password=password, client_strategy=strategy)
    connection.bind()
    for index in range(entries):
        connection.strategy.add_entry('cn=user%d,o=lab' % index,
                                      {'userPassword': 'pw', 'sn': 'sn%d' % index, 'revision': index})
    # two disjoint groups so different filters return independent, multi-page result sets
    for index in range(8):
        connection.strategy.add_entry('cn=alpha%d,o=lab' % index, {'userPassword': 'pw', 'sn': 'alpha'})
        connection.strategy.add_entry('cn=beta%d,o=lab' % index, {'userPassword': 'pw', 'sn': 'beta'})
    return connection


class TestPagedSearchContext(unittest.TestCase):
    def setUp(self):
        self.connection = build_connection()
        self.recorder = RequestRecorder(self.connection)

    def tearDown(self):
        if not self.connection.closed:
            self.connection.unbind()

    # ------------------------------------------------------------------ basics

    def test_generator_and_list_usages_are_kept(self):
        expected = 10 + 8 + 8  # user entries plus the alpha/beta groups
        generator_entries = list(
            self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                         search_scope=SUBTREE,
                                                         attributes=['sn'], paged_size=3))
        self.assertEqual(expected, len(generator_entries))

        list_entries = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                     search_scope=SUBTREE,
                                                                     attributes=['sn'], paged_size=3,
                                                                     generator=False)
        self.assertEqual(expected, len(list_entries))
        self.assertEqual(list_entries, self.connection.response)

    def test_first_request_has_no_cookie_and_later_requests_reuse_it(self):
        list(self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                          attributes=['sn'], paged_size=3))
        paged = self.recorder.paged_requests()
        self.assertGreater(len(paged), 1)
        self.assertEqual(b'', paged[0][1])  # first page always starts a fresh search
        for size, cookie in paged[1:]:
            self.assertEqual(3, size)
            self.assertTrue(cookie)  # every continuation request carries the server cookie

        # the server closes the result set by answering the last request with an empty cookie
        last_result = self.connection.result
        returned_cookie = last_result['controls'][PAGED_OID]['value']['cookie']
        self.assertEqual(b'', returned_cookie)

    def test_empty_result_needs_a_single_cookieless_request(self):
        entries = list(self.connection.extend.standard.paged_search('o=lab', '(cn=missing*)',
                                                                    attributes=['sn'], paged_size=3))
        self.assertEqual([], entries)
        paged = self.recorder.paged_requests()
        self.assertEqual(1, len(paged))
        self.assertEqual(b'', paged[0][1])

    def test_page_size_may_change_to_another_positive_value(self):
        # RFC 2696 permits changing the page size while paging, as long as it stays positive
        generator = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                  attributes=['sn'], paged_size=2)
        next(generator)
        context = generator.gi_frame.f_locals['context']
        context.verify_request_shape('o=lab', '(cn=*)', SUBTREE, DEREF_ALWAYS, ['sn'],
                                     0, 0, False, False, None)
        context.update_page_size(5)
        self.assertEqual(5, context.paged_size)
        # drain the two entries already buffered from the size-2 page, forcing a new wire request
        next(generator)
        next(generator)
        remaining = list(generator)
        self.assertEqual(26, 3 + len(remaining))
        sizes = [size for size, _ in self.recorder.paged_requests()]
        self.assertEqual(2, sizes[0])
        self.assertIn(5, sizes)

    def test_invalid_page_size_is_rejected_upfront(self):
        for bad_size in (0, -1, True, '3', 2.5):
            with self.assertRaises(LDAPPagedSearchContextError):
                list(self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                   attributes=['sn'], paged_size=bad_size))

    # ------------------------------------------------------------- interleaving

    def test_two_interleaved_searches_keep_their_own_cookies(self):
        first = self.connection.extend.standard.paged_search('o=lab', '(cn=alpha*)',
                                                             attributes=['sn'], paged_size=2)
        second = self.connection.extend.standard.paged_search('o=lab', '(cn=beta*)',
                                                              attributes=['sn'], paged_size=2)

        # interleave consumption: three entries from each search
        first_batch = [next(first), next(first), next(first)]
        second_batch = [next(second), next(second), next(second)]
        self.assertEqual(3, len(first_batch))
        self.assertEqual(3, len(second_batch))

        first_context = first.gi_frame.f_locals['context']
        second_context = second.gi_frame.f_locals['context']
        self.assertIsNot(first_context, second_context)
        self.assertTrue(first_context.cookie)
        self.assertTrue(second_context.cookie)
        self.assertNotEqual(first_context.cookie, second_context.cookie)

        # every continuation request replays a cookie returned by a previous response,
        # and each independent search starts with an empty cookie
        paged = self.recorder.paged_requests()
        response_cookies = self.recorder.response_cookies
        request_cookies = [cookie for _, cookie in paged]
        self.assertEqual(b'', request_cookies[0])  # first search starts fresh
        self.assertEqual(2, request_cookies.count(b''))  # two independent, fresh starts
        continuation = [cookie for cookie in request_cookies if cookie]
        self.assertTrue(continuation)
        for cookie in continuation:
            self.assertIn(cookie, response_cookies)

        # both cursors still resolve correctly when resumed in either order
        self.assertEqual(8, 3 + len(list(first)))
        self.assertEqual(8, 3 + len(list(second)))

        # and no request ever mixes one search's filter with the other search's cursor
        shapes = [str(request['filter']) for _, request in self.recorder.search_requests()]
        alpha_indexes = {index for index, filt in enumerate(shapes) if 'alpha' in filt}
        beta_indexes = {index for index, filt in enumerate(shapes) if 'beta' in filt}
        self.assertTrue(alpha_indexes and beta_indexes)
        self.assertFalse(alpha_indexes & beta_indexes)

    def test_identical_cookie_bytes_in_another_context_are_rejected(self):
        # A cookie value that is byte-identical must not be accepted when smuggled into a
        # different context, because the context (not the bytes) owns the cursor.
        donor = PagedSearchContext(self.connection,
                                   'o=lab', '(cn=user1*)', SUBTREE, DEREF_ALWAYS, ['sn'],
                                   0, 0, False, False, None, 2, False)
        donor.cookie = b'shared-cookie-bytes'

        other = PagedSearchContext(self.connection,
                                   'o=lab', '(cn=user2*)', SUBTREE, DEREF_ALWAYS, ['sn'],
                                   0, 0, False, False, None, 2, False)
        other.cookie = b'shared-cookie-bytes'

        self.assertEqual(donor.cookie, other.cookie)
        # a third connection/context presenting the same bytes for a different shape is invalid
        foreign = build_connection(entries=1)
        try:
            with self.assertRaises(LDAPPagedSearchContextError):
                donor.verify(foreign)
        finally:
            foreign.unbind()

    # -------------------------------------------------------- context hardening

    def test_rebind_invalidates_the_context(self):
        generator = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                 attributes=['sn'], paged_size=2)
        next(generator)
        context = generator.gi_frame.f_locals['context']

        # simulate a rebind on the same connection: bound identity changes
        self.connection.user = 'cn=someone-else,o=lab'
        with self.assertRaises(LDAPPagedSearchContextError):
            context.verify(self.connection)

        # once the buffered entries are drained the generator refuses the next page
        for _ in range(2):
            try:
                next(generator)
            except LDAPPagedSearchContextError:
                break
        else:
            self.fail('generator did not reject the rebound connection')
        generator.close()

    def test_real_rebind_to_another_identity_rejects_old_cookie(self):
        # a second, bindable identity on the same server
        self.connection.strategy.add_entry('cn=other,o=lab',
                                           {'userPassword': 'other-pw', 'sn': 'other'})
        generator = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                 attributes=['sn'], paged_size=2)
        next(generator)
        context = generator.gi_frame.f_locals['context']

        self.connection.rebind(user='cn=other,o=lab', password='other-pw')
        with self.assertRaises(LDAPPagedSearchContextError):
            context.verify(self.connection)
        generator.close()

    def test_server_switch_invalidates_the_context(self):
        generator = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                 attributes=['sn'], paged_size=2)
        next(generator)
        context = generator.gi_frame.f_locals['context']

        original_server = self.connection.server
        self.connection.server = Server('other-host')
        try:
            with self.assertRaises(LDAPPagedSearchContextError):
                context.verify(self.connection)
        finally:
            self.connection.server = original_server
        generator.close()

    def test_request_shape_change_is_rejected(self):
        context = PagedSearchContext(self.connection,
                                     'o=lab', '(cn=*)', SUBTREE, DEREF_ALWAYS, ['sn'],
                                     0, 0, False, False, None, 2, False)
        with self.assertRaises(LDAPPagedSearchContextError):
            context.verify_request_shape('ou=other,o=lab', '(cn=*)', SUBTREE, DEREF_ALWAYS, ['sn'],
                                         0, 0, False, False, None)
        with self.assertRaises(LDAPPagedSearchContextError):
            context.verify_request_shape('o=lab', '(uid=*)', SUBTREE, DEREF_ALWAYS, ['sn'],
                                         0, 0, False, False, None)
        with self.assertRaises(LDAPPagedSearchContextError):
            context.verify_request_shape('o=lab', '(cn=*)', BASE, DEREF_ALWAYS, ['sn'],
                                         0, 0, False, False, None)
        with self.assertRaises(LDAPPagedSearchContextError):
            context.verify_request_shape('o=lab', '(cn=*)', SUBTREE, DEREF_ALWAYS, ['mail'],
                                         0, 0, False, False, None)
        # page size is the only mutable part, but it must stay a positive integer
        for bad_size in (0, -3, True, '4', 1.5):
            with self.assertRaises(LDAPPagedSearchContextError):
                context.update_page_size(bad_size)
        context.update_page_size(7)
        self.assertEqual(7, context.paged_size)

    def test_context_error_messages_do_not_leak_credentials_or_entries(self):
        context = PagedSearchContext(self.connection,
                                     'o=lab', '(cn=secret*)', SUBTREE, DEREF_ALWAYS, ['sn'],
                                     0, 0, False, False, None, 2, False)
        foreign = build_connection(entries=1, password='another-secret')
        try:
            try:
                context.verify(foreign)
            except LDAPPagedSearchContextError as exc:
                message = str(exc)
                self.assertNotIn('secret-pw', message)
                self.assertNotIn('another-secret', message)
                self.assertNotIn('cn=secret', message)
                self.assertIn('paged search context', message)
            else:
                self.fail('expected LDAPPagedSearchContextError')
        finally:
            foreign.unbind()

    # ------------------------------------------------------------- cursor release

    def test_early_close_releases_the_cursor_with_size_zero(self):
        generator = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                 attributes=['sn'], paged_size=3)
        next(generator)
        context = generator.gi_frame.f_locals['context']
        self.assertEqual(1, len(self.connection.strategy._paged_sets))

        generator.close()

        self.assertEqual(0, len(self.connection.strategy._paged_sets))
        paged = self.recorder.paged_requests()
        release = paged[-1]
        self.assertEqual(0, release[0])          # RFC 2696 abandon request
        self.assertTrue(release[1])              # carries the open cursor cookie
        self.assertTrue(context.released)

    def test_release_statuses_are_distinguished(self):
        # open cursor, healthy connection -> released; repeated release stays idempotent
        generator = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                 attributes=['sn'], paged_size=3)
        next(generator)
        live_context = generator.gi_frame.f_locals['context']
        self.assertEqual(CURSOR_RELEASED, live_context.release_cursor())
        self.assertTrue(live_context.released)
        self.assertEqual(CURSOR_RELEASED, live_context.release_cursor())
        generator.close()

        # a context that never opened a cursor reports a no-op release as released
        idle = PagedSearchContext(self.connection, 'o=lab', '(cn=*)', SUBTREE, DEREF_ALWAYS, ['sn'],
                                  0, 0, False, False, None, 2, False)
        self.assertEqual(CURSOR_RELEASED, idle.release_cursor())

    def test_release_against_disconnected_connection(self):
        generator = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                 attributes=['sn'], paged_size=3)
        next(generator)
        context = generator.gi_frame.f_locals['context']
        self.connection.unbind()
        self.recorder.detach()

        status = context.release_cursor()
        self.assertEqual(CURSOR_DISCONNECTED, status)
        self.assertIsNone(context.cookie)  # stale state is dropped, never reusable
        self.assertTrue(context.finished)

    def test_release_failure_invalidates_state_so_it_is_not_reused(self):
        generator = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                 attributes=['sn'], paged_size=3)
        next(generator)
        context = generator.gi_frame.f_locals['context']

        # force the release search to fail; outcome must be 'unknown' and the cookie discarded
        def failing_search(*args, **kwargs):
            raise RuntimeError('late response lost')

        self.connection.search = failing_search
        status = context.release_cursor()
        self.assertEqual(CURSOR_UNKNOWN, status)
        self.assertIsNone(context.cookie)
        self.assertTrue(context.finished)
        self.assertFalse(context.released)

    def test_late_response_after_release_does_not_resurrect_cursor(self):
        generator = self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                 attributes=['sn'], paged_size=3)
        next(generator)
        context = generator.gi_frame.f_locals['context']
        generator.close()
        self.assertTrue(context.released)
        self.assertIsNone(context.cookie)

        # a brand new search must start cookie-less even if a late page response arrived meanwhile
        fresh = list(self.connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                   attributes=['sn'], paged_size=3))
        self.assertEqual(26, len(fresh))
        paged = self.recorder.paged_requests()
        # locate the first request of the new search: it follows the size-0 release request
        release_index = next(index for index, (size, _) in enumerate(paged) if size == 0)
        self.assertEqual(b'', paged[release_index + 1][1])

    def test_async_strategy_early_close_releases_cursor(self):
        async_connection = build_connection(strategy=MOCK_ASYNC)
        recorder = RequestRecorder(async_connection)
        try:
            generator = async_connection.extend.standard.paged_search('o=lab', '(cn=*)',
                                                                       attributes=['sn'], paged_size=3)
            next(generator)
            self.assertEqual(1, len(async_connection.strategy._paged_sets))
            generator.close()
            self.assertEqual(0, len(async_connection.strategy._paged_sets))
            self.assertEqual(0, recorder.paged_requests()[-1][0])
        finally:
            recorder.detach()
            async_connection.unbind()


if __name__ == '__main__':
    unittest.main()
