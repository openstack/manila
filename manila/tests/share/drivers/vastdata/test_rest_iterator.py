# Copyright 2026 VAST Data Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from unittest import mock

from manila import exception as manila_exception
from manila.share.drivers.vastdata import driver_util
from manila.share.drivers.vastdata.rest_iterator import DEFAULT_PAGE_SIZE
from manila.share.drivers.vastdata.rest_iterator import ResourceIterator
from manila import test


class TestResourceIterator(test.TestCase):

    def setUp(self):
        super(TestResourceIterator, self).setUp()
        self.mock_session = mock.MagicMock()
        self.mock_resource = mock.MagicMock()
        self.mock_resource.session = self.mock_session
        self.mock_resource.resource_name = "testresources"

    def _make_iterator(self, initial_params=None, page_size=None):
        kwargs = {"resource": self.mock_resource}
        if initial_params is not None:
            kwargs["initial_params"] = initial_params
        if page_size is not None:
            kwargs["page_size"] = page_size
        return ResourceIterator(**kwargs)

    def test_init_sets_default_page_size(self):
        iterator = self._make_iterator(initial_params={"name": "foo"})
        self.assertEqual(
            {
                "name": "foo",
                "page_size": DEFAULT_PAGE_SIZE,
            },
            iterator.initial_params,
        )

    def test_init_preserves_explicit_page_size_param(self):
        iterator = self._make_iterator(
            initial_params={"page_size": 50}, page_size=100)
        self.assertEqual({"page_size": 50}, iterator.initial_params)

    def test_init_skips_page_size_when_disabled(self):
        iterator = self._make_iterator(
            initial_params={"name": "foo"}, page_size=0)
        self.assertEqual({"name": "foo"}, iterator.initial_params)

    def test_process_paginated_response(self):
        iterator = self._make_iterator()
        response = driver_util.Bunch.from_dict({
            "count": 2,
            "next": "https://host/api/testresources/?page=2",
            "previous": None,
            "results": [{"id": 1}, {"id": 2}],
        })
        result = iterator._process_response(response)
        self.assertEqual([{"id": 1}, {"id": 2}], result)
        self.assertEqual(2, iterator.count())
        self.assertEqual(
            "https://host/api/testresources/?page=2", iterator._next_url)
        iterator._initialized = True
        self.assertTrue(iterator.has_next())

    def test_process_bare_list_response(self):
        iterator = self._make_iterator()
        result = iterator._process_response([{"id": 1}, {"id": 2}])
        self.assertEqual([{"id": 1}, {"id": 2}], result)
        self.assertEqual(2, iterator.count())
        self.assertIsNone(iterator._next_url)
        iterator._initialized = True
        self.assertFalse(iterator.has_next())

    def test_process_single_bunch_response(self):
        iterator = self._make_iterator()
        response = driver_util.Bunch(id=1, name="solo")
        result = iterator._process_response(response)
        self.assertEqual([response], result)
        self.assertEqual(1, iterator.count())
        self.assertIsNone(iterator._next_url)
        iterator._initialized = True
        self.assertFalse(iterator.has_next())

    def test_process_unexpected_response_type(self):
        iterator = self._make_iterator()
        self.assertRaises(
            manila_exception.VastApiException,
            iterator._process_response,
            "not-valid",
        )

    def test_process_empty_results(self):
        iterator = self._make_iterator()
        response = driver_util.Bunch.from_dict({
            "count": 0,
            "next": None,
            "previous": None,
            "results": None,
        })
        result = iterator._process_response(response)
        self.assertEqual([], result)
        self.assertEqual(0, iterator.count())
        self.assertIsNone(iterator._next_url)
        iterator._initialized = True
        self.assertFalse(iterator.has_next())

    def test_next_fetches_first_page(self):
        page = driver_util.Bunch.from_dict({
            "count": 1,
            "next": None,
            "previous": None,
            "results": [{"id": 1}],
        })
        self.mock_session.get.return_value = page
        iterator = self._make_iterator(initial_params={"name": "x"})

        result = iterator.next()

        self.assertEqual([{"id": 1}], result)
        self.mock_session.get.assert_called_once_with(
            "testresources",
            params={"name": "x", "page_size": DEFAULT_PAGE_SIZE},
        )
        self.assertTrue(iterator._initialized)

    def test_next_follows_next_url(self):
        page1 = driver_util.Bunch.from_dict({
            "count": 3,
            "next": "https://host/api/testresources/?page=2&page_size=2",
            "previous": None,
            "results": [{"id": 1}, {"id": 2}],
        })
        page2 = driver_util.Bunch.from_dict({
            "count": 3,
            "next": None,
            "previous": None,
            "results": [{"id": 3}],
        })
        self.mock_session.get.return_value = page1
        self.mock_session.request.return_value = page2
        iterator = self._make_iterator()

        first = iterator.next()
        second = iterator.next()
        third = iterator.next()

        self.assertEqual([{"id": 1}, {"id": 2}], first)
        self.assertEqual([{"id": 3}], second)
        self.assertEqual([], third)
        self.mock_session.request.assert_called_once_with(
            "GET",
            "testresources",
            params={"page": "2", "page_size": "2"},
        )

    def test_fetch_page_strips_api_prefix_and_keeps_query_params(self):
        page = driver_util.Bunch.from_dict({
            "count": 1,
            "next": None,
            "previous": None,
            "results": [{"path": "/bright-flea/a"}],
        })
        self.mock_session.request.return_value = page
        iterator = self._make_iterator()
        iterator._initialized = True
        iterator._next_url = (
            "https://host/api/v1/views/"
            "?fields=path&page=2&path__startswith=%2Fbright-flea"
        )

        result = iterator.next()

        self.assertEqual([{"path": "/bright-flea/a"}], result)
        self.mock_session.request.assert_called_once_with(
            "GET",
            "v1/views",
            params={
                "fields": "path",
                "page": "2",
                "path__startswith": "/bright-flea",
            },
        )

    def test_all_aggregates_pages(self):
        page1 = driver_util.Bunch.from_dict({
            "count": 3,
            "next": "https://host/api/testresources/?page=2",
            "previous": None,
            "results": [{"id": 1}, {"id": 2}],
        })
        page2 = driver_util.Bunch.from_dict({
            "count": 3,
            "next": None,
            "previous": None,
            "results": [{"id": 3}],
        })
        self.mock_session.get.return_value = page1
        self.mock_session.request.return_value = page2
        iterator = self._make_iterator()

        self.assertEqual(
            [{"id": 1}, {"id": 2}, {"id": 3}], iterator.all())

    def test_all_after_partial_iteration(self):
        page1 = driver_util.Bunch.from_dict({
            "count": 3,
            "next": "https://host/api/testresources/?page=2",
            "previous": None,
            "results": [{"id": 1}, {"id": 2}],
        })
        page2 = driver_util.Bunch.from_dict({
            "count": 3,
            "next": None,
            "previous": None,
            "results": [{"id": 3}],
        })
        self.mock_session.get.return_value = page1
        self.mock_session.request.return_value = page2
        iterator = self._make_iterator()
        iterator.next()

        self.assertEqual(
            [{"id": 1}, {"id": 2}, {"id": 3}], iterator.all())

    def test_has_next_before_initialization(self):
        iterator = self._make_iterator()
        self.assertTrue(iterator.has_next())

    def test_count_before_fetch(self):
        iterator = self._make_iterator()
        self.assertEqual(-1, iterator.count())

    def test_python_iterator_protocol(self):
        page1 = driver_util.Bunch.from_dict({
            "count": 3,
            "next": "https://host/api/testresources/?page=2",
            "previous": None,
            "results": [{"id": 1}],
        })
        page2 = driver_util.Bunch.from_dict({
            "count": 3,
            "next": None,
            "previous": None,
            "results": [{"id": 2}],
        })
        self.mock_session.get.return_value = page1
        self.mock_session.request.return_value = page2
        iterator = self._make_iterator()

        pages = list(iterator)

        self.assertEqual([[{"id": 1}], [{"id": 2}]], pages)
        self.assertRaises(StopIteration, next, iterator)
