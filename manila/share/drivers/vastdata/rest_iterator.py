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

"""Resource iterator for automatic VMS pagination handling.

Handles both paginated responses ({results, count, next, previous}) and
plain list responses.
"""

import urllib.parse

from manila import exception
from manila.share.drivers.vastdata import driver_util

DEFAULT_PAGE_SIZE = 1000


class ResourceIterator:
    """Iterate VAST API list results across paginated and non-paginated shapes.

    Newer VMS versions return list endpoints as::

        {"count": N, "next": "...", "previous": "...", "results": [...]}

    Older versions may return a bare list. This iterator normalizes both so
    callers always consume lists of objects, and follows ``next`` until all
    pages are fetched.
    """

    def __init__(self, resource, initial_params=None,
                 page_size=DEFAULT_PAGE_SIZE):
        self.resource = resource
        self.session = resource.session
        self.initial_params = dict(initial_params or {})
        self._page_size = page_size

        if self._page_size > 0 and 'page_size' not in self.initial_params:
            self.initial_params['page_size'] = self._page_size

        self._initialized = False
        self._current = []
        self._next_url = None
        self._previous_url = None
        self._total_count = -1
        self._current_page = 0

    def _fetch_page(self, url=None, params=None):
        if url:
            # Keep api_method path-only; pass query via params so slash-join in
            # request() cannot corrupt values (e.g. path__startswith=/foo).
            parsed = urllib.parse.urlparse(url)
            path = parsed.path or ""
            if path.startswith("/api/"):
                path = path[len("/api/"):]
            path = path.strip("/")

            query_params = dict(
                urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            )
            response = self.session.request(
                "GET", path, params=query_params or None
            )
        else:
            response = self.session.get(
                self.resource.resource_name,
                params=params or self.initial_params,
            )
        return self._process_response(response)

    def _process_response(self, response):
        if (isinstance(response, driver_util.Bunch) and
                'results' in response and 'count' in response):
            self._current = list(response.results or [])
            self._total_count = response.count or 0
            self._next_url = response.get('next')
            self._previous_url = response.get('previous')
        elif isinstance(response, (list, tuple)):
            self._current = list(response)
            self._total_count = len(self._current)
            self._next_url = None
            self._previous_url = None
        elif isinstance(response, driver_util.Bunch):
            self._current = [response]
            self._total_count = 1
            self._next_url = None
            self._previous_url = None
        else:
            raise exception.VastApiException(
                reason=(
                    "Unexpected response type in ResourceIterator: "
                    f"{type(response)}"
                )
            )
        return self._current

    def next(self):
        if not self._initialized:
            self._fetch_page(params=self.initial_params)
            self._initialized = True
            return self._current

        if not self.has_next():
            return []

        self._current_page += 1
        return self._fetch_page(url=self._next_url)

    def has_next(self):
        if not self._initialized:
            return True
        return bool(self._next_url)

    def count(self):
        return self._total_count

    def all(self):
        """Fetch all pages and return every record as one list."""
        all_records = []
        if not self._initialized:
            all_records.extend(self.next())
        else:
            all_records.extend(self._current)

        while self.has_next():
            all_records.extend(self.next())
        return all_records

    def __iter__(self):
        return self

    def __next__(self):
        if not self._initialized:
            return self.next()
        if not self.has_next():
            raise StopIteration
        return self.next()
