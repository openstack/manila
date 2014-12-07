# Copyright (c) 2014 eBay Inc.
# Copyright (c) 2015 Rushil Chugh
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

from manila.api import common


class ViewBuilder(common.ViewBuilder):
    """Model scheduler-stats API responses as a python dictionary."""

    _collection_name = "scheduler-stats"

    def summary(self, request, pool):
        """Summary view of a single pool."""
        return {
            'pool': {
                'name': pool.get('name'),
            }
        }

    def detail(self, request, pool):
        """Detailed view of a single pool."""
        return {
            'pool': {
                'name': pool.get('name'),
                'capabilities': pool.get('capabilities'),
            }
        }

    def pools(self, request, pools, detail):
        """Summary view of a list of pools seen by scheduler."""
        pdict = self.detail if detail else self.summary

        return {"pools": [pdict(request, pool)['pool'] for pool in pools]}
