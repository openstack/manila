# Copyright 2026 SAP SE.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from manila.api import common


class ViewBuilder(common.ViewBuilder):
    """Model a qos type API response as a python dictionary."""

    _collection_name = 'qos_types'

    def show(self, request, qos_type, brief=False):
        """Trim away extraneous qos type attributes."""
        trimmed = {
            'id': qos_type.get('id'),
            'name': qos_type.get('name'),
            'description': qos_type.get('description'),
            'specs': qos_type.get('specs', {}),
            'created_at': qos_type.get('created_at'),
            'updated_at': qos_type.get('updated_at'),
        }
        return trimmed if brief else {"qos_type": trimmed}

    def index(self, request, qos_types):
        """Index over trimmed qos types."""
        qos_types_list = [
            self.show(request, qos_type, True)
            for qos_type in qos_types
        ]
        return {"qos_types": qos_types_list}
