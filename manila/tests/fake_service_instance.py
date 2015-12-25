#    Copyright 2014 Mirantis Inc.
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

import mock

from manila.tests import fake_compute


class FakeServiceInstanceManager(object):

    def __init__(self, *args, **kwargs):
        self.db = mock.Mock()
        self._helpers = {
            'CIFS': mock.Mock(),
            'NFS': mock.Mock(),
        }
        self.share_networks_locks = {}
        self.share_networks_servers = {}
        self.fake_server = fake_compute.FakeServer()
        self.service_instance_name_template = 'manila_fake_service_instance-%s'

    def get_service_instance(self, context, share_network_id, create=True):
        return self.fake_server

    def _create_service_instance(self, context, instance_name,
                                 share_network_id, old_server_ip):
        return self.fake_server

    def _delete_server(self, context, server):
        pass

    def _get_service_instance_name(self, share_network_id):
        return self.service_instance_name_template % share_network_id
