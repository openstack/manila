# Copyright 2013 Openstack Foundation
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
import abc

from oslo.config import cfg
import oslo.utils.importutils

network_opts = [
    cfg.StrOpt('network_api_class',
               default='manila.network.neutron.'
                       'neutron_network_plugin.NeutronNetworkPlugin',
               help='The full class name of the Networking API class to use.'),
]

cfg.CONF.register_opts(network_opts)


def API():
    importutils = oslo.utils.importutils
    network_api_class = cfg.CONF.network_api_class
    cls = importutils.import_class(network_api_class)
    return cls()


class NetworkBaseAPI(object):

    @abc.abstractmethod
    def allocate_network(self, context, network_id, subnet_id, **kwargs):
        pass

    @abc.abstractmethod
    def deallocate_network(self, context, share_server_id):
        pass

    @abc.abstractmethod
    def get_provider_info(self, context, network_id, subnet_id):
        pass
