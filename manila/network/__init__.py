# Copyright 2013 OpenStack Foundation
# Copyright 2014 Mirantis Inc.
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

from oslo_config import cfg
from oslo_utils import importutils
import six

from manila.db import base as db_base
from manila import exception
from manila.i18n import _

network_opts = [
    cfg.StrOpt(
        'network_api_class',
        default='manila.network.neutron.'
                'neutron_network_plugin.NeutronNetworkPlugin',
        deprecated_group='DEFAULT',
        help='The full class name of the Networking API class to use.'),
]

CONF = cfg.CONF


def API(config_group_name=None, label='user'):
    """Selects class and config group of network plugin.

    :param config_group_name: name of config group to be used for
                              registration of networking opts.
    :returns: instance of networking plugin class
    """
    CONF.register_opts(network_opts, group=config_group_name)
    if config_group_name:
        network_api_class = getattr(CONF, config_group_name).network_api_class
    else:
        network_api_class = CONF.network_api_class
    cls = importutils.import_class(network_api_class)
    return cls(config_group_name=config_group_name, label=label)


@six.add_metaclass(abc.ABCMeta)
class NetworkBaseAPI(db_base.Base):
    """User network plugin for setting up main net interfaces."""

    def __init__(self, db_driver=None):
        super(NetworkBaseAPI, self).__init__(db_driver=db_driver)

    def _verify_share_network(self, share_server_id, share_network):
        if share_network is None:
            msg = _("'Share network' is not provided for setting up "
                    "network interfaces for 'Share server' "
                    "'%s'.") % share_server_id
            raise exception.NetworkBadConfigurationException(reason=msg)

    @abc.abstractmethod
    def allocate_network(self, context, share_server, share_network=None,
                         **kwargs):
        pass

    @abc.abstractmethod
    def deallocate_network(self, context, share_server_id):
        pass
