# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Handles all requests to Glance.
"""

from keystoneauth1 import loading as ks_loading
import openstack
from oslo_config import cfg

from manila.common import client_auth
from manila.common.config import core_opts
from manila.db import base

GLANCE_GROUP = 'glance'


glance_opts = [
    cfg.StrOpt('api_microversion',
               default='2',
               help='Version of Glance API to be used.'),
    cfg.StrOpt('region_name',
               default='RegionOne',
               help='Region name for connecting to glance.'),
    cfg.StrOpt('endpoint_type',
               default='publicURL',
               choices=['publicURL', 'internalURL', 'adminURL',
                        'public', 'internal', 'admin'],
               help='Endpoint type to be used with glance client calls.'),
    ]

CONF = cfg.CONF
CONF.register_opts(core_opts)
CONF.register_opts(glance_opts, GLANCE_GROUP)
ks_loading.register_session_conf_options(CONF, GLANCE_GROUP)
ks_loading.register_auth_conf_options(CONF, GLANCE_GROUP)


def list_opts():
    return client_auth.AuthClientLoader.list_opts(GLANCE_GROUP)


def openstackclient(context):
    auth = ks_loading.load_auth_from_conf_options(CONF, 'glance')
    session = ks_loading.load_session_from_conf_options(
        CONF, 'glance', auth=auth)
    return openstack.connection.Connection(
        session=session,
        context=context,
        image_version=CONF[GLANCE_GROUP].api_microversion,
        image_interface=CONF[GLANCE_GROUP].endpoint_type,
        region_name=CONF[GLANCE_GROUP].region_name)


class API(base.Base):

    def image_list(self, context):
        client = openstackclient(context)
        return client.image.images()
