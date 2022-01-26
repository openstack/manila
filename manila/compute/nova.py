# Copyright 2014 Mirantis Inc.
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
Handles all requests to Nova.
"""

import functools

from keystoneauth1 import loading as ks_loading
from novaclient import client as nova_client
from novaclient import exceptions as nova_exception
from novaclient import utils
from oslo_config import cfg

from manila.common import client_auth
from manila.common.config import core_opts
from manila.db import base
from manila import exception
from manila.i18n import _

NOVA_GROUP = 'nova'
AUTH_OBJ = None


nova_opts = [
    cfg.StrOpt('api_microversion',
               default='2.10',
               help='Version of Nova API to be used.'),
    cfg.StrOpt('endpoint_type',
               default='publicURL',
               help='Endpoint type to be used with nova client calls.'),
    cfg.StrOpt('region_name',
               help='Region name for connecting to nova.'),
    ]

CONF = cfg.CONF
CONF.register_opts(core_opts)
CONF.register_opts(nova_opts, NOVA_GROUP)
ks_loading.register_session_conf_options(CONF,
                                         NOVA_GROUP)
ks_loading.register_auth_conf_options(CONF, NOVA_GROUP)


def list_opts():
    return client_auth.AuthClientLoader.list_opts(NOVA_GROUP)


def novaclient(context):
    global AUTH_OBJ
    if not AUTH_OBJ:
        AUTH_OBJ = client_auth.AuthClientLoader(
            client_class=nova_client.Client, cfg_group=NOVA_GROUP)
    return AUTH_OBJ.get_client(context,
                               version=CONF[NOVA_GROUP].api_microversion,
                               endpoint_type=CONF[NOVA_GROUP].endpoint_type,
                               region_name=CONF[NOVA_GROUP].region_name)


def _untranslate_server_summary_view(server):
    """Maps keys for servers summary view."""
    d = {}
    d['id'] = server.id
    d['status'] = server.status
    d['flavor'] = server.flavor['id']
    d['name'] = server.name
    d['image'] = server.image['id']
    d['created'] = server.created
    d['addresses'] = server.addresses
    d['networks'] = server.networks
    d['tenant_id'] = server.tenant_id
    d['user_id'] = server.user_id
    d['security_groups'] = getattr(server, 'security_groups', [])

    return d


def _to_dict(obj):
    if isinstance(obj, dict):
        return obj
    elif hasattr(obj, 'to_dict'):
        return obj.to_dict()
    else:
        return obj.__dict__


def translate_server_exception(method):
    """Transforms the exception for the instance.

    Note: keeps its traceback intact.
    """

    @functools.wraps(method)
    def wrapper(self, ctx, instance_id, *args, **kwargs):
        try:
            res = method(self, ctx, instance_id, *args, **kwargs)
            return res
        except nova_exception.ClientException as e:
            if isinstance(e, nova_exception.NotFound):
                raise exception.InstanceNotFound(instance_id=instance_id)
            elif isinstance(e, nova_exception.BadRequest):
                raise exception.InvalidInput(reason=str(e))
            else:
                raise exception.ManilaException(e)

    return wrapper


class API(base.Base):
    """API for interacting with novaclient."""

    def server_create(self, context, name, image, flavor, key_name=None,
                      user_data=None, security_groups=None,
                      block_device_mapping=None,
                      block_device_mapping_v2=None, nics=None,
                      availability_zone=None, instance_count=1,
                      admin_pass=None, meta=None):
        return _untranslate_server_summary_view(
            novaclient(context).servers.create(
                name, image, flavor, userdata=user_data,
                security_groups=security_groups, key_name=key_name,
                block_device_mapping=block_device_mapping,
                block_device_mapping_v2=block_device_mapping_v2,
                nics=nics, availability_zone=availability_zone,
                min_count=instance_count, admin_pass=admin_pass,
                meta=meta)
        )

    def server_delete(self, context, instance):
        novaclient(context).servers.delete(instance)

    @translate_server_exception
    def server_get(self, context, instance_id):
        return _untranslate_server_summary_view(
            novaclient(context).servers.get(instance_id)
        )

    def server_get_by_name_or_id(self, context, instance_name_or_id):
        try:
            server = utils.find_resource(
                novaclient(context).servers, instance_name_or_id)
        except nova_exception.CommandError:
            # we did not find the server in the current tenant,
            # and proceed searching in all tenants
            try:
                server = utils.find_resource(
                    novaclient(context).servers, instance_name_or_id,
                    all_tenants=True)
            except nova_exception.CommandError as e:
                msg = _("Failed to get Nova VM. %s") % e
                raise exception.ManilaException(msg)
        return _untranslate_server_summary_view(server)

    @translate_server_exception
    def server_reboot(self, context, instance_id, soft_reboot=False):
        hardness = 'SOFT' if soft_reboot else 'HARD'
        novaclient(context).servers.reboot(instance_id, hardness)

    @translate_server_exception
    def instance_volume_attach(self, context, instance_id, volume_id,
                               device=None):
        if device == 'auto':
            device = None
        return novaclient(context).volumes.create_server_volume(instance_id,
                                                                volume_id,
                                                                device)

    @translate_server_exception
    def instance_volume_detach(self, context, instance_id, att_id):
        return novaclient(context).volumes.delete_server_volume(instance_id,
                                                                att_id)

    @translate_server_exception
    def instance_volumes_list(self, context, instance_id):
        from manila.volume import cinder

        volumes = novaclient(context).volumes.get_server_volumes(instance_id)

        for volume in volumes:
            volume_data = cinder.cinderclient(context).volumes.get(volume.id)
            volume.name = volume_data.name

        return volumes

    @translate_server_exception
    def server_update(self, context, instance_id, name):
        return _untranslate_server_summary_view(
            novaclient(context).servers.update(instance_id, name=name)
        )

    def keypair_import(self, context, name, public_key):
        return novaclient(context).keypairs.create(name, public_key)

    def keypair_delete(self, context, keypair_id):
        novaclient(context).keypairs.delete(keypair_id)

    def keypair_list(self, context):
        return novaclient(context).keypairs.list()

    def add_security_group_to_server(self, context, server, security_group):
        return novaclient(context).servers.add_security_group(server,
                                                              security_group)
