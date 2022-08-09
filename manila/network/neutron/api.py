# Copyright 2013 OpenStack Foundation
# Copyright 2014 Mirantis Inc.
# All Rights Reserved
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

from keystoneauth1 import loading as ks_loading
from neutronclient.common import exceptions as neutron_client_exc
from neutronclient.v2_0 import client as clientv20
from oslo_config import cfg
from oslo_log import log

from manila.common import client_auth
from manila import context
from manila import exception
from manila.network.neutron import constants as neutron_constants

NEUTRON_GROUP = 'neutron'


neutron_opts = [
    cfg.StrOpt(
        'url',
        help='URL for connecting to neutron.'),
    cfg.IntOpt(
        'url_timeout',
        deprecated_for_removal=True,
        deprecated_reason='This parameter has had no effect since 2.0.0. '
                          'The timeout parameter should be used instead.',
        deprecated_since='Yoga',
        default=30,
        help='Timeout value for connecting to neutron in seconds.'),
    cfg.StrOpt(
        'auth_strategy',
        deprecated_for_removal=True,
        deprecated_reason='This parameter has had no effect since 2.0.0. '
                          'Use the auth_type parameter to select '
                          'authentication type',
        deprecated_since='Yoga',
        default='keystone',
        help='Auth strategy for connecting to neutron in admin context.'),
    cfg.StrOpt(
        'endpoint_type',
        default='publicURL',
        help='Endpoint type to be used with neutron client calls.'),
    cfg.StrOpt(
        'region_name',
        help='Region name for connecting to neutron in admin context.'),
]


CONF = cfg.CONF
LOG = log.getLogger(__name__)


def list_opts():
    return client_auth.AuthClientLoader.list_opts(NEUTRON_GROUP)


class API(object):
    """API for interacting with the neutron 2.x API.

    :param configuration: instance of config or config group.
    """

    def __init__(self, config_group_name=None):
        self.config_group_name = config_group_name or 'DEFAULT'

        ks_loading.register_session_conf_options(
            CONF, NEUTRON_GROUP)
        ks_loading.register_auth_conf_options(CONF, NEUTRON_GROUP)
        CONF.register_opts(neutron_opts, NEUTRON_GROUP)

        self.configuration = getattr(CONF, self.config_group_name, CONF)
        self.last_neutron_extension_sync = None
        self.extensions = {}
        self.auth_obj = None

    @property
    def client(self):
        return self.get_client(context.get_admin_context())

    def get_client(self, context):
        if not self.auth_obj:
            self.auth_obj = client_auth.AuthClientLoader(
                client_class=clientv20.Client, cfg_group=NEUTRON_GROUP)

        return self.auth_obj.get_client(
            self,
            context,
            endpoint_type=CONF[NEUTRON_GROUP].endpoint_type,
            region_name=CONF[NEUTRON_GROUP].region_name,
            endpoint_override=CONF[NEUTRON_GROUP].url,
        )

    @property
    def admin_project_id(self):
        if self.client.httpclient.auth_token is None:
            try:
                self.client.httpclient.authenticate()
            except neutron_client_exc.NeutronClientException as e:
                raise exception.NetworkException(code=e.status_code,
                                                 message=e.message)
        return self.client.httpclient.get_project_id()

    def get_all_admin_project_networks(self):
        search_opts = {'tenant_id': self.admin_project_id, 'shared': False}
        nets = self.client.list_networks(**search_opts).get('networks', [])
        return nets

    def create_port(self, tenant_id, network_id, host_id=None, subnet_id=None,
                    fixed_ip=None, device_owner=None, device_id=None,
                    mac_address=None, port_security_enabled=True,
                    security_group_ids=None, dhcp_opts=None, **kwargs):
        try:
            port_req_body = {'port': {}}
            port_req_body['port']['network_id'] = network_id
            port_req_body['port']['admin_state_up'] = True
            port_req_body['port']['tenant_id'] = tenant_id
            if not port_security_enabled:
                port_req_body['port']['port_security_enabled'] = (
                    port_security_enabled)
            elif security_group_ids:
                port_req_body['port']['security_groups'] = security_group_ids
            if mac_address:
                port_req_body['port']['mac_address'] = mac_address
            if host_id:
                if not self._has_port_binding_extension():
                    msg = ("host_id (%(host_id)s) specified but neutron "
                           "doesn't support port binding. Please activate the "
                           "extension accordingly." % {"host_id": host_id})
                    raise exception.NetworkException(message=msg)
                port_req_body['port']['binding:host_id'] = host_id
            if dhcp_opts is not None:
                port_req_body['port']['extra_dhcp_opts'] = dhcp_opts
            if subnet_id:
                fixed_ip_dict = {'subnet_id': subnet_id}
                if fixed_ip:
                    fixed_ip_dict.update({'ip_address': fixed_ip})
                port_req_body['port']['fixed_ips'] = [fixed_ip_dict]
            if device_owner:
                port_req_body['port']['device_owner'] = device_owner
            if device_id:
                port_req_body['port']['device_id'] = device_id
            if kwargs:
                port_req_body['port'].update(kwargs)
            port = self.client.create_port(port_req_body).get('port', {})
            return port
        except neutron_client_exc.NeutronClientException as e:
            LOG.exception('Neutron error creating port on network %s',
                          network_id)
            if e.status_code == 409:
                raise exception.PortLimitExceeded()
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def delete_port(self, port_id):
        try:
            self.client.delete_port(port_id)
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def delete_subnet(self, subnet_id):
        try:
            self.client.delete_subnet(subnet_id)
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def list_ports(self, **search_opts):
        """List ports for the client based on search options."""
        return self.client.list_ports(**search_opts).get('ports')

    def show_port(self, port_id):
        """Return the port for the client given the port id."""
        try:
            return self.client.show_port(port_id).get('port')
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def get_all_networks(self):
        """Get all networks for client."""
        return self.client.list_networks().get('networks')

    def get_network(self, network_uuid):
        """Get specific network for client."""
        try:
            network = self.client.show_network(network_uuid).get('network', {})
            return network
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def get_subnet(self, subnet_uuid):
        """Get specific subnet for client."""
        try:
            return self.client.show_subnet(subnet_uuid).get('subnet', {})
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def list_extensions(self):
        extensions_list = self.client.list_extensions().get('extensions')
        return {ext['name']: ext for ext in extensions_list}

    def _has_port_binding_extension(self):
        if not self.extensions:
            self.extensions = self.list_extensions()
        return neutron_constants.PORTBINDING_EXT in self.extensions

    def router_create(self, tenant_id, name):
        router_req_body = {'router': {}}
        router_req_body['router']['tenant_id'] = tenant_id
        router_req_body['router']['name'] = name
        try:
            return self.client.create_router(router_req_body).get('router', {})
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def network_create(self, tenant_id, name):
        network_req_body = {'network': {}}
        network_req_body['network']['tenant_id'] = tenant_id
        network_req_body['network']['name'] = name
        try:
            return self.client.create_network(
                network_req_body).get('network', {})
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def subnet_create(self, tenant_id, net_id, name, cidr, no_gateway=False):
        subnet_req_body = {'subnet': {}}
        subnet_req_body['subnet']['tenant_id'] = tenant_id
        subnet_req_body['subnet']['name'] = name
        subnet_req_body['subnet']['network_id'] = net_id
        subnet_req_body['subnet']['cidr'] = cidr
        subnet_req_body['subnet']['ip_version'] = 4
        if no_gateway:
            subnet_req_body['subnet']['gateway_ip'] = None
        try:
            return self.client.create_subnet(
                subnet_req_body).get('subnet', {})
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def router_add_interface(self, router_id, subnet_id, port_id=None):
        body = {}
        if subnet_id:
            body['subnet_id'] = subnet_id
        if port_id:
            body['port_id'] = port_id
        try:
            self.client.add_interface_router(router_id, body)
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def router_remove_interface(self, router_id, subnet_id, port_id=None):
        body = {}
        if subnet_id:
            body['subnet_id'] = subnet_id
        if port_id:
            body['port_id'] = port_id
        try:
            self.client.remove_interface_router(router_id, body)
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def router_list(self):
        try:
            return self.client.list_routers().get('routers', {})
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def update_port_fixed_ips(self, port_id, fixed_ips):
        try:
            port_req_body = {'port': fixed_ips}
            port = self.client.update_port(
                port_id, port_req_body).get('port', {})
            return port
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def show_router(self, router_id):
        try:
            return self.client.show_router(router_id).get('router', {})
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def router_update_routes(self, router_id, routes):
        try:
            router_req_body = {'router': routes}
            port = self.client.update_router(
                router_id, router_req_body).get('router', {})
            return port
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def update_subnet(self, subnet_uuid, name):
        """Update specific subnet for client."""
        subnet_req_body = {'subnet': {'name': name}}
        try:
            return self.client.update_subnet(
                subnet_uuid, subnet_req_body).get('subnet', {})
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(code=e.status_code,
                                             message=e.message)

    def security_group_list(self, search_opts=None):
        try:
            return self.client.list_security_groups(**search_opts)
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(
                code=e.status_code, message=e.message)

    def security_group_create(self, name, description=""):
        try:
            return self.client.create_security_group(
                {'security_group': {"name": name, "description": description}})
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(
                code=e.status_code, message=e.message)

    def security_group_rule_create(self, parent_group_id,
                                   ip_protocol=None, from_port=None,
                                   to_port=None, cidr=None, group_id=None,
                                   direction="ingress"):
        request = {"security_group_id": parent_group_id,
                   "protocol": ip_protocol, "remote_ip_prefix": cidr,
                   "remote_group_id": group_id, "direction": direction}
        if ip_protocol != "icmp":
            request["port_range_min"] = from_port
            request["port_range_max"] = to_port

        try:
            return self.client.create_security_group_rule(
                {"security_group_rule": request})
        except neutron_client_exc.NeutronClientException as e:
            raise exception.NetworkException(
                code=e.status_code, message=e.message)
