# Copyright (c) 2014 NetApp, Inc.
# Copyright (c) 2015 Mirantis, Inc.
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

"""Module for managing nova instances for share drivers."""

import abc
import os
import socket
import time

import netaddr
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
import six

from manila.common import constants as const
from manila import compute
from manila import context
from manila import exception
from manila.i18n import _
from manila.i18n import _LW
from manila.network.linux import ip_lib
from manila.network.neutron import api as neutron
from manila import utils

LOG = log.getLogger(__name__)
NEUTRON_NAME = "neutron"
NOVA_NAME = "nova"

share_servers_handling_mode_opts = [
    cfg.StrOpt(
        "service_image_name",
        default="manila-service-image",
        help="Name of image in Glance, that will be used for service instance "
             "creation."),
    cfg.StrOpt(
        "service_instance_name_template",
        default="manila_service_instance_%s",
        help="Name of service instance."),
    cfg.StrOpt(
        "manila_service_keypair_name",
        default="manila-service",
        help="Keypair name that will be created and used for service "
             "instances."),
    cfg.StrOpt(
        "path_to_public_key",
        default="~/.ssh/id_rsa.pub",
        help="Path to hosts public key."),
    cfg.StrOpt(
        "service_instance_security_group",
        default="manila-service",
        help="Security group name, that will be used for "
             "service instance creation."),
    cfg.IntOpt(
        "service_instance_flavor_id",
        default=100,
        help="ID of flavor, that will be used for service instance "
             "creation."),
    cfg.StrOpt(
        "service_network_name",
        default="manila_service_network",
        help="Name of manila service network. Used only with Neutron."),
    cfg.StrOpt(
        "service_network_cidr",
        default="10.254.0.0/16",
        help="CIDR of manila service network. Used only with Neutron."),
    cfg.IntOpt(
        "service_network_division_mask",
        default=28,
        help="This mask is used for dividing service network into "
             "subnets, IP capacity of subnet with this mask directly "
             "defines possible amount of created service VMs "
             "per tenant's subnet. Used only with Neutron."),
    cfg.StrOpt(
        "interface_driver",
        default="manila.network.linux.interface.OVSInterfaceDriver",
        help="Vif driver. Used only with Neutron."),
    cfg.BoolOpt(
        "connect_share_server_to_tenant_network",
        default=False,
        help="Attach share server directly to share network. "
             "Used only with Neutron."),
    cfg.StrOpt(
        "service_instance_network_helper_type",
        default=NEUTRON_NAME,
        help="Allowed values are %s." % [NOVA_NAME, NEUTRON_NAME])
]

no_share_servers_handling_mode_opts = [
    cfg.StrOpt(
        "service_instance_name_or_id",
        help="Name or ID of service instance in Nova to use for share "
             "exports. Used only when share servers handling is disabled."),
    cfg.StrOpt(
        "service_net_name_or_ip",
        help="Can be either name of network that is used by service "
             "instance within Nova to get IP address or IP address itself "
             "for managing shares there. "
             "Used only when share servers handling is disabled."),
    cfg.StrOpt(
        "tenant_net_name_or_ip",
        help="Can be either name of network that is used by service "
             "instance within Nova to get IP address or IP address itself "
             "for exporting shares. "
             "Used only when share servers handling is disabled."),
]

common_opts = [
    cfg.StrOpt(
        "service_instance_user",
        help="User in service instance that will be used for authentication."),
    cfg.StrOpt(
        "service_instance_password",
        secret=True,
        help="Password for service instance user."),
    cfg.StrOpt(
        "path_to_private_key",
        default=None,
        help="Path to host's private key."),
    cfg.IntOpt(
        "max_time_to_build_instance",
        default=300,
        help="Maximum time in seconds to wait for creating service instance."),
]

CONF = cfg.CONF


class ServiceInstanceManager(object):
    """Manages nova instances for various share drivers.

    This class provides following external methods:

    1. set_up_service_instance: creates instance and sets up share
       infrastructure.
    2. ensure_service_instance: ensure service instance is available.
    3. delete_service_instance: removes service instance and network
       infrastructure.
    """
    _INSTANCE_CONNECTION_PROTO = "SSH"

    def get_config_option(self, key):
        """Returns value of config option.

        :param key: key of config' option.
        :returns: str -- value of config's option.
                  first priority is driver's config,
                  second priority is global config.
        """
        if self.driver_config:
            return self.driver_config.safe_get(key)
        return CONF.get(key)

    def _get_network_helper(self):
        network_helper_type = (
            self.get_config_option(
                "service_instance_network_helper_type").lower())
        if network_helper_type == NEUTRON_NAME:
            return NeutronNetworkHelper(self)
        elif network_helper_type == NOVA_NAME:
            return NovaNetworkHelper(self)
        else:
            raise exception.ManilaException(
                _("Wrong value '%(provided)s' for config opt "
                  "'service_instance_network_helper_type'. "
                  "Allowed values are %(allowed)s.") % dict(
                      provided=network_helper_type,
                      allowed=[NOVA_NAME, NEUTRON_NAME]))

    def __init__(self, driver_config=None):
        super(ServiceInstanceManager, self).__init__()
        self.driver_config = driver_config

        if self.driver_config:
            self.driver_config.append_config_values(common_opts)
            if self.get_config_option("driver_handles_share_servers"):
                self.driver_config.append_config_values(
                    share_servers_handling_mode_opts)
            else:
                self.driver_config.append_config_values(
                    no_share_servers_handling_mode_opts)
        else:
            CONF.register_opts(common_opts)
            if self.get_config_option("driver_handles_share_servers"):
                CONF.register_opts(share_servers_handling_mode_opts)
            else:
                CONF.register_opts(no_share_servers_handling_mode_opts)

        if not self.get_config_option("service_instance_user"):
            raise exception.ServiceInstanceException(
                _('Service instance user is not specified.'))
        self.admin_context = context.get_admin_context()
        self._execute = utils.execute

        self.compute_api = compute.API()

        self.path_to_private_key = self.get_config_option(
            "path_to_private_key")
        self.max_time_to_build_instance = self.get_config_option(
            "max_time_to_build_instance")

        if self.get_config_option("driver_handles_share_servers"):
            self.path_to_public_key = self.get_config_option(
                "path_to_public_key")
            self._network_helper = None

    @property
    @utils.synchronized("instantiate_network_helper")
    def network_helper(self):
        if not self._network_helper:
            self._network_helper = self._get_network_helper()
            self._network_helper.setup_connectivity_with_service_instances()
        return self._network_helper

    def get_common_server(self):
        data = {
            'public_address': None,
            'private_address': None,
            'service_net_name_or_ip': self.get_config_option(
                'service_net_name_or_ip'),
            'tenant_net_name_or_ip': self.get_config_option(
                'tenant_net_name_or_ip'),
        }

        data['instance'] = self.compute_api.server_get_by_name_or_id(
            self.admin_context,
            self.get_config_option('service_instance_name_or_id'))

        if netaddr.valid_ipv4(data['service_net_name_or_ip']):
            data['private_address'] = [data['service_net_name_or_ip']]
        else:
            data['private_address'] = self._get_addresses_by_network_name(
                data['service_net_name_or_ip'], data['instance'])

        if netaddr.valid_ipv4(data['tenant_net_name_or_ip']):
            data['public_address'] = [data['tenant_net_name_or_ip']]
        else:
            data['public_address'] = self._get_addresses_by_network_name(
                data['tenant_net_name_or_ip'], data['instance'])

        if not (data['public_address'] and data['private_address']):
            raise exception.ManilaException(
                "Can not find one of net addresses for service instance. "
                "Instance: %(instance)s, "
                "private_address: %(private_address)s, "
                "public_address: %(public_address)s." % data)

        share_server = {
            'username': self.get_config_option('service_instance_user'),
            'password': self.get_config_option('service_instance_password'),
            'pk_path': self.path_to_private_key,
            'instance_id': data['instance']['id'],
        }
        for key in ('private_address', 'public_address'):
            data[key + '_v4'] = None
            for address in data[key]:
                if netaddr.valid_ipv4(address):
                    data[key + '_v4'] = address
                    break
        share_server['ip'] = data['private_address_v4']
        share_server['public_address'] = data['public_address_v4']
        return {'backend_details': share_server}

    def _get_addresses_by_network_name(self, net_name, server):
        net_ips = []
        if 'networks' in server and net_name in server['networks']:
            net_ips = server['networks'][net_name]
        elif 'addresses' in server and net_name in server['addresses']:
            net_ips = [addr['addr'] for addr in server['addresses'][net_name]]
        return net_ips

    def _get_service_instance_name(self, share_server_id):
        """Returns service vms name."""
        if self.driver_config:
            # Make service instance name unique for multibackend installation
            name = "%s_%s" % (self.driver_config.config_group, share_server_id)
        else:
            name = share_server_id
        return self.get_config_option("service_instance_name_template") % name

    def _get_server_ip(self, server, net_name):
        """Returns service IP address of service instance."""
        net_ips = self._get_addresses_by_network_name(net_name, server)
        if not net_ips:
            msg = _("Failed to get service instance IP address. "
                    "Service network name is '%(net_name)s' "
                    "and provided data are '%(data)s'.")
            msg = msg % {'net_name': net_name, 'data': six.text_type(server)}
            raise exception.ServiceInstanceException(msg)
        return net_ips[0]

    @utils.synchronized(
        "service_instance_get_or_create_security_group", external=True)
    def _get_or_create_security_group(self, context, name=None,
                                      description=None):
        """Get or create security group for service_instance.

        :param context: context, that should be used
        :param name: this is used for selection/creation of sec.group
        :param description: this is used on sec.group creation step only
        :returns: SecurityGroup -- security group instance from Nova
        :raises: exception.ServiceInstanceException.
        """
        name = name or self.get_config_option(
            "service_instance_security_group")
        if not name:
            LOG.warning(_LW("Name for service instance security group is not "
                            "provided. Skipping security group step."))
            return None
        s_groups = [s for s in self.compute_api.security_group_list(context)
                    if s.name == name]
        if not s_groups:
            # Creating security group
            if not description:
                description = "This security group is intended "\
                              "to be used by share service."
            LOG.debug("Creating security group with name '%s'.", name)
            sg = self.compute_api.security_group_create(
                context, name, description)
            for protocol, ports in const.SERVICE_INSTANCE_SECGROUP_DATA:
                self.compute_api.security_group_rule_create(
                    context,
                    parent_group_id=sg.id,
                    ip_protocol=protocol,
                    from_port=ports[0],
                    to_port=ports[1],
                    cidr="0.0.0.0/0",
                )
        elif len(s_groups) > 1:
            msg = _("Ambiguous security_groups.")
            raise exception.ServiceInstanceException(msg)
        else:
            sg = s_groups[0]
        return sg

    def ensure_service_instance(self, context, server):
        """Ensures that server exists and active."""
        try:
            inst = self.compute_api.server_get(self.admin_context,
                                               server['instance_id'])
        except exception.InstanceNotFound:
            LOG.warning(_LW("Service instance %s does not exist."),
                        server['instance_id'])
            return False
        if inst['status'] == 'ACTIVE':
            return self._check_server_availability(server)
        return False

    def _delete_server(self, context, server_id):
        """Deletes the server."""
        try:
            self.compute_api.server_get(context, server_id)
        except exception.InstanceNotFound:
            LOG.debug("Service instance '%s' was not found. "
                      "Nothing to delete, skipping.", server_id)
            return

        self.compute_api.server_delete(context, server_id)

        t = time.time()
        while time.time() - t < self.max_time_to_build_instance:
            try:
                self.compute_api.server_get(context, server_id)
            except exception.InstanceNotFound:
                LOG.debug("Service instance '%s' was deleted "
                          "successfully.", server_id)
                break
            time.sleep(2)
        else:
            raise exception.ServiceInstanceException(
                _("Instance '%(id)s' has not been deleted in %(s)ss. "
                  "Giving up.") % {
                      'id': server_id, 's': self.max_time_to_build_instance})

    def set_up_service_instance(self, context, network_info):
        """Finds or creates and sets up service vm.

        :param context: defines context, that should be used
        :param network_info: network info for getting allocations
        :returns: dict with service instance details
        :raises: exception.ServiceInstanceException
        """
        instance_name = network_info['server_id']
        server = self._create_service_instance(
            context, instance_name, network_info)
        instance_details = self._get_new_instance_details(server)

        if not self._check_server_availability(instance_details):
            raise exception.ServiceInstanceException(
                _('%(conn_proto)s connection has not been '
                  'established to %(server)s in %(time)ss. Giving up.') % {
                      'conn_proto': self._INSTANCE_CONNECTION_PROTO,
                      'server': server['ip'],
                      'time': self.max_time_to_build_instance})

        return instance_details

    def _get_new_instance_details(self, server):
        instance_details = {
            'instance_id': server['id'],
            'ip': server['ip'],
            'pk_path': server.get('pk_path'),
            'subnet_id': server.get('subnet_id'),
            'password': self.get_config_option('service_instance_password'),
            'username': self.get_config_option('service_instance_user'),
            'public_address': server['public_address'],
            'service_ip': server['service_ip'],
        }
        if server.get('router_id'):
            instance_details['router_id'] = server['router_id']
        if server.get('service_port_id'):
            instance_details['service_port_id'] = server['service_port_id']
        if server.get('public_port_id'):
            instance_details['public_port_id'] = server['public_port_id']
        for key in ('password', 'pk_path', 'subnet_id'):
            if not instance_details[key]:
                instance_details.pop(key)
        return instance_details

    @utils.synchronized("service_instance_get_key", external=True)
    def _get_key(self, context):
        """Get ssh key.

        :param context: defines context, that should be used
        :returns: tuple with keypair name and path to private key.
        """
        if not (self.path_to_public_key and self.path_to_private_key):
            return (None, None)
        path_to_public_key = os.path.expanduser(self.path_to_public_key)
        path_to_private_key = os.path.expanduser(self.path_to_private_key)
        if (not os.path.exists(path_to_public_key) or
                not os.path.exists(path_to_private_key)):
            return (None, None)
        keypair_name = self.get_config_option("manila_service_keypair_name")
        keypairs = [k for k in self.compute_api.keypair_list(context)
                    if k.name == keypair_name]
        if len(keypairs) > 1:
            raise exception.ServiceInstanceException(_('Ambiguous keypairs.'))

        public_key, __ = self._execute('cat', path_to_public_key)
        if not keypairs:
            keypair = self.compute_api.keypair_import(
                context, keypair_name, public_key)
        else:
            keypair = keypairs[0]
            if keypair.public_key != public_key:
                LOG.debug('Public key differs from existing keypair. '
                          'Creating new keypair.')
                self.compute_api.keypair_delete(context, keypair.id)
                keypair = self.compute_api.keypair_import(
                    context, keypair_name, public_key)

        return keypair.name, path_to_private_key

    def _get_service_image(self, context):
        """Returns ID of service image for service vm creating."""
        service_image_name = self.get_config_option("service_image_name")
        images = [image.id for image in self.compute_api.image_list(context)
                  if image.name == service_image_name]
        if len(images) == 1:
            return images[0]
        elif not images:
            raise exception.ServiceInstanceException(
                _("Image with name '%s' not found.") % service_image_name)
        else:
            raise exception.ServiceInstanceException(
                _("Found more than one image by name '%s'.") %
                service_image_name)

    def _create_service_instance(self, context, instance_name, network_info):
        """Creates service vm and sets up networking for it."""
        service_image_id = self._get_service_image(context)
        key_name, key_path = self._get_key(context)
        if not (self.get_config_option("service_instance_password") or
                key_name):
            raise exception.ServiceInstanceException(
                _('Neither service instance password nor key are available.'))
        if not key_path:
            LOG.warning(_LW(
                'No key path is available. May be non-existent key path is '
                'provided. Check path_to_private_key (current value '
                '%(private_path)s) and path_to_public_key (current value '
                '%(public_path)s) in manila configuration file.'), dict(
                    private_path=self.path_to_private_key,
                    public_path=self.path_to_public_key))
        network_data = self.network_helper.setup_network(network_info)
        fail_safe_data = dict(
            router_id=network_data.get('router_id'),
            subnet_id=network_data.get('subnet_id'))
        if network_data.get('service_port'):
            fail_safe_data['service_port_id'] = (
                network_data['service_port']['id'])
        if network_data.get('public_port'):
            fail_safe_data['public_port_id'] = (
                network_data['public_port']['id'])
        try:
            create_kwargs = self._get_service_instance_create_kwargs()
            service_instance = self.compute_api.server_create(
                context,
                name=instance_name,
                image=service_image_id,
                flavor=self.get_config_option("service_instance_flavor_id"),
                key_name=key_name,
                nics=network_data['nics'],
                availability_zone=CONF.storage_availability_zone,
                **create_kwargs)

            fail_safe_data['instance_id'] = service_instance['id']

            service_instance = self.wait_for_instance_to_be_active(
                service_instance['id'],
                self.max_time_to_build_instance)

            security_group = self._get_or_create_security_group(context)
            if security_group:
                if self.network_helper.NAME == NOVA_NAME:
                    # NOTE(vponomaryov): Nova-network allows to assign
                    #                    secgroups only by names.
                    sg_id = security_group.name
                else:
                    sg_id = security_group.id
                LOG.debug(
                    "Adding security group '%(sg)s' to server '%(si)s'.",
                    dict(sg=sg_id, si=service_instance["id"]))
                self.compute_api.add_security_group_to_server(
                    context, service_instance["id"], sg_id)

            if self.network_helper.NAME == NEUTRON_NAME:
                service_instance['ip'] = self._get_server_ip(
                    service_instance,
                    self.get_config_option("service_network_name"))
                public_ip = network_data.get(
                    'public_port', network_data['service_port'])['fixed_ips']
                service_instance['public_address'] = public_ip[0]['ip_address']
            else:
                net_name = self.network_helper.get_network_name(network_info)
                service_instance['ip'] = self._get_server_ip(
                    service_instance, net_name)
                service_instance['public_address'] = service_instance['ip']

        except Exception as e:
            e.detail_data = {'server_details': fail_safe_data}
            raise

        service_instance.update(fail_safe_data)
        service_instance['pk_path'] = key_path
        for pair in [('router', 'router_id'), ('service_subnet', 'subnet_id')]:
            if pair[0] in network_data and 'id' in network_data[pair[0]]:
                service_instance[pair[1]] = network_data[pair[0]]['id']

        service_instance['service_ip'] = network_data.get('service_ip')

        return service_instance

    def _get_service_instance_create_kwargs(self):
        """Specify extra arguments used when creating the service instance.

        Classes inheriting the service instance manager can use this to easily
        pass extra arguments such as user data or metadata.
        """
        return {}

    def _check_server_availability(self, instance_details):
        t = time.time()
        while time.time() - t < self.max_time_to_build_instance:
            LOG.debug('Checking server availability.')
            if not self._test_server_connection(instance_details):
                time.sleep(5)
            else:
                return True
        return False

    def _test_server_connection(self, server):
        try:
            socket.socket().connect((server['ip'], 22))
            LOG.debug('Server %s is available via SSH.',
                      server['ip'])
            return True
        except socket.error as e:
            LOG.debug(e)
            LOG.debug("Server %s is not available via SSH. Waiting...",
                      server['ip'])
            return False

    def delete_service_instance(self, context, server_details):
        """Removes share infrastructure.

        Deletes service vm and subnet, associated to share network.
        """
        instance_id = server_details.get("instance_id")
        self._delete_server(context, instance_id)
        self.network_helper.teardown_network(server_details)

    def wait_for_instance_to_be_active(self, instance_id, timeout):
        t = time.time()
        while time.time() - t < timeout:
            try:
                service_instance = self.compute_api.server_get(
                    self.admin_context,
                    instance_id)
            except exception.InstanceNotFound as e:
                LOG.debug(e)
                time.sleep(1)
                continue

            instance_status = service_instance['status']
            # NOTE(vponomaryov): emptiness of 'networks' field checked as
            #                    workaround for nova/neutron bug #1210483.
            if (instance_status == 'ACTIVE' and
                    service_instance.get('networks', {})):
                return service_instance
            elif service_instance['status'] == 'ERROR':
                break

            LOG.debug("Waiting for instance %(instance_id)s to be active. "
                      "Current status: %(instance_status)s." %
                      dict(instance_id=instance_id,
                           instance_status=instance_status))
            time.sleep(1)
        raise exception.ServiceInstanceException(
            _("Instance %(instance_id)s failed to reach active state "
              "in %(timeout)s seconds. "
              "Current status: %(instance_status)s.") %
            dict(instance_id=instance_id,
                 timeout=timeout,
                 instance_status=instance_status))

    def reboot_server(self, server, soft_reboot=False):
        self.compute_api.server_reboot(self.admin_context,
                                       server['instance_id'],
                                       soft_reboot)


@six.add_metaclass(abc.ABCMeta)
class BaseNetworkhelper(object):

    @abc.abstractproperty
    def NAME(self):
        """Returns code name of network helper."""

    @abc.abstractmethod
    def __init__(self, service_instance_manager):
        """Instantiates class and its attrs."""

    @abc.abstractmethod
    def get_network_name(self, network_info):
        """Returns name of network for service instance."""

    @abc.abstractmethod
    def setup_connectivity_with_service_instances(self):
        """Sets up connectivity between Manila host and service instances."""

    @abc.abstractmethod
    def setup_network(self, network_info):
        """Sets up network for service instance."""

    @abc.abstractmethod
    def teardown_network(self, server_details):
        """Teardowns network resources provided for service instance."""


class NeutronNetworkHelper(BaseNetworkhelper):

    def __init__(self, service_instance_manager):
        self.get_config_option = service_instance_manager.get_config_option
        self.vif_driver = importutils.import_class(
            self.get_config_option("interface_driver"))()

        if service_instance_manager.driver_config:
            self._network_config_group = (
                service_instance_manager.driver_config.network_config_group or
                service_instance_manager.driver_config.config_group)
        else:
            self._network_config_group = None

        self._neutron_api = None
        self._service_network_id = None
        self.connect_share_server_to_tenant_network = (
            self.get_config_option('connect_share_server_to_tenant_network'))

    @property
    def NAME(self):
        return NEUTRON_NAME

    @property
    def admin_project_id(self):
        return self.neutron_api.admin_project_id

    @property
    @utils.synchronized("instantiate_neutron_api_neutron_net_helper")
    def neutron_api(self):
        if not self._neutron_api:
            self._neutron_api = neutron.API(
                config_group_name=self._network_config_group)
        return self._neutron_api

    @property
    @utils.synchronized("service_network_id_neutron_net_helper")
    def service_network_id(self):
        if not self._service_network_id:
            self._service_network_id = self._get_service_network_id()
        return self._service_network_id

    def get_network_name(self, network_info):
        """Returns name of network for service instance."""
        net = self.neutron_api.get_network(network_info['neutron_net_id'])
        return net['name']

    @utils.synchronized("service_instance_get_service_network", external=True)
    def _get_service_network_id(self):
        """Finds existing or creates new service network."""
        service_network_name = self.get_config_option("service_network_name")
        networks = []
        for network in self.neutron_api.get_all_admin_project_networks():
            if network['name'] == service_network_name:
                networks.append(network)
        if len(networks) > 1:
            raise exception.ServiceInstanceException(
                _('Ambiguous service networks.'))
        elif not networks:
            return self.neutron_api.network_create(
                self.admin_project_id, service_network_name)['id']
        else:
            return networks[0]['id']

    @utils.synchronized(
        "service_instance_setup_and_teardown_network_for_instance",
        external=True)
    def teardown_network(self, server_details):
        subnet_id = server_details.get("subnet_id")
        router_id = server_details.get("router_id")

        service_port_id = server_details.get("service_port_id")
        public_port_id = server_details.get("public_port_id")
        for port_id in (service_port_id, public_port_id):
            if port_id:
                try:
                    self.neutron_api.delete_port(port_id)
                except exception.NetworkException as e:
                    if e.kwargs.get('code') != 404:
                        raise
                    LOG.debug("Failed to delete port %(port_id)s with error: "
                              "\n %(exc)s", {"port_id": port_id, "exc": e})

        if router_id and subnet_id:
            ports = self.neutron_api.list_ports(
                fields=['fixed_ips', 'device_id', 'device_owner'])
            # NOTE(vponomaryov): iterate ports to get to know whether current
            # subnet is used or not. We will not remove it from router if it
            # is used.
            for port in ports:
                # NOTE(vponomaryov): if device_id is present, then we know that
                # this port is used. Also, if device owner is 'compute:*', then
                # we know that it is VM. We continue only if both are 'True'.
                if (port['device_id'] and
                        port['device_owner'].startswith('compute:')):
                    for fixed_ip in port['fixed_ips']:
                        if fixed_ip['subnet_id'] == subnet_id:
                            # NOTE(vponomaryov): There are other share servers
                            # exist that use this subnet. So, do not remove it
                            # from router.
                            return
            try:
                # NOTE(vponomaryov): there is no other share servers or
                # some VMs that use this subnet. So, remove it from router.
                self.neutron_api.router_remove_interface(
                    router_id, subnet_id)
            except exception.NetworkException as e:
                if e.kwargs['code'] != 404:
                    raise
                LOG.debug('Subnet %(subnet_id)s is not attached to the '
                          'router %(router_id)s.',
                          {'subnet_id': subnet_id, 'router_id': router_id})
            self.neutron_api.update_subnet(subnet_id, '')

    @utils.synchronized(
        "service_instance_setup_and_teardown_network_for_instance",
        external=True)
    def setup_network(self, network_info):
        neutron_net_id = network_info['neutron_net_id']
        neutron_subnet_id = network_info['neutron_subnet_id']
        network_data = dict()
        subnet_name = ('service_subnet_for_handling_of_share_server_for_'
                       'tenant_subnet_%s' % neutron_subnet_id)

        network_data['service_subnet'] = self._get_service_subnet(subnet_name)
        if not network_data['service_subnet']:
            network_data['service_subnet'] = self.neutron_api.subnet_create(
                self.admin_project_id, self.service_network_id, subnet_name,
                self._get_cidr_for_subnet())

        if not self.connect_share_server_to_tenant_network:
            network_data['router'] = self._get_private_router(
                neutron_net_id, neutron_subnet_id)
            try:
                self.neutron_api.router_add_interface(
                    network_data['router']['id'],
                    network_data['service_subnet']['id'])
            except exception.NetworkException as e:
                if e.kwargs['code'] != 400:
                    raise
                LOG.debug('Subnet %(subnet_id)s is already attached to the '
                          'router %(router_id)s.',
                          {'subnet_id': network_data['service_subnet']['id'],
                           'router_id': network_data['router']['id']})

        network_data['service_port'] = self.neutron_api.create_port(
            self.admin_project_id, self.service_network_id,
            subnet_id=network_data['service_subnet']['id'],
            device_owner='manila')

        network_data['ports'] = [network_data['service_port']]
        if self.connect_share_server_to_tenant_network:
            network_data['public_port'] = self.neutron_api.create_port(
                self.admin_project_id, neutron_net_id,
                subnet_id=neutron_subnet_id, device_owner='manila')
            network_data['ports'].append(network_data['public_port'])

        try:
            port = self.setup_connectivity_with_service_instances()
            service_ip = self._get_service_ip(
                port, network_data['service_subnet']['id'])
        except Exception as e:
            for port in network_data['ports']:
                self.neutron_api.delete_port(port['id'])
            raise

        network_data['nics'] = [
            {'port-id': port['id']} for port in network_data['ports']]
        public_ip = network_data.get(
            'public_port', network_data['service_port'])
        network_data['ip_address'] = public_ip['fixed_ips'][0]['ip_address']
        network_data['service_ip'] = service_ip

        return network_data

    def _get_service_ip(self, port, subnet_id):
        for fixed_ips in port['fixed_ips']:
            if subnet_id == fixed_ips['subnet_id']:
                return fixed_ips['ip_address']
        msg = _("Service IP not found for Share Server.")
        raise exception.ServiceIPNotFound(reason=msg)

    def _get_cidr_for_subnet(self):
        """Returns not used cidr for service subnet creating."""
        subnets = self._get_all_service_subnets()
        used_cidrs = set(subnet['cidr'] for subnet in subnets)
        serv_cidr = netaddr.IPNetwork(
            self.get_config_option("service_network_cidr"))
        division_mask = self.get_config_option("service_network_division_mask")
        for subnet in serv_cidr.subnet(division_mask):
            cidr = six.text_type(subnet.cidr)
            if cidr not in used_cidrs:
                return cidr
        else:
            raise exception.ServiceInstanceException(_('No available cidrs.'))

    def setup_connectivity_with_service_instances(self):
        """Sets up connectivity with service instances.

        Creates creating port in service network, creating and setting up
        required network devices.
        """
        port = self._get_service_port()
        port = self._add_fixed_ips_to_service_port(port)
        interface_name = self.vif_driver.get_device_name(port)
        self.vif_driver.plug(interface_name, port['id'], port['mac_address'])
        ip_cidrs = []
        for fixed_ip in port['fixed_ips']:
            subnet = self.neutron_api.get_subnet(fixed_ip['subnet_id'])
            net = netaddr.IPNetwork(subnet['cidr'])
            ip_cidr = '%s/%s' % (fixed_ip['ip_address'], net.prefixlen)
            ip_cidrs.append(ip_cidr)

        self.vif_driver.init_l3(interface_name, ip_cidrs)

        # ensure that interface is first in the list
        device = ip_lib.IPDevice(interface_name)
        device.route.pullup_route(interface_name)

        # here we are checking for garbage devices from removed service port
        self._remove_outdated_interfaces(device)

        return port

    @utils.synchronized(
        "service_instance_remove_outdated_interfaces", external=True)
    def _remove_outdated_interfaces(self, device):
        """Finds and removes unused network device."""
        device_cidr_set = self._get_set_of_device_cidrs(device)
        for dev in ip_lib.IPWrapper().get_devices():
            if dev.name != device.name and dev.name[:3] == device.name[:3]:
                cidr_set = self._get_set_of_device_cidrs(dev)
                if device_cidr_set & cidr_set:
                    self.vif_driver.unplug(dev.name)

    def _get_set_of_device_cidrs(self, device):
        cidrs = set()
        for addr in device.addr.list():
            if addr['ip_version'] == 4:
                cidrs.add(six.text_type(netaddr.IPNetwork(addr['cidr']).cidr))
        return cidrs

    @utils.synchronized("service_instance_get_service_port", external=True)
    def _get_service_port(self):
        """Find or creates service neutron port.

        This port will be used for connectivity with service instances.
        """
        host = socket.gethostname()
        search_opts = {'device_id': 'manila-share',
                       'binding:host_id': host}
        ports = [port for port in self.neutron_api.
                 list_ports(**search_opts)]
        if len(ports) > 1:
            raise exception.ServiceInstanceException(
                _('Error. Ambiguous service ports.'))
        elif not ports:
            port = self.neutron_api.create_port(
                self.admin_project_id, self.service_network_id,
                device_id='manila-share', device_owner='manila:share',
                host_id=host)
        else:
            port = ports[0]
        return port

    @utils.synchronized(
        "service_instance_add_fixed_ips_to_service_port", external=True)
    def _add_fixed_ips_to_service_port(self, port):
        network = self.neutron_api.get_network(self.service_network_id)
        subnets = set(network['subnets'])
        port_fixed_ips = []
        for fixed_ip in port['fixed_ips']:
            port_fixed_ips.append({'subnet_id': fixed_ip['subnet_id'],
                                   'ip_address': fixed_ip['ip_address']})
            if fixed_ip['subnet_id'] in subnets:
                subnets.remove(fixed_ip['subnet_id'])

        # If there are subnets here that means that
        # we need to add those to the port and call update.
        if subnets:
            port_fixed_ips.extend([dict(subnet_id=s) for s in subnets])
            port = self.neutron_api.update_port_fixed_ips(
                port['id'], {'fixed_ips': port_fixed_ips})

        return port

    @utils.synchronized("service_instance_get_private_router", external=True)
    def _get_private_router(self, neutron_net_id, neutron_subnet_id):
        """Returns router attached to private subnet gateway."""
        private_subnet = self.neutron_api.get_subnet(neutron_subnet_id)
        if not private_subnet['gateway_ip']:
            raise exception.ServiceInstanceException(
                _('Subnet must have gateway.'))
        private_network_ports = [p for p in self.neutron_api.list_ports(
                                 network_id=neutron_net_id)]
        for p in private_network_ports:
            fixed_ip = p['fixed_ips'][0]
            if (fixed_ip['subnet_id'] == private_subnet['id'] and
                    fixed_ip['ip_address'] == private_subnet['gateway_ip']):
                private_subnet_gateway_port = p
                break
        else:
            raise exception.ServiceInstanceException(
                _('Subnet gateway is not attached to the router.'))
        private_subnet_router = self.neutron_api.show_router(
            private_subnet_gateway_port['device_id'])
        return private_subnet_router

    @utils.synchronized("service_instance_get_service_subnet", external=True)
    def _get_service_subnet(self, subnet_name):
        all_service_subnets = self._get_all_service_subnets()
        service_subnets = [subnet for subnet in all_service_subnets
                           if subnet['name'] == subnet_name]
        if len(service_subnets) == 1:
            return service_subnets[0]
        elif not service_subnets:
            unused_service_subnets = [subnet for subnet in all_service_subnets
                                      if subnet['name'] == '']
            if unused_service_subnets:
                service_subnet = unused_service_subnets[0]
                self.neutron_api.update_subnet(
                    service_subnet['id'], subnet_name)
                return service_subnet
            return None
        else:
            raise exception.ServiceInstanceException(
                _('Ambiguous service subnets.'))

    @utils.synchronized(
        "service_instance_get_all_service_subnets", external=True)
    def _get_all_service_subnets(self):
        service_network = self.neutron_api.get_network(self.service_network_id)
        subnets = []
        for subnet_id in service_network['subnets']:
            subnets.append(self.neutron_api.get_subnet(subnet_id))
        return subnets


class NovaNetworkHelper(BaseNetworkhelper):
    """Nova network helper for Manila service instances.

    All security-group rules are applied to all interfaces of Nova VM
    using Nova-network. In that case there is no need to create additional
    service network. Only one thing should be satisfied - Manila host
    should have access to all tenant networks.
    This network helper does not create resources.
    """

    def __init__(self, service_instance_manager):
        self.compute_api = service_instance_manager.compute_api
        self.admin_context = service_instance_manager.admin_context

    @property
    def NAME(self):
        return NOVA_NAME

    def setup_network(self, network_info):
        net = self._get_nova_network(network_info['nova_net_id'])
        network_info['nics'] = [{'net-id': net['id']}]
        network_info['service_ip'] = net['gateway']
        return network_info

    def get_network_name(self, network_info):
        """Returns name of network for service instance."""
        return self._get_nova_network(network_info['nova_net_id'])['label']

    def teardown_network(self, server_details):
        """Nothing to do. Placeholder."""

    def setup_connectivity_with_service_instances(self):
        """Nothing to do. Placeholder."""

    def _get_nova_network(self, nova_network_id):
        """Returns network to be used for service instance.

        :param nova_network_id: string with id of network.
        :returns: dict -- network data as dict
        :raises: exception.ManilaException
        """
        if not nova_network_id:
            raise exception.ManilaException(
                _('Nova network for service instance is not provided.'))
        net = self.compute_api.network_get(self.admin_context, nova_network_id)
        return net
