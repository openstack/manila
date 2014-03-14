# Copyright (c) 2014 NetApp, Inc.
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

import netaddr
import os
import socket
import threading
import time

from oslo.config import cfg

from manila import compute
from manila import context
from manila import exception
from manila.network.linux import ip_lib
from manila.network.neutron import api as neutron
from manila.openstack.common import importutils
from manila.openstack.common import log as logging
from manila import utils


LOG = logging.getLogger(__name__)

server_opts = [
    cfg.StrOpt('service_image_name',
               default='manila-service-image',
               help="Name of image in glance, that will be used to create "
               "service instance."),
    cfg.StrOpt('service_instance_name_template',
               default='manila_service_instance-%s',
               help="Name of service instance."),
    cfg.StrOpt('service_instance_user',
               help="User in service instance."),
    cfg.StrOpt('service_instance_password',
               default=None,
               help="Password to service instance user."),
    cfg.StrOpt('manila_service_keypair_name',
               default='manila-service',
               help="Name of keypair that will be created and used "
               "for service instance."),
    cfg.StrOpt('path_to_public_key',
               default='~/.ssh/id_rsa.pub',
               help="Path to hosts public key."),
    cfg.StrOpt('path_to_private_key',
               default='~/.ssh/id_rsa',
               help="Path to hosts private key."),
    cfg.IntOpt('max_time_to_build_instance',
               default=300,
               help="Maximum time to wait for creating service instance."),
    cfg.IntOpt('service_instance_flavor_id',
               default=100,
               help="ID of flavor, that will be used for service instance "
               "creation."),
    cfg.StrOpt('service_network_name',
               default='manila_service_network',
               help="Name of manila service network."),
    cfg.StrOpt('service_network_cidr',
               default='10.254.0.0/16',
               help="CIDR of manila service network."),
    cfg.StrOpt('interface_driver',
               default='manila.network.linux.interface.OVSInterfaceDriver',
               help="Vif driver."),
]

CONF = cfg.CONF
CONF.register_opts(server_opts)

lock = threading.Lock()


def synchronized(f):
    """Decorates function with unique locks for each share network.

    Share network id must be provided either as value/attribute
    of one of args or as named argument.
    """
    def wrapped_func(self, *args, **kwargs):
        share_network_id = kwargs.get('share_network_id', None)
        if not share_network_id:
            for arg in args:
                share_network_id = getattr(arg, 'share_network_id', None)
                if isinstance(arg, dict):
                    share_network_id = arg.get('share_network_id', None)
                if share_network_id:
                    break
            else:
                raise exception.ServiceInstanceException(_('Could not get '
                                                          'share network id'))
        with self.share_networks_locks.setdefault(share_network_id,
                                                  threading.RLock()):
            return f(self, *args, **kwargs)
    return wrapped_func


def _ssh_exec(server, command):
    """Executes ssh commands and checks/restores ssh connection."""
    if not server['ssh'].get_transport().is_active():
        server['ssh_pool'].remove(server['ssh'])
        server['ssh'] = server['ssh_pool'].create()
    return utils.ssh_execute(server['ssh'], ' '.join(command))


class ServiceInstanceManager(object):
    """Manages nova instances for various share drivers."""

    def __init__(self, db, _helpers, *args, **kwargs):
        """Do initialization."""
        super(ServiceInstanceManager, self).__init__(*args, **kwargs)
        if not CONF.service_instance_user:
            raise exception.ServiceInstanceException(_('Service instance user '
                                                       'is not specified'))
        self.admin_context = context.get_admin_context()
        self._execute = utils.execute
        self.compute_api = compute.API()
        self.neutron_api = neutron.API()
        self._helpers = _helpers
        self.db = db
        attempts = 5
        while attempts:
            try:
                self.service_tenant_id = self.neutron_api.admin_tenant_id
                break
            except exception.NetworkException:
                LOG.debug(_('Connection to neutron failed.'))
                attempts -= 1
                time.sleep(3)
        else:
            raise exception.ServiceInstanceException(_('Can not receive '
                                                       'service tenant id.'))
        self.share_networks_locks = {}
        self.share_networks_servers = {}
        self.service_network_id = self._get_service_network()
        self.vif_driver = importutils.import_class(CONF.interface_driver)()
        self._setup_connectivity_with_service_instances()

    def _get_service_network(self):
        """Finds existing or creates new service network."""
        service_network_name = CONF.service_network_name
        networks = [network for network in self.neutron_api.
                    get_all_tenant_networks(self.service_tenant_id)
                    if network['name'] == service_network_name]
        if len(networks) > 1:
            raise exception.ServiceInstanceException(_('Ambiguous service '
                                                       'networks.'))
        elif not networks:
            return self.neutron_api.network_create(self.service_tenant_id,
                                              service_network_name)['id']
        else:
            return networks[0]['id']

    def _get_service_instance_name(self, share_network_id):
        """Returns service vms name."""
        return CONF.service_instance_name_template % share_network_id

    def _get_server_ip(self, server):
        """Returns service vms ip address."""
        net = server['networks']
        try:
            net_ips = net[CONF.service_network_name]
            return net_ips[0]
        except KeyError:
            msg = _('Service vm is not attached to %s network.')
        except IndexError:
            msg = _('Service vm has no ips on %s network.')
        msg = msg % CONF.service_network_name
        LOG.error(msg)
        raise exception.ServiceInstanceException(msg)

    def _ensure_server(self, context, server, update=False):
        """Ensures that server exists and active, otherwise deletes it."""
        if not server:
            return False
        if update:
            try:
                server.update(self.compute_api.server_get(context,
                                                          server['id']))
            except exception.InstanceNotFound as e:
                LOG.debug(e)
                return False
        if server['status'] == 'ACTIVE':
            if self._check_server_availability(server):
                return True

        return False

    def _delete_server(self, context, server):
        """Deletes the server."""
        if not server:
            return
        self.compute_api.server_delete(context, server['id'])
        t = time.time()
        while time.time() - t < CONF.max_time_to_build_instance:
            try:
                server = self.compute_api.server_get(context, server['id'])
            except exception.InstanceNotFound:
                LOG.debug(_('Service instance was deleted succesfully.'))
                break
            time.sleep(1)
        else:
            raise exception.ServiceInstanceException(_('Instance have not '
                'been deleted in %ss. Giving up.') %
                CONF.max_time_to_build_instance)

    @synchronized
    def get_service_instance(self, context, share_network_id, create=True):
        """Finds or creates and sets up service vm."""
        server = self.share_networks_servers.get(share_network_id, {})
        old_server_ip = server.get('ip', None)
        if self._ensure_server(context, server, update=True):
            return server
        else:
            self._delete_server(context, server)
            server = {}
            service_instance_name = self._get_service_instance_name(
                    share_network_id)
            search_opts = {'name': service_instance_name}
            servers = self.compute_api.server_list(context, search_opts, True)
            if len(servers) == 1:
                server = servers[0]
                server['ip'] = self._get_server_ip(server)
                old_server_ip = server['ip']
                if not self._ensure_server(context, server):
                    self._delete_server(context, server)
                    server.clear()
            elif len(servers) > 1:
                raise exception.ServiceInstanceException(
                        _('Error. Ambiguous service instances.'))
            if not server and create:
                server = self._create_service_instance(context,
                                                       service_instance_name,
                                                       share_network_id,
                                                       old_server_ip)
        if server:
            server['share_network_id'] = share_network_id
            server['ip'] = self._get_server_ip(server)
            server['ssh_pool'] = self._get_ssh_pool(server)
            server['ssh'] = server['ssh_pool'].create()
            for helper in self._helpers.values():
                helper.init_helper(server)

        self.share_networks_servers[share_network_id] = server
        return server

    def _get_ssh_pool(self, server):
        """Returns ssh connection pool for service vm."""
        ssh_pool = utils.SSHPool(server['ip'], 22, None,
                                 CONF.service_instance_user,
                                 password=CONF.service_instance_password,
                                 privatekey=CONF.path_to_private_key,
                                 max_size=1)
        return ssh_pool

    def _get_key(self, context):
        """Returns name of key, that will be injected to service vm."""
        if not CONF.path_to_public_key or not CONF.path_to_private_key:
            return
        path_to_public_key = os.path.expanduser(CONF.path_to_public_key)
        path_to_private_key = os.path.expanduser(CONF.path_to_private_key)
        if (not os.path.exists(path_to_public_key) or
                                    not os.path.exists(path_to_private_key)):
            return
        keypair_name = CONF.manila_service_keypair_name
        keypairs = [k for k in self.compute_api.keypair_list(context)
                    if k.name == keypair_name]
        if len(keypairs) > 1:
            raise exception.ServiceInstanceException(_('Ambiguous keypairs.'))

        public_key, __ = self._execute('cat', path_to_public_key)
        if not keypairs:
            keypair = self.compute_api.keypair_import(context,
                                                      keypair_name,
                                                      public_key)
        else:
            keypair = keypairs[0]
            if keypair.public_key != public_key:
                LOG.debug(_('Public key differs from existing keypair. '
                          'Creating new keypair.'))
                self.compute_api.keypair_delete(context, keypair.id)
                keypair = self.compute_api.keypair_import(context,
                                                          keypair_name,
                                                          public_key)
        return keypair.name

    def _get_service_image(self, context):
        """Returns ID of service image for service vm creating."""
        images = [image.id for image in self.compute_api.image_list(context)
                  if image.name == CONF.service_image_name]
        if len(images) == 1:
            return images[0]
        elif not images:
            raise exception.ServiceInstanceException(_('No appropriate '
                                                       'image was found.'))
        else:
            raise exception.ServiceInstanceException(
                                    _('Ambiguous image name.'))

    def _create_service_instance(self, context, instance_name,
                                 share_network_id, old_server_ip):
        """Creates service vm and sets up networking for it."""
        service_image_id = self._get_service_image(context)
        with lock:
            key_name = self._get_key(context)
        if not CONF.service_instance_password and not key_name:
            raise exception.ServiceInstanceException(
                _('Neither service instance password nor key are available.'))

        port = self._setup_network_for_instance(context,
                                                share_network_id,
                                                old_server_ip)
        try:
            self._setup_connectivity_with_service_instances()
        except Exception as e:
            LOG.debug(e)
            self.neutron_api.delete_port(port['id'])
            raise
        service_instance = self.compute_api.server_create(context,
                                              instance_name,
                                              service_image_id,
                                              CONF.service_instance_flavor_id,
                                              key_name,
                                              None,
                                              None,
                                              nics=[{'port-id': port['id']}])

        t = time.time()
        while time.time() - t < CONF.max_time_to_build_instance:
            if service_instance['status'] == 'ACTIVE':
                break
            if service_instance['status'] == 'ERROR':
                raise exception.ServiceInstanceException(
                        _('Failed to build service instance.'))
            time.sleep(1)
            try:
                service_instance = self.compute_api.server_get(context,
                                                        service_instance['id'])
            except exception.InstanceNotFound as e:
                LOG.debug(e)
        else:
            raise exception.ServiceInstanceException(
                    _('Instance have not been spawned in %ss. Giving up.') %
                    CONF.max_time_to_build_instance)

        service_instance['ip'] = self._get_server_ip(service_instance)
        if not self._check_server_availability(service_instance):
            raise exception.ServiceInstanceException(
                            _('SSH connection have not been '
                              'established in %ss. Giving up.') %
                              CONF.max_time_to_build_instance)
        return service_instance

    def _check_server_availability(self, server):
        t = time.time()
        while time.time() - t < CONF.max_time_to_build_instance:
            LOG.debug(_('Checking service vm availablity.'))
            try:
                socket.socket().connect((server['ip'], 22))
                LOG.debug(_('Service vm is available via ssh.'))
                return True
            except socket.error as e:
                LOG.debug(e)
                LOG.debug(_('Server is not available through ssh. Waiting...'))
                time.sleep(5)
        return False

    def _setup_network_for_instance(self, context, share_network_id,
                                    old_server_ip):
        """Sets up network for service vm."""
        service_subnet = self._get_service_subnet(share_network_id)
        if not service_subnet:
            service_subnet = self.neutron_api.subnet_create(
                        self.service_tenant_id,
                        self.service_network_id,
                        share_network_id,
                        self._get_cidr_for_subnet())

        private_router = self._get_private_router(share_network_id)
        try:
            self.neutron_api.router_add_interface(private_router['id'],
                                                  service_subnet['id'])
        except exception.NetworkException as e:
            if e.kwargs['code'] != 400:
                raise
            LOG.debug(_('Subnet %(subnet_id)s is already attached to the '
                        'router %(router_id)s.') %
                                    {'subnet_id': service_subnet['id'],
                                     'router_id': private_router['id']})

        return self.neutron_api.create_port(self.service_tenant_id,
                                            self.service_network_id,
                                            subnet_id=service_subnet['id'],
                                            fixed_ip=old_server_ip,
                                            device_owner='manila')

    def _get_private_router(self, share_network_id):
        """Returns router attached to private subnet gateway."""
        share_network = self.db.share_network_get(self.admin_context,
                                                  share_network_id)
        private_subnet = self.neutron_api.get_subnet(
                                            share_network['neutron_subnet_id'])
        if not private_subnet['gateway_ip']:
            raise exception.ServiceInstanceException(
                    _('Subnet must have gateway.'))
        private_network_ports = [p for p in self.neutron_api.list_ports(
                                 network_id=share_network['neutron_net_id'])]
        for p in private_network_ports:
            fixed_ip = p['fixed_ips'][0]
            if (fixed_ip['subnet_id'] == private_subnet['id'] and
                     fixed_ip['ip_address'] == private_subnet['gateway_ip']):
                private_subnet_gateway_port = p
                break
        else:
            raise exception.ServiceInstanceException(
                    _('Subnet gateway is not attached the router.'))
        private_subnet_router = self.neutron_api.show_router(
                                  private_subnet_gateway_port['device_id'])
        return private_subnet_router

    def _setup_connectivity_with_service_instances(self):
        """Sets up connectivity with service instances.

        Creates creating port in service network, creating and setting up
        required network devices.
        """
        port = self._get_service_port()
        port = self._add_fixed_ips_to_service_port(port)
        interface_name = self.vif_driver.get_device_name(port)
        self.vif_driver.plug(port['id'], interface_name, port['mac_address'])
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

    def _remove_outdated_interfaces(self, device):
        """Finds and removes unused network device."""
        list_dev = []
        for dev in ip_lib.IPWrapper().get_devices():
            if dev.name != device.name and dev.name[:3] == device.name[:3]:
                cidr_set = set()
                for a in dev.addr.list():
                    if a['ip_version'] == 4:
                        cidr_set.add(str(netaddr.IPNetwork(a['cidr']).cidr))
                list_dev.append((dev.name, cidr_set))
        device_cidr_set = set(str(netaddr.IPNetwork(a['cidr']).cidr)
                              for a in device.addr.list()
                              if a['ip_version'] == 4)

        for dev_name, cidr_set in list_dev:
            if device_cidr_set & cidr_set:
                self.vif_driver.unplug(dev_name)

    def _get_service_port(self):
        """Find or creates service neutron port.

        This port will be used for connectivity with service instances.
        """
        ports = [port for port in self.neutron_api.
                 list_ports(device_id='manila-share')]
        if len(ports) > 1:
            raise exception.ServiceInstanceException(
                    _('Error. Ambiguous service ports.'))
        elif not ports:
            try:
                stdout, stderr = self._execute('hostname')
                host = stdout.strip()
            except exception.ProcessExecutionError as e:
                msg = _('Unable to get host. %s') % e.stderr
                raise exception.ManilaException(msg)
            port = self.neutron_api.create_port(self.service_tenant_id,
                                       self.service_network_id,
                                       device_id='manila-share',
                                       device_owner='manila:share',
                                       host_id=host)
        else:
            port = ports[0]
        return port

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

    def _remove_fixed_ip_from_service_port(self, port, subnet_id):
        port_fixed_ips = []
        for fixed_ip in port['fixed_ips']:
            if fixed_ip['subnet_id'] == subnet_id:
                continue
            port_fixed_ips.append({'subnet_id': fixed_ip['subnet_id'],
                                   'ip_address': fixed_ip['ip_address']})

        if port_fixed_ips != port['fixed_ips']:
            port = self.neutron_api.update_port_fixed_ips(
                   port['id'], {'fixed_ips': port_fixed_ips})

        return port

    def _get_cidr_for_subnet(self):
        """Returns not used cidr for service subnet creating."""
        subnets = self._get_all_service_subnets()
        used_cidrs = set(subnet['cidr'] for subnet in subnets)
        serv_cidr = netaddr.IPNetwork(CONF.service_network_cidr)
        for subnet in serv_cidr.subnet(29):
            cidr = str(subnet.cidr)
            if cidr not in used_cidrs:
                return cidr
        else:
            raise exception.ServiceInstanceException(_('No available cidrs.'))

    def delete_share_infrastructure(self, context, share_network_id):
        """Removes share infrastructure.

        Deletes service vm and subnet, associated to share network.
        """
        server = self.get_service_instance(context,
                                           share_network_id=share_network_id,
                                           create=False)
        if server:
            self._delete_server(context, server)
        subnet_id = self._get_service_subnet(share_network_id)
        if subnet_id:
            router = self._get_private_router(share_network_id)
            port = self._get_service_port()
            self.neutron_api.router_remove_interface(router['id'], subnet_id)
            self._remove_fixed_ip_from_service_port(port, subnet_id)
            self.neutron_api.delete_subnet(subnet_id)
            self._setup_connectivity_with_service_instances()

    def _get_all_service_subnets(self):
        service_network = self.neutron_api.get_network(self.service_network_id)
        return [self.neutron_api.get_subnet(subnet_id)
                for subnet_id in service_network['subnets']]

    def _get_service_subnet(self, share_network_id):
        all_service_subnets = self._get_all_service_subnets()
        service_subnets = [subnet for subnet in all_service_subnets
                           if subnet['name'] == share_network_id]
        if len(service_subnets) == 1:
            return service_subnets[0]
        elif not service_subnets:
            return None
        else:
            raise exception.ServiceInstanceException(_('Ambiguous service '
                                                       'subnets.'))
