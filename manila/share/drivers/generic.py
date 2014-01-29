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
"""
Generic Driver for shares.

"""

import ConfigParser
import netaddr
import os
import re
import shutil
import socket
import threading
import time

from manila import compute
from manila import context
from manila import exception
from manila.network.linux import ip_lib
from manila.network.neutron import api as neutron
from manila.openstack.common import importutils
from manila.openstack.common import log as logging
from manila.share import driver
from manila import utils
from manila import volume

from oslo.config import cfg

LOG = logging.getLogger(__name__)

share_opts = [
    cfg.StrOpt('service_image_name',
               default='manila-service-image',
               help="Name of image in glance, that will be used to create "
               "service instance"),
    cfg.StrOpt('smb_template_config_path',
               default='$state_path/smb.conf',
               help="Path to smb config"),
    cfg.StrOpt('service_instance_name_template',
               default='manila_service_instance-%s',
               help="Name of service instance"),
    cfg.StrOpt('service_instance_user',
               help="User in service instance"),
    cfg.StrOpt('service_instance_password',
               default=None,
               help="Password to service instance user"),
    cfg.StrOpt('volume_name_template',
               default='manila-share-%s',
               help="Volume name template"),
    cfg.StrOpt('manila_service_keypair_name',
               default='manila-service',
               help="Name of keypair that will be created and used "
               "for service instance"),
    cfg.StrOpt('path_to_public_key',
               default='/home/stack/.ssh/id_rsa.pub',
               help="Path to hosts public key"),
    cfg.StrOpt('path_to_private_key',
               default='/home/stack/.ssh/id_rsa',
               help="Path to hosts private key"),
    cfg.StrOpt('volume_snapshot_name_template',
               default='manila-snapshot-%s',
               help="Volume snapshot name template"),
    cfg.IntOpt('max_time_to_build_instance',
               default=300,
               help="Maximum time to wait for creating service instance"),
    cfg.StrOpt('share_mount_path',
               default='/shares',
               help="Parent path in service instance where shares "
               "will be mounted"),
    cfg.IntOpt('max_time_to_create_volume',
               default=180,
               help="Maximum time to wait for creating cinder volume"),
    cfg.IntOpt('max_time_to_attach',
               default=120,
               help="Maximum time to wait for attaching cinder volume"),
    cfg.IntOpt('service_instance_flavor_id',
               default=100,
               help="ID of flavor, that will be used for service instance "
               "creation"),
    cfg.StrOpt('service_instance_smb_config_path',
               default='$share_mount_path/smb.conf',
               help="Path to smb config in service instance"),
    cfg.StrOpt('service_network_name',
               default='manila_service_network',
               help="Name of manila service network"),
    cfg.StrOpt('service_network_cidr',
               default='10.254.0.0/16',
               help="CIDR of manila service network"),
    cfg.StrOpt('interface_driver',
               default='manila.network.linux.interface.OVSInterfaceDriver',
               help="Vif driver"),
    cfg.ListOpt('share_helpers',
                default=[
                    'CIFS=manila.share.drivers.generic.CIFSHelper',
                    'NFS=manila.share.drivers.generic.NFSHelper',
                ],
                help='Specify list of share export helpers.'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)


def synchronized(f):
    """Decorates function with unique locks for each share network."""
    def wrapped_func(self, *args, **kwargs):
        for arg in args:
            share_network_id = getattr(arg, 'share_network_id', None)
            if isinstance(arg, dict):
                share_network_id = arg.get('share_network_id', None)
            if share_network_id:
                break
        else:
            raise exception.\
                        ManilaException(_('Could not get share network id'))
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


class GenericShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """Executes commands relating to Shares."""

    def __init__(self, db, *args, **kwargs):
        """Do initialization."""
        super(GenericShareDriver, self).__init__(*args, **kwargs)
        self.admin_context = context.get_admin_context()
        self.db = db
        self.configuration.append_config_values(share_opts)
        self._helpers = None

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met."""
        if not self.configuration.service_instance_user:
            raise exception.ManilaException(_('Service instance user is not '
                                              'specified'))

    def do_setup(self, context):
        """Any initialization the generic driver does while starting."""
        super(GenericShareDriver, self).do_setup(context)
        self.compute_api = compute.API()
        self.volume_api = volume.API()
        self.neutron_api = neutron.API()
        self.share_networks_locks = {}
        self.share_networks_servers = {}
        attempts = 5
        while attempts:
            try:
                self.service_tenant_id = self.neutron_api.admin_tenant_id
                break
            except exception.NetworkException:
                LOG.debug(_('Connection to neutron failed'))
                attempts -= 1
                time.sleep(3)
        else:
            raise exception.\
                    ManilaException(_('Can not receive service tenant id'))
        self.service_network_id = self._get_service_network()
        self.vif_driver = importutils.\
                import_class(self.configuration.interface_driver)()
        self._setup_connectivity_with_service_instances()
        self._setup_helpers()

    def _get_service_network(self):
        """Finds existing or creates new service network."""
        service_network_name = self.configuration.service_network_name
        networks = [network for network in self.neutron_api.
                    get_all_tenant_networks(self.service_tenant_id)
                    if network['name'] == service_network_name]
        if len(networks) > 1:
            raise exception.ManilaException(_('Ambiguous service networks'))
        elif not networks:
            return self.neutron_api.network_create(self.service_tenant_id,
                                              service_network_name)['id']
        else:
            return networks[0]['id']

    def _setup_helpers(self):
        """Initializes protocol-specific NAS drivers."""
        self._helpers = {}
        for helper_str in self.configuration.share_helpers:
            share_proto, _, import_str = helper_str.partition('=')
            helper = importutils.import_class(import_str)
            self._helpers[share_proto.upper()] = helper(self._execute,
                                                    self.configuration,
                                                    self.share_networks_locks)

    def create_share(self, context, share):
        """Creates share."""
        if share['share_network_id'] is None:
            raise exception.\
                    ManilaException(_('Share Network is not specified'))
        server = self._get_service_instance(self.admin_context, share)
        volume = self._allocate_container(context, share)
        volume = self._attach_volume(context, share, server, volume)
        self._format_device(server, volume)
        self._mount_device(context, share, server, volume)
        location = self._get_helper(share).create_export(server, share['name'])
        return location

    def _format_device(self, server, volume):
        """Formats device attached to the service vm."""
        command = ['sudo', 'mkfs.ext4', volume['mountpoint']]
        _ssh_exec(server, command)

    def _mount_device(self, context, share, server, volume):
        """Mounts attached and formatted block device to the directory."""
        mount_path = self._get_mount_path(share)
        command = ['sudo', 'mkdir', '-p', mount_path, ';']
        command.extend(['sudo', 'mount', volume['mountpoint'], mount_path])
        try:
            _ssh_exec(server, command)
        except exception.ProcessExecutionError as e:
            if 'already mounted' not in e.stderr:
                raise
            LOG.debug(_('Share %s is already mounted') % share['name'])
        command = ['sudo', 'chmod', '777', mount_path]
        _ssh_exec(server, command)

    def _unmount_device(self, context, share, server):
        """Unmounts device from directory on service vm."""
        mount_path = self._get_mount_path(share)
        command = ['sudo', 'umount', mount_path, ';']
        command.extend(['sudo', 'rmdir', mount_path])
        try:
            _ssh_exec(server, command)
        except exception.ProcessExecutionError as e:
            if 'not found' in e.stderr:
                LOG.debug(_('%s is not mounted') % share['name'])

    def _get_mount_path(self, share):
        """
        Returns the path, that will be used for mount device in service vm.
        """
        return os.path.join(self.configuration.share_mount_path, share['name'])

    @synchronized
    def _attach_volume(self, context, share, server, volume):
        """Attaches cinder volume to service vm."""
        if volume['status'] == 'in-use':
            attached_volumes = [vol.id for vol in
                self.compute_api.instance_volumes_list(self.admin_context,
                                                       server['id'])]
            if volume['id'] in attached_volumes:
                return volume
            else:
                raise exception.ManilaException(_('Volume %s is already '
                        'attached to another instance') % volume['id'])
        device_path = self._get_device_path(self.admin_context, server)
        self.compute_api.instance_volume_attach(self.admin_context,
                                                server['id'],
                                                volume['id'],
                                                device_path)

        t = time.time()
        while time.time() - t < self.configuration.max_time_to_attach:
            volume = self.volume_api.get(context, volume['id'])
            if volume['status'] == 'in-use':
                break
            elif volume['status'] != 'attaching':
                raise exception.ManilaException(_('Failed to attach volume %s')
                                                % volume['id'])
            time.sleep(1)
        else:
            raise exception.ManilaException(_('Volume have not been attached '
                                              'in %ss. Giving up') %
                                      self.configuration.max_time_to_attach)

        return volume

    def _get_volume(self, context, share_id):
        """Finds volume, associated to the specific share."""
        volume_name = self.configuration.volume_name_template % share_id
        search_opts = {'display_name': volume_name}
        if context.is_admin:
            search_opts['all_tenants'] = True
        volumes_list = self.volume_api.get_all(context, search_opts)
        volume = None
        if len(volumes_list) == 1:
            volume = volumes_list[0]
        elif len(volumes_list) > 1:
            raise exception.ManilaException(_('Error. Ambiguous volumes'))
        return volume

    def _get_volume_snapshot(self, context, snapshot_id):
        """Finds volume snaphots, associated to the specific share snaphots."""
        volume_snapshot_name = self.configuration.\
                volume_snapshot_name_template % snapshot_id
        volume_snapshot_list = self.volume_api.get_all_snapshots(context,
                                        {'display_name': volume_snapshot_name})
        volume_snapshot = None
        if len(volume_snapshot_list) == 1:
            volume_snapshot = volume_snapshot_list[0]
        elif len(volume_snapshot_list) > 1:
            raise exception.\
                    ManilaException(_('Error. Ambiguous volume snaphots'))
        return volume_snapshot

    @synchronized
    def _detach_volume(self, context, share, server):
        """Detaches cinder volume from service vm."""
        attached_volumes = [vol.id for vol in
                self.compute_api.instance_volumes_list(self.admin_context,
                                                       server['id'])]
        volume = self._get_volume(context, share['id'])
        if volume and volume['id'] in attached_volumes:
            self.compute_api.instance_volume_detach(self.admin_context,
                                                    server['id'],
                                                    volume['id'])
            t = time.time()
            while time.time() - t < self.configuration.max_time_to_attach:
                volume = self.volume_api.get(context, volume['id'])
                if volume['status'] in ('available', 'error'):
                    break
                time.sleep(1)
            else:
                raise exception.ManilaException(_('Volume have not been '
                                                  'detached in %ss. Giving up')
                                       % self.configuration.max_time_to_attach)

    def _get_device_path(self, context, server):
        """Returns device path, that will be used for cinder volume attaching.
        """
        volumes = self.compute_api.instance_volumes_list(context, server['id'])
        used_literals = set(volume.device[-1] for volume in volumes
                            if '/dev/vd' in volume.device)
        lit = 'b'
        while lit in used_literals:
            lit = chr(ord(lit) + 1)
        device_name = '/dev/vd' + lit
        return device_name

    def _get_service_instance_name(self, share):
        """Returns service vms name."""
        return self.configuration.service_instance_name_template % \
                    share['share_network_id']

    def _get_server_ip(self, server):
        """Returns service vms ip address."""
        net = server['networks']
        try:
            net_ips = net[self.configuration.service_network_name]
            return net_ips[0]
        except KeyError:
            msg = _('Service vm is not attached to %s network')
        except IndexError:
            msg = _('Service vm has no ips on %s network')
        msg = msg % self.configuration.service_network_name
        LOG.error(msg)
        raise exception.ManilaException(msg)

    def _ensure_or_delete_server(self, context, server, update=False):
        """Ensures that server exists and active, otherwise deletes it."""
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

        self._delete_server(context, server)
        return False

    def _delete_server(self, context, server):
        """Deletes the server."""
        self.compute_api.server_delete(context, server['id'])
        t = time.time()
        while time.time() - t < self.configuration.\
                                         max_time_to_build_instance:
            try:
                server = self.compute_api.server_get(context,
                                                     server['id'])
            except exception.InstanceNotFound:
                LOG.debug(_('Service instance was deleted succesfully'))
                break
            time.sleep(1)
        else:
            raise exception.ManilaException(_('Instance have not been deleted '
                                              'in %ss. Giving up') %
                                 self.configuration.max_time_to_build_instance)

    @synchronized
    def _get_service_instance(self, context, share, create=True):
        """Finds or creates and setups service vm."""
        server = self.share_networks_servers.get(share['share_network_id'], {})
        old_server_ip = server.get('ip', None)
        if server and self._ensure_or_delete_server(context,
                                                    server,
                                                    update=True):
            return server
        else:
            server = {}
            service_instance_name = self._get_service_instance_name(share)
            search_opts = {'name': service_instance_name}
            servers = self.compute_api.server_list(context, search_opts, True)
            if len(servers) == 1:
                server = servers[0]
                server['ip'] = self._get_server_ip(server)
                old_server_ip = server['ip']
                if not self._ensure_or_delete_server(context, server):
                    server.clear()
            elif len(servers) > 1:
                raise exception.\
                        ManilaException(_('Ambiguous service instances'))
            if not server and create:
                server = self._create_service_instance(context,
                                                       service_instance_name,
                                                       share, old_server_ip)
        if server:
            server['share_network_id'] = share['share_network_id']
            server['ip'] = self._get_server_ip(server)
            server['ssh_pool'] = self._get_ssh_pool(server)
            server['ssh'] = server['ssh_pool'].create()
            for helper in self._helpers.values():
                helper.init_helper(server)

        self.share_networks_servers[share['share_network_id']] = server
        return server

    def _get_ssh_pool(self, server):
        """Returns ssh connection pool for service vm."""
        ssh_pool = utils.SSHPool(server['ip'], 22, None,
                         self.configuration.service_instance_user,
                         password=self.configuration.service_instance_password,
                         privatekey=self.configuration.path_to_private_key,
                         max_size=1)
        return ssh_pool

    def _get_key(self, context):
        """Returns name of key, that will be injected to service vm."""
        if not self.configuration.path_to_public_key or \
                not self.configuration.path_to_private_key:
            return
        if not os.path.exists(self.configuration.path_to_public_key) or \
                not os.path.exists(self.configuration.path_to_private_key):
            return
        keypair_name = self.configuration.manila_service_keypair_name
        keypairs = [k for k in self.compute_api.keypair_list(context)
                    if k.name == keypair_name]
        if len(keypairs) > 1:
            raise exception.ManilaException(_('Ambiguous keypairs'))

        public_key, _ = self._execute('cat',
                                      self.configuration.path_to_public_key,
                                      run_as_root=True)
        if not keypairs:
            keypair = self.compute_api.keypair_import(context, keypair_name,
                                                      public_key)
        else:
            keypair = keypairs[0]
            if keypair.public_key != public_key:
                LOG.debug('Public key differs from existing keypair. '
                          'Creating new keypair')
                self.compute_api.keypair_delete(context, keypair.id)
                keypair = self.compute_api.keypair_import(context,
                                                          keypair_name,
                                                          public_key)
        return keypair.name

    def _get_service_image(self, context):
        """Returns ID of service image, that will be used for service vm
           creating.
        """
        images = [image.id for image in self.compute_api.image_list(context)
                  if image.name == self.configuration.service_image_name]
        if len(images) == 1:
            return images[0]
        elif not images:
            raise exception.\
                    ManilaException(_('No appropriate image was found'))
        else:
            raise exception.ManilaException(_('Ambiguous image name'))

    def _create_service_instance(self, context, instance_name, share,
                                 old_server_ip):
        """Creates service vm and sets up networking for it."""
        service_image_id = self._get_service_image(context)
        key_name = self._get_key(context)
        if not self.configuration.service_instance_password and not key_name:
            raise exception.ManilaException(_('Neither service instance'
                                             'password nor key are available'))

        port = self._setup_network_for_instance(context, share, old_server_ip)
        try:
            self._setup_connectivity_with_service_instances()
        except Exception as e:
            LOG.debug(e)
            self.neutron_api.delete_port(port['id'])
            raise
        service_instance = self.compute_api.server_create(context,
                                instance_name, service_image_id,
                                self.configuration.service_instance_flavor_id,
                                key_name, None, None,
                                nics=[{'port-id': port['id']}])

        t = time.time()
        while time.time() - t < self.configuration.max_time_to_build_instance:
            if service_instance['status'] == 'ACTIVE':
                break
            if service_instance['status'] == 'ERROR':
                raise exception.ManilaException(_('Failed to build service '
                                                  'instance'))
            time.sleep(1)
            try:
                service_instance = self.compute_api.server_get(context,
                                    service_instance['id'])
            except exception.InstanceNotFound as e:
                LOG.debug(e)
        else:
            raise exception.ManilaException(_('Instance have not been spawned '
                                              'in %ss. Giving up') %
                                 self.configuration.max_time_to_build_instance)

        service_instance['ip'] = self._get_server_ip(service_instance)
        if not self._check_server_availability(service_instance):
            raise exception.ManilaException(_('SSH connection have not been '
                                              'established in %ss. Giving up')
                              % self.configuration.max_time_to_build_instance)
        return service_instance

    def _check_server_availability(self, server):
        t = time.time()
        while time.time() - t < self.configuration.max_time_to_build_instance:
            LOG.debug('Checking service vm availablity')
            try:
                socket.socket().connect((server['ip'], 22))
                LOG.debug(_('Service vm is available via ssh.'))
                return True
            except socket.error as e:
                LOG.debug(e)
                LOG.debug(_('Server is not available through ssh. Waiting...'))
                time.sleep(5)
        return False

    def _setup_network_for_instance(self, context, share, old_server_ip):
        """Setups network for service vm."""
        service_network = self.neutron_api.get_network(self.service_network_id)
        all_service_subnets = [self.neutron_api.get_subnet(subnet_id)
                               for subnet_id in service_network['subnets']]
        service_subnets = [subnet for subnet in all_service_subnets
                           if subnet['name'] == share['share_network_id']]
        if len(service_subnets) > 1:
            raise exception.ManilaException(_('Ambiguous subnets'))
        elif not service_subnets:
            service_subnet = \
                    self.neutron_api.subnet_create(self.service_tenant_id,
                        self.service_network_id,
                        share['share_network_id'],
                        self._get_cidr_for_subnet(all_service_subnets))
        else:
            service_subnet = service_subnets[0]

        share_network = self.db.share_network_get(context,
                                                  share['share_network_id'])
        private_router = self._get_private_router(share_network)
        try:
            self.neutron_api.router_add_interface(private_router['id'],
                                                  service_subnet['id'])
        except exception.NetworkException as e:
            if 'already has' not in e.msg:
                raise
            LOG.debug(_('Subnet %(subnet_id)s is already attached to the '
                        'router %(router_id)s') %
                                    {'subnet_id': service_subnet['id'],
                                     'router_id': private_router['id']})

        return self.neutron_api.create_port(self.service_tenant_id,
                                            self.service_network_id,
                                            subnet_id=service_subnet['id'],
                                            fixed_ip=old_server_ip,
                                            device_owner='manila')

    def _get_private_router(self, share_network):
        """Returns router attached to private subnet gateway."""
        private_subnet = self.neutron_api.\
                get_subnet(share_network['neutron_subnet_id'])
        if not private_subnet['gateway_ip']:
            raise exception.ManilaException(_('Subnet must have gateway'))
        private_network_ports = [p for p in self.neutron_api.list_ports(
                                 network_id=share_network['neutron_net_id'])]
        for p in private_network_ports:
            fixed_ip = p['fixed_ips'][0]
            if fixed_ip['subnet_id'] == private_subnet['id'] and \
                     fixed_ip['ip_address'] == private_subnet['gateway_ip']:
                private_subnet_gateway_port = p
                break
        else:
            raise exception.ManilaException(_('Subnet gateway is not attached '
                                              'the router'))
        private_subnet_router = self.neutron_api.show_router(
                                  private_subnet_gateway_port['device_id'])
        return private_subnet_router

    def _setup_connectivity_with_service_instances(self):
        """Setups connectivity with service instances by creating port
        in service network, creating and setting up required network devices.
        """
        port = self._setup_service_port()
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
        self._clean_garbage(device)

    def _clean_garbage(self, device):
        """Finds and removes network device, that was associated with deleted
        service port.
        """
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

    def _setup_service_port(self):
        """Find or creates neutron port, that will be used for connectivity
        with service instances.
        """
        ports = [port for port in self.neutron_api.
                 list_ports(device_id='manila-share')]
        if len(ports) > 1:
            raise exception.\
                        ManilaException(_('Error. Ambiguous service ports'))
        elif not ports:
            services = self.db.service_get_all_by_topic(self.admin_context,
                                                        'manila-share')
            host = services[0]['host'] if services else None
            if host is None:
                raise exception.ManilaException('Unable to get host')
            port = self.neutron_api.create_port(self.service_tenant_id,
                                       self.service_network_id,
                                       device_id='manila-share',
                                       device_owner='manila:generic_driver',
                                       host_id=host)
        else:
            port = ports[0]

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

    def _get_cidr_for_subnet(self, subnets):
        """Returns not used cidr for service subnet creating."""
        used_cidrs = set(subnet['cidr'] for subnet in subnets)
        serv_cidr = netaddr.IPNetwork(self.configuration.service_network_cidr)
        for subnet in serv_cidr.subnet(29):
            cidr = str(subnet.cidr)
            if cidr not in used_cidrs:
                return cidr
        else:
            raise exception.ManilaException(_('No available cidrs'))

    def _allocate_container(self, context, share, snapshot=None):
        """Creates cinder volume, associated to share by name."""
        volume_snapshot = None
        if snapshot:
            volume_snapshot = self._get_volume_snapshot(context,
                                                        snapshot['id'])
        volume = self.volume_api.create(context, share['size'],
                     self.configuration.volume_name_template % share['id'], '',
                     snapshot=volume_snapshot)

        t = time.time()
        while time.time() - t < self.configuration.max_time_to_create_volume:
            if volume['status'] == 'available':
                break
            if volume['status'] == 'error':
                raise exception.ManilaException(_('Failed to create volume'))
            time.sleep(1)
            volume = self.volume_api.get(context, volume['id'])
        else:
            raise exception.ManilaException(_('Volume have not been created '
                                              'in %ss. Giving up') %
                                 self.configuration.max_time_to_create_volume)

        return volume

    def _deallocate_container(self, context, share):
        """Deletes cinder volume."""
        volume = self._get_volume(context, share['id'])
        if volume:
            self.volume_api.delete(context, volume['id'])
            t = time.time()
            while time.time() - t < self.configuration.\
                                                    max_time_to_create_volume:
                try:
                    volume = self.volume_api.get(context, volume['id'])
                except exception.VolumeNotFound:
                    LOG.debug(_('Volume was deleted succesfully'))
                    break
                time.sleep(1)
            else:
                raise exception.ManilaException(_('Volume have not been '
                                                  'deleted in %ss. Giving up')
                               % self.configuration.max_time_to_create_volume)

    def get_share_stats(self, refresh=False):
        """Get share status.
        If 'refresh' is True, run update the stats first."""
        if refresh:
            self._update_share_status()

        return self._stats

    def _update_share_status(self):
        """Retrieve status info from share volume group."""

        LOG.debug(_("Updating share status"))
        data = {}

        # Note(zhiteng): These information are driver/backend specific,
        # each driver may define these values in its own config options
        # or fetch from driver specific configuration file.
        data["share_backend_name"] = 'Cinder Volumes'
        data["vendor_name"] = 'Open Source'
        data["driver_version"] = '1.0'
        data["storage_protocol"] = 'NFS_CIFS'

        data['total_capacity_gb'] = 'infinite'
        data['free_capacity_gb'] = 'infinite'
        data['reserved_percentage'] = \
            self.configuration.reserved_share_percentage
        data['QoS_support'] = False

        self._stats = data

    def create_share_from_snapshot(self, context, share, snapshot):
        """Is called to create share from snapshot."""
        server = self._get_service_instance(self.admin_context, share)
        volume = self._allocate_container(context, share, snapshot)
        volume = self._attach_volume(context, share, server, volume)
        self._mount_device(context, share, server, volume)
        location = self._get_helper(share).create_export(server,
                                                         share['name'])
        return location

    def delete_share(self, context, share):
        """Deletes share."""
        if not share['share_network_id']:
            return
        server = self._get_service_instance(self.admin_context,
                                            share, create=False)
        if server:
            self._get_helper(share).remove_export(server, share['name'])
            self._unmount_device(context, share, server)
            self._detach_volume(context, share, server)
        self._deallocate_container(context, share)

    def create_snapshot(self, context, snapshot):
        """Creates a snapshot."""
        volume = self._get_volume(context, snapshot['share_id'])
        volume_snapshot_name = self.configuration.\
                volume_snapshot_name_template % snapshot['id']
        volume_snapshot = self.volume_api.create_snapshot_force(context,
                                              volume['id'],
                                              volume_snapshot_name,
                                              '')
        t = time.time()
        while time.time() - t < self.configuration.max_time_to_create_volume:
            if volume_snapshot['status'] == 'available':
                break
            if volume_snapshot['status'] == 'error':
                raise exception.ManilaException(_('Failed to create volume '
                                                  'snapshot'))
            time.sleep(1)
            volume_snapshot = self.volume_api.get_snapshot(context,
                                                volume_snapshot['id'])
        else:
            raise exception.ManilaException(_('Volume snapshot have not been '
                                              'created in %ss. Giving up') %
                                  self.configuration.max_time_to_create_volume)

    def delete_snapshot(self, context, snapshot):
        """Deletes a snapshot."""
        volume_snapshot = self._get_volume_snapshot(context, snapshot['id'])
        if volume_snapshot is None:
            return
        self.volume_api.delete_snapshot(context, volume_snapshot['id'])
        t = time.time()
        while time.time() - t < self.configuration.max_time_to_create_volume:
            try:
                snapshot = self.volume_api.get_snapshot(context,
                                                        volume_snapshot['id'])
            except exception.VolumeSnapshotNotFound:
                LOG.debug(_('Volume snapshot was deleted succesfully'))
                break
            time.sleep(1)
        else:
            raise exception.ManilaException(_('Volume snapshot have not been '
                                              'deleted in %ss. Giving up') %
                                  self.configuration.max_time_to_create_volume)

    def ensure_share(self, context, share):
        """Ensure that storage are mounted and exported."""
        server = self._get_service_instance(context, share)
        volume = self._get_volume(context, share['id'])
        volume = self._attach_volume(context, share, server, volume)
        self._mount_device(context, share, server, volume)
        self._get_helper(share).create_export(server, share['name'])

    def allow_access(self, context, share, access):
        """Allow access to the share."""
        server = self._get_service_instance(self.admin_context,
                                            share,
                                            create=False)
        if not server:
            raise exception.ManilaException('Server not found. Try to '
                                            'restart manila share service')
        self._get_helper(share).allow_access(server, share['name'],
                                             access['access_type'],
                                             access['access_to'])

    def deny_access(self, context, share, access):
        """Deny access to the share."""
        if not share['share_network_id']:
            return
        server = self._get_service_instance(self.admin_context,
                                            share,
                                            create=False)
        if server:
            self._get_helper(share).deny_access(server, share['name'],
                                                access['access_type'],
                                                access['access_to'])

    def _get_helper(self, share):
        if share['share_proto'].startswith('NFS'):
            return self._helpers['NFS']
        elif share['share_proto'].startswith('CIFS'):
            return self._helpers['CIFS']
        else:
            raise exception.InvalidShare(reason='Wrong share type')

    def get_network_allocations_number(self):
        return 0

    def setup_network(self, network_info):
        pass


class NASHelperBase(object):
    """Interface to work with share."""

    def __init__(self, execute, config_object, locks):
        self.configuration = config_object
        self._execute = execute
        self.share_networks_locks = locks

    def init_helper(self, server):
        pass

    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        raise NotImplementedError()

    def remove_export(self, server, share_name):
        """Remove export."""
        raise NotImplementedError()

    def allow_access(self, server, share_name, access_type, access):
        """Allow access to the host."""
        raise NotImplementedError()

    def deny_access(self, local_path, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        raise NotImplementedError()


class NFSHelper(NASHelperBase):
    """Interface to work with share."""

    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        return ':'.join([server['ip'],
            os.path.join(self.configuration.share_mount_path, share_name)])

    def init_helper(self, server):
        try:
            _ssh_exec(server, ['sudo', 'exportfs'])
        except exception.ProcessExecutionError as e:
            if 'command not found' in e.stderr:
                raise exception.ManilaException(
                    _('NFS server is not installed on %s') % server['id'])
            LOG.error(e.stderr)

    def remove_export(self, server, share_name):
        """Remove export."""
        pass

    def allow_access(self, server, share_name, access_type, access):
        """Allow access to the host"""
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        #check if presents in export
        out, _ = _ssh_exec(server, ['sudo', 'exportfs'])
        out = re.search(re.escape(local_path) + '[\s\n]*' + re.escape(access),
                        out)
        if out is not None:
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)
        _ssh_exec(server, ['sudo', 'exportfs', '-o', 'rw,no_subtree_check',
                  ':'.join([access, local_path])])

    def deny_access(self, server, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        _ssh_exec(server, ['sudo', 'exportfs', '-u',
                           ':'.join([access, local_path])])


class CIFSHelper(NASHelperBase):
    """Class provides functionality to operate with cifs shares"""

    def __init__(self, *args):
        """Store executor and configuration path."""
        super(CIFSHelper, self).__init__(*args)
        self.config_path = self.configuration.service_instance_smb_config_path
        self.smb_template_config = self.configuration.smb_template_config_path
        self.test_config = "%s_" % (self.smb_template_config,)
        self.local_configs = {}

    def _create_local_config(self, share_network_id):
        path, ext = os.path.splitext(self.smb_template_config)
        local_config = '%s-%s%s' % (path, share_network_id, ext)
        self.local_configs[share_network_id] = local_config
        shutil.copy(self.smb_template_config, local_config)
        return local_config

    def _get_local_config(self, share_network_id):
        local_config = self.local_configs.get(share_network_id, None)
        if local_config is None:
            local_config = self._create_local_config(share_network_id)
        return local_config

    def init_helper(self, server):
        self._recreate_template_config()
        local_config = self._create_local_config(server['share_network_id'])
        config_dir = os.path.dirname(self.config_path)
        try:
            _ssh_exec(server, ['sudo', 'mkdir',
                               config_dir])
        except exception.ProcessExecutionError as e:
            if 'File exists' not in e.stderr:
                raise
            LOG.debug(_('Directory %s already exists') % config_dir)
        _ssh_exec(server, ['sudo', 'chown',
                           self.configuration.service_instance_user,
                           config_dir])
        _ssh_exec(server, ['touch', self.config_path])
        try:
            _ssh_exec(server, ['sudo', 'stop', 'smbd'])
        except exception.ProcessExecutionError as e:
            if 'Unknown instance' not in e.stderr:
                raise
            LOG.debug(_('Samba service is not running'))
        self._write_remote_config(local_config, server)
        _ssh_exec(server, ['sudo', 'smbd', '-s', self.config_path])
        self._restart_service(server)

    def create_export(self, server, share_name, recreate=False):
        """Create new export, delete old one if exists."""
        local_path = os.path.join(self.configuration.share_mount_path,
                                  share_name)
        config = self._get_local_config(server['share_network_id'])
        parser = ConfigParser.ConfigParser()
        parser.read(config)
        #delete old one
        if parser.has_section(share_name):
            if recreate:
                parser.remove_section(share_name)
            else:
                raise exception.Error('Section exists')
        #Create new one
        parser.add_section(share_name)
        parser.set(share_name, 'path', local_path)
        parser.set(share_name, 'browseable', 'yes')
        parser.set(share_name, 'guest ok', 'yes')
        parser.set(share_name, 'read only', 'no')
        parser.set(share_name, 'writable', 'yes')
        parser.set(share_name, 'create mask', '0755')
        parser.set(share_name, 'hosts deny', '0.0.0.0/0')  # denying all ips
        parser.set(share_name, 'hosts allow', '127.0.0.1')
        self._update_config(parser, config)
        self._write_remote_config(config, server)
        self._restart_service(server)
        return '//%s/%s' % (server['ip'], share_name)

    def remove_export(self, server, share_name):
        """Remove export."""
        config = self._get_local_config(server['share_network_id'])
        parser = ConfigParser.ConfigParser()
        parser.read(config)
        #delete old one
        if parser.has_section(share_name):
            parser.remove_section(share_name)
        self._update_config(parser, config)
        self._write_remote_config(config, server)
        _ssh_exec(server, ['sudo', 'smbcontrol', 'all', 'close-share',
                       share_name])

    @synchronized
    def _write_remote_config(self, config, server):
        with open(config, 'r') as f:
            cfg = "'" + f.read() + "'"
        _ssh_exec(server, ['echo %s > %s' % (cfg, self.config_path)])

    def allow_access(self, server, share_name, access_type, access):
        """Allow access to the host."""
        if access_type != 'ip':
            reason = 'only ip access type allowed'
            raise exception.InvalidShareAccess(reason)
        config = self._get_local_config(server['share_network_id'])
        parser = ConfigParser.ConfigParser()
        parser.read(config)

        hosts = parser.get(share_name, 'hosts allow')

        if access in hosts.split():
            raise exception.ShareAccessExists(access_type=access_type,
                                              access=access)
        hosts += ' %s' % (access,)
        parser.set(share_name, 'hosts allow', hosts)
        self._update_config(parser, config)
        self._write_remote_config(config, server)
        self._restart_service(server)

    def deny_access(self, server, share_name, access_type, access,
                    force=False):
        """Deny access to the host."""
        config = self._get_local_config(server['share_network_id'])
        parser = ConfigParser.ConfigParser()
        try:
            parser.read(config)
            hosts = parser.get(share_name, 'hosts allow')
            hosts = hosts.replace(' %s' % (access,), '', 1)
            parser.set(share_name, 'hosts allow', hosts)
            self._update_config(parser, config)
        except ConfigParser.NoSectionError:
            if not force:
                raise
        self._write_remote_config(config, server)
        self._restart_service(server)

    def _recreate_template_config(self):
        """Create new SAMBA configuration file."""
        if os.path.exists(self.smb_template_config):
            os.unlink(self.smb_template_config)
        parser = ConfigParser.ConfigParser()
        parser.add_section('global')
        parser.set('global', 'security', 'user')
        parser.set('global', 'server string', '%h server (Samba, Openstack)')
        self._update_config(parser, self.smb_template_config)

    def _restart_service(self, server):
        _ssh_exec(server, 'sudo pkill -HUP smbd'.split())

    def _update_config(self, parser, config):
        """Check if new configuration is correct and save it."""
        #Check that configuration is correct
        with open(self.test_config, 'w') as fp:
            parser.write(fp)
        self._execute('testparm', '-s', self.test_config,
                      check_exit_code=True)
        #save it
        with open(config, 'w') as fp:
            parser.write(fp)
