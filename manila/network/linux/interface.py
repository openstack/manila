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

import netaddr
from oslo_config import cfg
from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.network.linux import ip_lib
from manila.network.linux import ovs_lib
from manila import utils


LOG = log.getLogger(__name__)

OPTS = [
    cfg.StrOpt('ovs_integration_bridge',
               default='br-int',
               help=_('Name of Open vSwitch bridge to use.')),
]

CONF = cfg.CONF
CONF.register_opts(OPTS)


def device_name_synchronized(f):
    """Wraps methods with interprocess locks by device names."""

    def wrapped_func(self, *args, **kwargs):
        device_name = "device_name_%s" % args[0]

        @utils.synchronized("linux_interface_%s" % device_name, external=True)
        def source_func(self, *args, **kwargs):
            return f(self, *args, **kwargs)

        return source_func(self, *args, **kwargs)

    return wrapped_func


class LinuxInterfaceDriver(metaclass=abc.ABCMeta):

    # from linux IF_NAMESIZE
    DEV_NAME_LEN = 14
    DEV_NAME_PREFIX = 'tap'

    def __init__(self):
        self.conf = CONF

    @device_name_synchronized
    def init_l3(self, device_name, ip_cidrs, namespace=None, clear_cidrs=[]):
        """Set the L3 settings for the interface using data from the port.

        ip_cidrs: list of 'X.X.X.X/YY' strings
        """
        device = ip_lib.IPDevice(device_name,
                                 namespace=namespace)

        for cidr in clear_cidrs:
            device.route.clear_outdated_routes(cidr)

        previous = {}
        for address in device.addr.list(scope='global', filters=['permanent']):
            previous[address['cidr']] = address['ip_version']

        # add new addresses
        for ip_cidr in ip_cidrs:

            net = netaddr.IPNetwork(ip_cidr)
            if ip_cidr in previous:
                del previous[ip_cidr]
                continue

            device.addr.add(net.version, ip_cidr, str(net.broadcast))

        # clean up any old addresses
        for ip_cidr, ip_version in previous.items():
            device.addr.delete(ip_version, ip_cidr)

        # ensure that interface is first in the list
        device.route.pullup_route(device_name)

        # here we are checking for garbage devices from removed service port
        self._remove_outdated_interfaces(device)

    def _remove_outdated_interfaces(self, device):
        """Finds and removes unused network device."""
        device_cidr_set = self._get_set_of_device_cidrs(device)
        for dev in ip_lib.IPWrapper().get_devices():
            if dev.name != device.name and dev.name[:3] == device.name[:3]:
                cidr_set = self._get_set_of_device_cidrs(dev)
                if device_cidr_set & cidr_set:
                    self.unplug(dev.name)

    def _get_set_of_device_cidrs(self, device):
        cidrs = set()
        addr_list = []
        try:
            # NOTE(ganso): I could call ip_lib.device_exists here, but since
            # this is a concurrency problem, it would not fix the problem.
            addr_list = device.addr.list()
        except Exception as e:
            if 'does not exist' in str(e):
                LOG.warning(
                    "Device %s does not exist anymore.", device.name)
            else:
                raise
        for addr in addr_list:
            if addr['ip_version'] == 4:
                cidrs.add(str(netaddr.IPNetwork(addr['cidr']).cidr))
        return cidrs

    def check_bridge_exists(self, bridge):
        if not ip_lib.device_exists(bridge):
            raise exception.BridgeDoesNotExist(bridge=bridge)

    def get_device_name(self, port):
        return (self.DEV_NAME_PREFIX + port['id'])[:self.DEV_NAME_LEN]

    @abc.abstractmethod
    def plug(self, device_name, port_id, mac_address,
             bridge=None, namespace=None, prefix=None):
        """Plug in the interface."""

    @abc.abstractmethod
    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""


class NoopInterfaceDriver(LinuxInterfaceDriver):
    """Noop driver when manila-share is already connected to admin network"""

    def init_l3(self, device_name, ip_cidrs, namespace=None, clear_cidrs=[]):
        pass

    def plug(self, device_name, port_id, mac_address,
             bridge=None, namespace=None, prefix=None):
        pass

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        pass


class OVSInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating an internal interface on an OVS bridge."""

    DEV_NAME_PREFIX = 'tap'

    def _get_tap_name(self, dev_name):
        return dev_name

    def _ovs_add_port(self, bridge, device_name, port_id, mac_address,
                      internal=True):
        cmd = ['ovs-vsctl', '--', '--may-exist',
               'add-port', bridge, device_name]
        if internal:
            cmd += ['--', 'set', 'Interface', device_name, 'type=internal']
        cmd += ['--', 'set', 'Interface', device_name,
                'external-ids:iface-id=%s' % port_id,
                '--', 'set', 'Interface', device_name,
                'external-ids:iface-status=active',
                '--', 'set', 'Interface', device_name,
                'external-ids:attached-mac=%s' % mac_address]
        utils.execute(*cmd, run_as_root=True)

    @device_name_synchronized
    def plug(self, device_name, port_id, mac_address,
             bridge=None, namespace=None, prefix=None):
        """Plug in the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        self.check_bridge_exists(bridge)
        ip = ip_lib.IPWrapper()
        ns_dev = ip.device(device_name)

        if not ip_lib.device_exists(device_name,
                                    namespace=namespace):
            LOG.info("Device %s does not exist - creating ....", device_name)
            tap_name = self._get_tap_name(device_name)
            self._ovs_add_port(bridge, tap_name, port_id, mac_address)
            ns_dev.link.set_address(mac_address)

            # Add an interface created by ovs to the namespace.
            if namespace:
                namespace_obj = ip.ensure_namespace(namespace)
                namespace_obj.add_device_to_namespace(ns_dev)

        else:
            LOG.info("Device %s already exists.", device_name)
            if ns_dev.link.address != mac_address:
                LOG.warning("Reset mac address to %s", mac_address)
                ns_dev.link.set_address(mac_address)
        ns_dev.link.set_up()

    @device_name_synchronized
    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""
        if not bridge:
            bridge = self.conf.ovs_integration_bridge

        tap_name = self._get_tap_name(device_name)
        self.check_bridge_exists(bridge)
        ovs = ovs_lib.OVSBridge(bridge)

        try:
            ovs.delete_port(tap_name)
        except RuntimeError:
            LOG.error("Failed unplugging interface '%s'",
                      device_name)


class BridgeInterfaceDriver(LinuxInterfaceDriver):
    """Driver for creating bridge interfaces."""

    DEV_NAME_PREFIX = 'ns-'

    @device_name_synchronized
    def plug(self, device_name, port_id, mac_address,
             bridge=None, namespace=None, prefix=None):
        """Plugin the interface."""
        ip = ip_lib.IPWrapper()
        if prefix:
            tap_name = device_name.replace(prefix, 'tap')
        else:
            tap_name = device_name.replace(self.DEV_NAME_PREFIX, 'tap')

        if not ip_lib.device_exists(device_name,
                                    namespace=namespace):
            # Create ns_veth in a namespace if one is configured.
            root_veth, ns_veth = ip.add_veth(tap_name, device_name,
                                             namespace2=namespace)
            ns_veth.link.set_address(mac_address)

        else:
            ns_veth = ip.device(device_name)
            root_veth = ip.device(tap_name)
            LOG.warning("Device %s already exists.", device_name)

        root_veth.link.set_up()
        ns_veth.link.set_up()

    @device_name_synchronized
    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        """Unplug the interface."""
        device = ip_lib.IPDevice(device_name, namespace)
        try:
            device.link.delete()
            LOG.debug("Unplugged interface '%s'", device_name)
        except RuntimeError:
            LOG.error("Failed unplugging interface '%s'",
                      device_name)
