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

import netaddr

from manila.i18n import _
from manila import utils


LOOPBACK_DEVNAME = 'lo'


class SubProcessBase(object):
    def __init__(self, namespace=None):
        self.namespace = namespace

    def _run(self, options, command, args):
        if self.namespace:
            return self._as_root(options, command, args)
        else:
            return self._execute(options, command, args)

    def _as_root(self, options, command, args, use_root_namespace=False):
        namespace = self.namespace if not use_root_namespace else None

        return self._execute(options, command, args, namespace, as_root=True)

    @classmethod
    def _execute(cls, options, command, args, namespace=None, as_root=False):
        opt_list = ['-%s' % o for o in options]
        if namespace:
            ip_cmd = ['ip', 'netns', 'exec', namespace, 'ip']
        else:
            ip_cmd = ['ip']
        total_cmd = ip_cmd + opt_list + [command] + list(args)
        return utils.execute(*total_cmd, run_as_root=as_root)[0]


class IPWrapper(SubProcessBase):
    def __init__(self, namespace=None):
        super(IPWrapper, self).__init__(namespace=namespace)
        self.netns = IpNetnsCommand(self)

    def device(self, name):
        return IPDevice(name, self.namespace)

    def get_devices(self, exclude_loopback=False):
        retval = []
        output = self._execute('o', 'link', ('list',), self.namespace)
        for line in output.split('\n'):
            if '<' not in line:
                continue
            tokens = line.split(':', 2)
            if len(tokens) >= 3:
                name = tokens[1].split('@', 1)[0].strip()

                if exclude_loopback and name == LOOPBACK_DEVNAME:
                    continue

                retval.append(IPDevice(name, self.namespace))
        return retval

    def add_tuntap(self, name, mode='tap'):
        self._as_root('', 'tuntap', ('add', name, 'mode', mode))
        return IPDevice(name, self.namespace)

    def add_veth(self, name1, name2, namespace2=None):
        args = ['add', name1, 'type', 'veth', 'peer', 'name', name2]

        if namespace2 is None:
            namespace2 = self.namespace
        else:
            self.ensure_namespace(namespace2)
            args += ['netns', namespace2]

        self._as_root('', 'link', tuple(args))

        return (IPDevice(name1, self.namespace), IPDevice(name2, namespace2))

    def ensure_namespace(self, name):
        if not self.netns.exists(name):
            ip = self.netns.add(name)
            lo = ip.device(LOOPBACK_DEVNAME)
            lo.link.set_up()
        else:
            ip = IPWrapper(name)
        return ip

    def namespace_is_empty(self):
        return not self.get_devices(exclude_loopback=True)

    def garbage_collect_namespace(self):
        """Conditionally destroy the namespace if it is empty."""
        if self.namespace and self.netns.exists(self.namespace):
            if self.namespace_is_empty():
                self.netns.delete(self.namespace)
                return True
        return False

    def add_device_to_namespace(self, device):
        if self.namespace:
            device.link.set_netns(self.namespace)

    @classmethod
    def get_namespaces(cls):
        output = cls._execute('', 'netns', ('list',))
        return [ns.strip() for ns in output.split('\n')]


class IPDevice(SubProcessBase):
    def __init__(self, name, namespace=None):
        super(IPDevice, self).__init__(namespace=namespace)
        self.name = name
        self.link = IpLinkCommand(self)
        self.addr = IpAddrCommand(self)
        self.route = IpRouteCommand(self)

    def __eq__(self, other):
        return (other is not None and self.name == other.name
                and self.namespace == other.namespace)

    def __str__(self):
        return self.name


class IpCommandBase(object):
    COMMAND = ''

    def __init__(self, parent):
        self._parent = parent

    def _run(self, *args, **kwargs):
        return self._parent._run(kwargs.get('options', []), self.COMMAND, args)

    def _as_root(self, *args, **kwargs):
        return self._parent._as_root(kwargs.get('options', []),
                                     self.COMMAND,
                                     args,
                                     kwargs.get('use_root_namespace', False))


class IpDeviceCommandBase(IpCommandBase):
    @property
    def name(self):
        return self._parent.name


class IpLinkCommand(IpDeviceCommandBase):
    COMMAND = 'link'

    def set_address(self, mac_address):
        self._as_root('set', self.name, 'address', mac_address)

    def set_mtu(self, mtu_size):
        self._as_root('set', self.name, 'mtu', mtu_size)

    def set_up(self):
        self._as_root('set', self.name, 'up')

    def set_down(self):
        self._as_root('set', self.name, 'down')

    def set_netns(self, namespace):
        self._as_root('set', self.name, 'netns', namespace)
        self._parent.namespace = namespace

    def set_name(self, name):
        self._as_root('set', self.name, 'name', name)
        self._parent.name = name

    def set_alias(self, alias_name):
        self._as_root('set', self.name, 'alias', alias_name)

    def delete(self):
        self._as_root('delete', self.name)

    @property
    def address(self):
        return self.attributes.get('link/ether')

    @property
    def state(self):
        return self.attributes.get('state')

    @property
    def mtu(self):
        return self.attributes.get('mtu')

    @property
    def qdisc(self):
        return self.attributes.get('qdisc')

    @property
    def qlen(self):
        return self.attributes.get('qlen')

    @property
    def alias(self):
        return self.attributes.get('alias')

    @property
    def attributes(self):
        return self._parse_line(self._run('show', self.name, options='o'))

    def _parse_line(self, value):
        if not value:
            return {}

        device_name, settings = value.replace("\\", '').split('>', 1)
        tokens = settings.split()
        keys = tokens[::2]
        values = [int(v) if v.isdigit() else v for v in tokens[1::2]]

        retval = dict(zip(keys, values))
        return retval


class IpAddrCommand(IpDeviceCommandBase):
    COMMAND = 'addr'

    def add(self, ip_version, cidr, broadcast, scope='global'):
        self._as_root('add',
                      cidr,
                      'brd',
                      broadcast,
                      'scope',
                      scope,
                      'dev',
                      self.name,
                      options=[ip_version])

    def delete(self, ip_version, cidr):
        self._as_root('del',
                      cidr,
                      'dev',
                      self.name,
                      options=[ip_version])

    def flush(self):
        self._as_root('flush', self.name)

    def list(self, scope=None, to=None, filters=None):
        if filters is None:
            filters = []

        retval = []

        if scope:
            filters += ['scope', scope]
        if to:
            filters += ['to', to]

        for line in self._run('show', self.name, *filters).split('\n'):
            line = line.strip()
            if not line.startswith('inet'):
                continue
            parts = line.split()
            if parts[0] == 'inet6':
                version = 6
                scope = parts[3]
                broadcast = '::'
            else:
                version = 4
                if parts[2] == 'brd':
                    broadcast = parts[3]
                    scope = parts[5]
                else:
                    # sometimes output of 'ip a' might look like:
                    # inet 192.168.100.100/24 scope global eth0
                    # and broadcast needs to be calculated from CIDR
                    broadcast = str(netaddr.IPNetwork(parts[1]).broadcast)
                    scope = parts[3]

            retval.append(dict(cidr=parts[1],
                               broadcast=broadcast,
                               scope=scope,
                               ip_version=version,
                               dynamic=('dynamic' == parts[-1])))
        return retval


class IpRouteCommand(IpDeviceCommandBase):
    COMMAND = 'route'

    def add_gateway(self, gateway, metric=None):
        args = ['replace', 'default', 'via', gateway]
        if metric:
            args += ['metric', metric]
        args += ['dev', self.name]
        self._as_root(*args)

    def delete_gateway(self, gateway):
        self._as_root('del',
                      'default',
                      'via',
                      gateway,
                      'dev',
                      self.name)

    def get_gateway(self, scope=None, filters=None):
        if filters is None:
            filters = []

        retval = None

        if scope:
            filters += ['scope', scope]

        route_list_lines = self._run('list', 'dev', self.name,
                                     *filters).split('\n')
        default_route_line = next((x.strip() for x in
                                   route_list_lines if
                                   x.strip().startswith('default')), None)
        if default_route_line:
            gateway_index = 2
            parts = default_route_line.split()
            retval = dict(gateway=parts[gateway_index])
            metric_index = 4
            parts_has_metric = (len(parts) > metric_index)
            if parts_has_metric:
                retval.update(metric=int(parts[metric_index]))

        return retval

    def pullup_route(self, interface_name):
        """Pullup route entry.

        Ensures that the route entry for the interface is before all
        others on the same subnet.
        """
        device_list = []
        device_route_list_lines = self._run('list', 'proto', 'kernel',
                                            'dev', interface_name).split('\n')
        for device_route_line in device_route_list_lines:
            try:
                subnet = device_route_line.split()[0]
            except Exception:
                continue
            subnet_route_list_lines = self._run(
                'list', 'proto', 'kernel', 'exact', subnet).split('\n')
            for subnet_route_line in subnet_route_list_lines:
                i = iter(subnet_route_line.split())
                while next(i) != 'dev':
                    pass
                device = next(i)
                try:
                    while next(i) != 'src':
                        pass
                    src = next(i)
                except Exception:
                    src = ''
                if device != interface_name:
                    device_list.append((device, src))
                else:
                    break

            for (device, src) in device_list:
                self._as_root('del', subnet, 'dev', device)
                if (src != ''):
                    self._as_root('append', subnet, 'proto', 'kernel',
                                  'src', src, 'dev', device)
                else:
                    self._as_root('append', subnet, 'proto', 'kernel',
                                  'dev', device)

    def clear_outdated_routes(self, cidr):
        """Removes duplicated routes for a certain network CIDR.

        Removes all routes related to supplied CIDR except for the one
        related to this interface device.

        :param cidr: The network CIDR to be cleared.
        """
        routes = self.list()
        items = [x for x in routes
                 if x['Destination'] == cidr and x.get('Device') and
                 x['Device'] != self.name]
        for item in items:
            self.delete_net_route(item['Destination'], item['Device'])

    def list(self):
        """List all routes

        :return: A dictionary with field 'Destination' and 'Device' for each
        route entry. 'Gateway' field is included if route has a gateway.
        """
        routes = []
        output = self._as_root('list')
        lines = output.split('\n')
        for line in lines:
            items = line.split()
            if len(items) > 0:
                item = {'Destination': items[0]}
                if len(items) > 1:
                    if items[1] == 'via':
                        item['Gateway'] = items[2]
                        if len(items) > 3 and items[3] == 'dev':
                            item['Device'] = items[4]
                    if items[1] == 'dev':
                        item['Device'] = items[2]
                routes.append(item)
        return routes

    def delete_net_route(self, cidr, device):
        """Deletes a route according to supplied CIDR and interface device.

        :param cidr: The network CIDR to be removed.
        :param device: The network interface device to be removed.
        """
        self._as_root('delete', cidr, 'dev', device)


class IpNetnsCommand(IpCommandBase):
    COMMAND = 'netns'

    def add(self, name):
        self._as_root('add', name, use_root_namespace=True)
        return IPWrapper(name)

    def delete(self, name):
        self._as_root('delete', name, use_root_namespace=True)

    def execute(self, cmds, addl_env=None, check_exit_code=True):
        if addl_env is None:
            addl_env = dict()

        if not self._parent.namespace:
            raise Exception(_('No namespace defined for parent'))
        else:
            env_params = []
            if addl_env:
                env_params = (['env'] + ['%s=%s' % pair
                              for pair in sorted(addl_env.items())])
            total_cmd = (['ip', 'netns', 'exec', self._parent.namespace] +
                         env_params + list(cmds))
            return utils.execute(*total_cmd, run_as_root=True,
                                 check_exit_code=check_exit_code)

    def exists(self, name):
        output = self._as_root('list', options='o', use_root_namespace=True)

        for line in output.split('\n'):
            if name == line.strip():
                return True
        return False


def device_exists(device_name, namespace=None):
    try:
        address = IPDevice(device_name, namespace).link.address
    except Exception as e:
        if 'does not exist' in str(e):
            return False
        raise
    return bool(address)


def iproute_arg_supported(command, arg):
    command += ['help']
    stdout, stderr = utils.execute(command, check_exit_code=False,
                                   return_stderr=True)
    return any(arg in line for line in stderr.split('\n'))
