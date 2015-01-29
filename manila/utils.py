# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Justin Santa Barbara
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

"""Utilities and helper functions."""

import contextlib
import errno
import inspect
import os
import pyclbr
import shutil
import socket
import sys
import tempfile
from xml.dom import minidom
from xml.parsers import expat
from xml import sax
from xml.sax import expatreader

from eventlet import pools
import netaddr
from oslo_concurrency import lockutils
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from oslo_utils import timeutils
import paramiko
import six

from manila import exception
from manila.i18n import _

CONF = cfg.CONF
LOG = log.getLogger(__name__)

synchronized = lockutils.synchronized_with_prefix('manila-')


def _get_root_helper():
    return 'sudo manila-rootwrap %s' % CONF.rootwrap_config


def execute(*cmd, **kwargs):
    """Convenience wrapper around oslo's execute() function."""
    if 'run_as_root' in kwargs and 'root_helper' not in kwargs:
        kwargs['root_helper'] = _get_root_helper()
    return processutils.execute(*cmd, **kwargs)


def trycmd(*args, **kwargs):
    """Convenience wrapper around oslo's trycmd() function."""
    if 'run_as_root' in kwargs and 'root_helper' not in kwargs:
        kwargs['root_helper'] = _get_root_helper()
    return processutils.trycmd(*args, **kwargs)


class SSHPool(pools.Pool):
    """A simple eventlet pool to hold ssh connections."""

    def __init__(self, ip, port, conn_timeout, login, password=None,
                 privatekey=None, *args, **kwargs):
        self.ip = ip
        self.port = port
        self.login = login
        self.password = password
        self.conn_timeout = conn_timeout if conn_timeout else None
        self.path_to_private_key = privatekey
        super(SSHPool, self).__init__(*args, **kwargs)

    def create(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        look_for_keys = True
        if self.path_to_private_key:
            self.path_to_private_key = os.path.expanduser(
                self.path_to_private_key)
            look_for_keys = False
        elif self.password:
            look_for_keys = False
        try:
            ssh.connect(self.ip,
                        port=self.port,
                        username=self.login,
                        password=self.password,
                        key_filename=self.path_to_private_key,
                        look_for_keys=look_for_keys,
                        timeout=self.conn_timeout)
            # Paramiko by default sets the socket timeout to 0.1 seconds,
            # ignoring what we set thru the sshclient. This doesn't help for
            # keeping long lived connections. Hence we have to bypass it, by
            # overriding it after the transport is initialized. We are setting
            # the sockettimeout to None and setting a keepalive packet so that,
            # the server will keep the connection open. All that does is send
            # a keepalive packet every ssh_conn_timeout seconds.
            if self.conn_timeout:
                transport = ssh.get_transport()
                transport.sock.settimeout(None)
                transport.set_keepalive(self.conn_timeout)
            return ssh
        except Exception as e:
            msg = _("Check whether private key or password are correctly "
                    "set. Error connecting via ssh: %s") % e
            LOG.error(msg)
            raise exception.SSHException(msg)

    def get(self):
        """Return an item from the pool, when one is available.

        This may cause the calling greenthread to block. Check if a
        connection is active before returning it. For dead connections
        create and return a new connection.
        """
        if self.free_items:
            conn = self.free_items.popleft()
            if conn:
                if conn.get_transport().is_active():
                    return conn
                else:
                    conn.close()
            return self.create()
        if self.current_size < self.max_size:
            created = self.create()
            self.current_size += 1
            return created
        return self.channel.get()

    def remove(self, ssh):
        """Close an ssh client and remove it from free_items."""
        ssh.close()
        ssh = None
        if ssh in self.free_items:
            self.free_items.pop(ssh)
        if self.current_size > 0:
            self.current_size -= 1


def maniladir():
    import manila
    return os.path.abspath(manila.__file__).split('manila/__init__.py')[0]


def debug(arg):
    LOG.debug('debug in callback: %s', arg)
    return arg


class LazyPluggable(object):
    """A pluggable backend loaded lazily based on some value."""

    def __init__(self, pivot, **backends):
        self.__backends = backends
        self.__pivot = pivot
        self.__backend = None

    def __get_backend(self):
        if not self.__backend:
            backend_name = CONF[self.__pivot]
            if backend_name not in self.__backends:
                raise exception.Error(_('Invalid backend: %s') % backend_name)

            backend = self.__backends[backend_name]
            if isinstance(backend, tuple):
                name = backend[0]
                fromlist = backend[1]
            else:
                name = backend
                fromlist = backend

            self.__backend = __import__(name, None, None, fromlist)
            LOG.debug('backend %s', self.__backend)
        return self.__backend

    def __getattr__(self, key):
        backend = self.__get_backend()
        return getattr(backend, key)


class ProtectedExpatParser(expatreader.ExpatParser):
    """An expat parser which disables DTD's and entities by default."""

    def __init__(self, forbid_dtd=True, forbid_entities=True,
                 *args, **kwargs):
        # Python 2.x old style class
        expatreader.ExpatParser.__init__(self, *args, **kwargs)
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities

    def start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        raise ValueError("Inline DTD forbidden")

    def entity_decl(self, entityName, is_parameter_entity, value, base,
                    systemId, publicId, notationName):
        raise ValueError("<!ENTITY> forbidden")

    def unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        # expat 1.2
        raise ValueError("<!ENTITY> forbidden")

    def reset(self):
        expatreader.ExpatParser.reset(self)
        if self.forbid_dtd:
            self._parser.StartDoctypeDeclHandler = self.start_doctype_decl
        if self.forbid_entities:
            self._parser.EntityDeclHandler = self.entity_decl
            self._parser.UnparsedEntityDeclHandler = self.unparsed_entity_decl


def safe_minidom_parse_string(xml_string):
    """Parse an XML string using minidom safely.

    """
    try:
        return minidom.parseString(xml_string, parser=ProtectedExpatParser())
    except sax.SAXParseException:
        raise expat.ExpatError()


def delete_if_exists(pathname):
    """Delete a file, but ignore file not found error."""

    try:
        os.unlink(pathname)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return
        else:
            raise


def get_from_path(items, path):
    """Returns a list of items matching the specified path.

    Takes an XPath-like expression e.g. prop1/prop2/prop3, and for each item
    in items, looks up items[prop1][prop2][prop3].  Like XPath, if any of the
    intermediate results are lists it will treat each list item individually.
    A 'None' in items or any child expressions will be ignored, this function
    will not throw because of None (anywhere) in items.  The returned list
    will contain no None values.

    """
    if path is None:
        raise exception.Error('Invalid mini_xpath')

    (first_token, sep, remainder) = path.partition('/')

    if first_token == '':
        raise exception.Error('Invalid mini_xpath')

    results = []

    if items is None:
        return results

    if not isinstance(items, list):
        # Wrap single objects in a list
        items = [items]

    for item in items:
        if item is None:
            continue
        get_method = getattr(item, 'get', None)
        if get_method is None:
            continue
        child = get_method(first_token)
        if child is None:
            continue
        if isinstance(child, list):
            # Flatten intermediate lists
            for x in child:
                results.append(x)
        else:
            results.append(child)

    if not sep:
        # No more tokens
        return results
    else:
        return get_from_path(results, remainder)


def is_ipv6_configured():
    """Check if system contain IPv6 capable network interface.

    :rtype: bool
    :raises: IOError
    """
    try:
        fd = open('/proc/net/if_inet6')
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
        result = False
    else:
        result = bool(fd.read(32))
        fd.close()
    return result


def is_eventlet_bug105():
    """Check if eventlet support IPv6 addresses.

    See https://bitbucket.org/eventlet/eventlet/issue/105

    :rtype: bool
    """
    try:
        mod = sys.modules['eventlet.support.greendns']
    except KeyError:
        return False

    try:
        connect_data = mod.getaddrinfo('::1', 80)
    except socket.gaierror:
        return True

    fail = [x for x in connect_data if x[0] != socket.AF_INET6]
    return bool(fail)


def monkey_patch():
    """Patch decorator.

    If the Flags.monkey_patch set as True,
    this function patches a decorator
    for all functions in specified modules.
    You can set decorators for each modules
    using CONF.monkey_patch_modules.
    The format is "Module path:Decorator function".
    Example: 'manila.api.ec2.cloud:' \
     manila.openstack.common.notifier.api.notify_decorator'

    Parameters of the decorator is as follows.
    (See manila.openstack.common.notifier.api.notify_decorator)

    name - name of the function
    function - object of the function
    """
    # If CONF.monkey_patch is not True, this function do nothing.
    if not CONF.monkey_patch:
        return
    # Get list of modules and decorators
    for module_and_decorator in CONF.monkey_patch_modules:
        module, decorator_name = module_and_decorator.split(':')
        # import decorator function
        decorator = importutils.import_class(decorator_name)
        __import__(module)
        # Retrieve module information using pyclbr
        module_data = pyclbr.readmodule_ex(module)
        for key in module_data.keys():
            # set the decorator for the class methods
            if isinstance(module_data[key], pyclbr.Class):
                clz = importutils.import_class("%s.%s" % (module, key))
                for method, func in inspect.getmembers(clz, inspect.ismethod):
                    setattr(
                        clz, method,
                        decorator("%s.%s.%s" % (module, key, method), func))
            # set the decorator for the function
            if isinstance(module_data[key], pyclbr.Function):
                func = importutils.import_class("%s.%s" % (module, key))
                setattr(sys.modules[module], key,
                        decorator("%s.%s" % (module, key), func))


def read_cached_file(filename, cache_info, reload_func=None):
    """Read from a file if it has been modified.

    :param cache_info: dictionary to hold opaque cache.
    :param reload_func: optional function to be called with data when
                        file is reloaded due to a modification.

    :returns: data from file

    """
    mtime = os.path.getmtime(filename)
    if not cache_info or mtime != cache_info.get('mtime'):
        with open(filename) as fap:
            cache_info['data'] = fap.read()
        cache_info['mtime'] = mtime
        if reload_func:
            reload_func(cache_info['data'])
    return cache_info['data']


def file_open(*args, **kwargs):
    """Open file

    see built-in file() documentation for more details

    Note: The reason this is kept in a separate module is to easily
          be able to provide a stub module that doesn't alter system
          state at all (for unit tests)
    """
    return file(*args, **kwargs)


def service_is_up(service):
    """Check whether a service is up based on last heartbeat."""
    last_heartbeat = service['updated_at'] or service['created_at']
    # Timestamps in DB are UTC.
    elapsed = timeutils.total_seconds(timeutils.utcnow() - last_heartbeat)
    return abs(elapsed) <= CONF.service_down_time


def read_file_as_root(file_path):
    """Secure helper to read file as root."""
    try:
        out, _err = execute('cat', file_path, run_as_root=True)
        return out
    except exception.ProcessExecutionError:
        raise exception.FileNotFound(file_path=file_path)


@contextlib.contextmanager
def temporary_chown(path, owner_uid=None):
    """Temporarily chown a path.

    :params owner_uid: UID of temporary owner (defaults to current user)
    """
    if owner_uid is None:
        owner_uid = os.getuid()

    orig_uid = os.stat(path).st_uid

    if orig_uid != owner_uid:
        execute('chown', owner_uid, path, run_as_root=True)
    try:
        yield
    finally:
        if orig_uid != owner_uid:
            execute('chown', orig_uid, path, run_as_root=True)


@contextlib.contextmanager
def tempdir(**kwargs):
    tmpdir = tempfile.mkdtemp(**kwargs)
    try:
        yield tmpdir
    finally:
        try:
            shutil.rmtree(tmpdir)
        except OSError as e:
            LOG.debug('Could not remove tmpdir: %s', six.text_type(e))


def walk_class_hierarchy(clazz, encountered=None):
    """Walk class hierarchy, yielding most derived classes first."""
    if not encountered:
        encountered = []
    for subclass in clazz.__subclasses__():
        if subclass not in encountered:
            encountered.append(subclass)
            # drill down to leaves first
            for subsubclass in walk_class_hierarchy(subclass, encountered):
                yield subsubclass
            yield subclass


def ensure_tree(path):
    """Create a directory (and any ancestor directories required)

    :param path: Directory to create
    """
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            if not os.path.isdir(path):
                raise
        else:
            raise


def cidr_to_netmask(cidr):
    """Convert cidr to netmask."""
    try:
        network = netaddr.IPNetwork(cidr)
        return str(network.netmask)
    except netaddr.AddrFormatError:
        raise exception.InvalidInput(_("Invalid cidr supplied %s") % cidr)


def is_valid_ip_address(ip_address, ip_version):
    if int(ip_version) == 4:
        return netaddr.valid_ipv4(ip_address)
    elif int(ip_version) == 6:
        return netaddr.valid_ipv6(ip_address)
    else:
        raise exception.ManilaException(
            _("Provided improper IP version '%s'.") % ip_version)


class IsAMatcher(object):
    def __init__(self, expected_value=None):
        self.expected_value = expected_value

    def __eq__(self, actual_value):
        return isinstance(actual_value, self.expected_value)
