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
import functools
import inspect
import os
import pyclbr
import random
import re
import shutil
import socket
import sys
import tempfile
import time

from eventlet import pools
import netaddr
from oslo_concurrency import lockutils
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log
from oslo_utils import importutils
from oslo_utils import timeutils
import paramiko
import retrying
import six

from manila.common import constants
from manila.db import api as db_api
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
            # ignoring what we set through the sshclient. This doesn't help for
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


def check_ssh_injection(cmd_list):
    ssh_injection_pattern = ['`', '$', '|', '||', ';', '&', '&&', '>', '>>',
                             '<']

    # Check whether injection attacks exist
    for arg in cmd_list:
        arg = arg.strip()

        # Check for matching quotes on the ends
        is_quoted = re.match('^(?P<quote>[\'"])(?P<quoted>.*)(?P=quote)$', arg)
        if is_quoted:
            # Check for unescaped quotes within the quoted argument
            quoted = is_quoted.group('quoted')
            if quoted:
                if (re.match('[\'"]', quoted) or
                        re.search('[^\\\\][\'"]', quoted)):
                    raise exception.SSHInjectionThreat(command=cmd_list)
        else:
            # We only allow spaces within quoted arguments, and that
            # is the only special character allowed within quotes
            if len(arg.split()) > 1:
                raise exception.SSHInjectionThreat(command=cmd_list)

        # Second, check whether danger character in command. So the shell
        # special operator must be a single argument.
        for c in ssh_injection_pattern:
            if c not in arg:
                continue

            result = arg.find(c)
            if not result == -1:
                if result == 0 or not arg[result - 1] == '\\':
                    raise exception.SSHInjectionThreat(command=cmd_list)


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
                # NOTE(vponomaryov): we need to distinguish class methods types
                # for py2 and py3, because the concept of 'unbound methods' has
                # been removed from the python3.x
                if six.PY3:
                    member_type = inspect.isfunction
                else:
                    member_type = inspect.ismethod
                for method, func in inspect.getmembers(clz, member_type):
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
    tdelta = timeutils.utcnow() - last_heartbeat
    elapsed = tdelta.total_seconds()
    return abs(elapsed) <= CONF.service_down_time


def validate_service_host(context, host):
    service = db_api.service_get_by_host_and_topic(context, host,
                                                   'manila-share')
    if not service_is_up(service):
        raise exception.ServiceIsDown(service=service['host'])

    return service


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


class ComparableMixin(object):
    def _compare(self, other, method):
        try:
            return method(self._cmpkey(), other._cmpkey())
        except (AttributeError, TypeError):
            # _cmpkey not implemented, or return different type,
            # so I can't compare with "other".
            return NotImplemented

    def __lt__(self, other):
        return self._compare(other, lambda s, o: s < o)

    def __le__(self, other):
        return self._compare(other, lambda s, o: s <= o)

    def __eq__(self, other):
        return self._compare(other, lambda s, o: s == o)

    def __ge__(self, other):
        return self._compare(other, lambda s, o: s >= o)

    def __gt__(self, other):
        return self._compare(other, lambda s, o: s > o)

    def __ne__(self, other):
        return self._compare(other, lambda s, o: s != o)


def retry(exception, interval=1, retries=10, backoff_rate=2,
          wait_random=False):
    """A wrapper around retrying library.

    This decorator allows to log and to check 'retries' input param.
    Time interval between retries is calculated in the following way:
    interval * backoff_rate ^ previous_attempt_number

    :param exception: expected exception type. When wrapped function
                      raises an exception of this type, the function
                      execution is retried.
    :param interval: param 'interval' is used to calculate time interval
                     between retries:
                     interval * backoff_rate ^ previous_attempt_number
    :param retries: number of retries.
    :param backoff_rate: param 'backoff_rate' is used to calculate time
                         interval between retries:
                         interval * backoff_rate ^ previous_attempt_number
    :param wait_random: boolean value to enable retry with random wait timer.

    """
    def _retry_on_exception(e):
        return isinstance(e, exception)

    def _backoff_sleep(previous_attempt_number, delay_since_first_attempt_ms):
        exp = backoff_rate ** previous_attempt_number
        wait_for = max(0, interval * exp)

        if wait_random:
            wait_val = random.randrange(interval * 1000.0, wait_for * 1000.0)
        else:
            wait_val = wait_for * 1000.0

        LOG.debug("Sleeping for %s seconds.", (wait_val / 1000.0))
        return wait_val

    def _print_stop(previous_attempt_number, delay_since_first_attempt_ms):
        delay_since_first_attempt = delay_since_first_attempt_ms / 1000.0
        LOG.debug("Failed attempt %s", previous_attempt_number)
        LOG.debug("Have been at this for %s seconds",
                  delay_since_first_attempt)
        return previous_attempt_number == retries

    if retries < 1:
        raise ValueError(_('Retries must be greater than or '
                           'equal to 1 (received: %s).') % retries)

    def _decorator(f):

        @six.wraps(f)
        def _wrapper(*args, **kwargs):
            r = retrying.Retrying(retry_on_exception=_retry_on_exception,
                                  wait_func=_backoff_sleep,
                                  stop_func=_print_stop)
            return r.call(f, *args, **kwargs)

        return _wrapper

    return _decorator


def require_driver_initialized(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        # we can't do anything if the driver didn't init
        if not self.driver.initialized:
            driver_name = self.driver.__class__.__name__
            raise exception.DriverNotInitialized(driver=driver_name)
        return func(self, *args, **kwargs)
    return wrapper


def translate_string_size_to_float(string, multiplier='G'):
    """Translates human-readable storage size to float value.

    Supported values for 'multiplier' are following:
        K - kilo | 1
        M - mega | 1024
        G - giga | 1024 * 1024
        T - tera | 1024 * 1024 * 1024
        P = peta | 1024 * 1024 * 1024 * 1024

    returns:
        - float if correct input data provided
        - None if incorrect
    """
    if not isinstance(string, six.string_types):
        return None
    multipliers = ('K', 'M', 'G', 'T', 'P')
    mapping = {
        k: 1024.0 ** v
        for k, v in zip(multipliers, range(len(multipliers)))
    }
    if multiplier not in multipliers:
        raise exception.ManilaException(
            "'multiplier' arg should be one of following: "
            "'%(multipliers)s'. But it is '%(multiplier)s'." % {
                'multiplier': multiplier,
                'multipliers': "', '".join(multipliers),
            }
        )
    try:
        value = float(string) / 1024.0
        value = value / mapping[multiplier]
        return value
    except (ValueError, TypeError):
        matched = re.match(
            r"^(\d+\.*\d*)([%s])$" % ','.join(multipliers), string)
        if matched:
            value = float(matched.groups()[0])
            multiplier = mapping[matched.groups()[1]] / mapping[multiplier]
            return value * multiplier


def wait_for_access_update(context, db, share_instance,
                           migration_wait_access_rules_timeout):
    starttime = time.time()
    deadline = starttime + migration_wait_access_rules_timeout
    tries = 0

    while True:
        instance = db.share_instance_get(context, share_instance['id'])

        if instance['access_rules_status'] == constants.STATUS_ACTIVE:
            break

        tries += 1
        now = time.time()
        if instance['access_rules_status'] == constants.STATUS_ERROR:
            msg = _("Failed to update access rules"
                    " on share instance %s") % share_instance['id']
            raise exception.ShareMigrationFailed(reason=msg)
        elif now > deadline:
            msg = _("Timeout trying to update access rules"
                    " on share instance %(share_id)s. Timeout "
                    "was %(timeout)s seconds.") % {
                'share_id': share_instance['id'],
                'timeout': migration_wait_access_rules_timeout}
            raise exception.ShareMigrationFailed(reason=msg)
        else:
            time.sleep(tries ** 2)
