# Copyright 2018 Inspur Corp.
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
Share driver for Inspur AS13000
"""

import eventlet
import functools
import json
import re
import requests
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share import utils as share_utils


inspur_as13000_opts = [
    cfg.HostAddressOpt(
        'as13000_nas_ip',
        required=True,
        help='IP address for the AS13000 storage.'),
    cfg.PortOpt(
        'as13000_nas_port',
        default=8088,
        help='Port number for the AS13000 storage.'),
    cfg.StrOpt(
        'as13000_nas_login',
        required=True,
        help='Username for the AS13000 storage'),
    cfg.StrOpt(
        'as13000_nas_password',
        required=True,
        secret=True,
        help='Password for the AS13000 storage'),
    cfg.ListOpt(
        'as13000_share_pools',
        required=True,
        help='The Storage Pools Manila should use, a comma separated list'),
    cfg.IntOpt(
        'as13000_token_available_time',
        default=3600,
        help='The effective time of token validity in seconds.')
]

CONF = cfg.CONF
CONF.register_opts(inspur_as13000_opts)
LOG = logging.getLogger(__name__)


def inspur_driver_debug_trace(f):
    """Log the method entrance and exit including active backend name.

    This should only be used on Share_Driver class methods. It depends on
    having a 'self' argument that is a AS13000_Driver.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        driver = args[0]
        cls_name = driver.__class__.__name__
        method_name = "%(cls_name)s.%(method)s" % {"cls_name": cls_name,
                                                   "method": f.__name__}
        backend_name = driver.configuration.share_backend_name
        LOG.debug("[%(backend_name)s] Enter %(method_name)s",
                  {"method_name": method_name, "backend_name": backend_name})
        result = f(*args, **kwargs)
        LOG.debug("[%(backend_name)s] Leave %(method_name)s",
                  {"method_name": method_name, "backend_name": backend_name})
        return result

    return wrapper


class RestAPIExecutor(object):
    def __init__(self, hostname, port, username, password):
        self._hostname = hostname
        self._port = port
        self._username = username
        self._password = password
        self._token_pool = []
        self._token_size = 1

    def logins(self):
        """login the AS13000 and store the token in token_pool"""
        times = self._token_size
        while times > 0:
            token = self.login()
            self._token_pool.append(token)
            times = times - 1
        LOG.debug('Logged into the AS13000.')

    def login(self):
        """login in the AS13000 and return the token"""
        method = 'security/token'
        params = {'name': self._username, 'password': self._password}
        token = self.send_rest_api(method=method, params=params,
                                   request_type='post').get('token')
        return token

    def logout(self):
        method = 'security/token'
        self.send_rest_api(method=method, request_type='delete')

    def refresh_token(self, force=False):
        if force is True:
            for i in range(self._token_size):
                self._token_pool = []
                token = self.login()
                self._token_pool.append(token)
        else:
            for i in range(self._token_size):
                self.logout()
                token = self.login()
                self._token_pool.append(token)
        LOG.debug('Tokens have been refreshed.')

    def send_rest_api(self, method, params=None, request_type='post'):
        attempts = 3
        msge = ''
        while attempts > 0:
            attempts -= 1
            try:
                return self.send_api(method, params, request_type)
            except exception.NetworkException as e:
                msge = str(e)
                LOG.error(msge)

                self.refresh_token(force=True)
                eventlet.sleep(1)
            except exception.ShareBackendException as e:
                msge = str(e)
                break

        msg = (_('Access RestAPI /rest/%(method)s by %(type)s failed,'
                 ' error: %(msge)s') % {'method': method,
                                        'msge': msge,
                                        'type': request_type})
        LOG.error(msg)
        raise exception.ShareBackendException(msg)

    @staticmethod
    def do_request(cmd, url, header, data):
        LOG.debug('CMD: %(cmd)s, URL: %(url)s, DATA: %(data)s',
                  {'cmd': cmd, 'url': url, 'data': data})
        if cmd == 'post':
            req = requests.post(url,
                                data=data,
                                headers=header)
        elif cmd == 'get':
            req = requests.get(url,
                               data=data,
                               headers=header)
        elif cmd == 'put':
            req = requests.put(url,
                               data=data,
                               headers=header)
        elif cmd == 'delete':
            req = requests.delete(url,
                                  data=data,
                                  headers=header)
        else:
            msg = (_('Unsupported cmd: %s') % cmd)
            raise exception.ShareBackendException(msg)

        response = req.json()
        code = req.status_code
        LOG.debug('CODE: %(code)s, RESPONSE: %(response)s',
                  {'code': code, 'response': response})

        if code != 200:
            msg = (_('Code: %(code)s, URL: %(url)s, Message: %(msg)s')
                   % {'code': req.status_code,
                      'url': req.url,
                      'msg': req.text})
            LOG.error(msg)
            raise exception.NetworkException(msg)

        return response

    def send_api(self, method, params=None, request_type='post'):
        if params:
            params = json.dumps(params)

        url = ('http://%(hostname)s:%(port)s/%(rest)s/%(method)s'
               % {'hostname': self._hostname,
                  'port': self._port,
                  'rest': 'rest',
                  'method': method})

        # header is not needed when the driver login the backend
        if method == 'security/token':
            # token won't be return to the token_pool
            if request_type == 'delete':
                header = {'X-Auth-Token': self._token_pool.pop(0)}
            else:
                header = None
        else:
            if len(self._token_pool) == 0:
                self.logins()
            token = self._token_pool.pop(0)
            header = {'X-Auth-Token': token}
            self._token_pool.append(token)

        response = self.do_request(request_type, url, header, params)

        try:
            code = response.get('code')
            if code == 0:
                if request_type == 'get':
                    data = response.get('data')
                else:
                    if method == 'security/token':
                        data = response.get('data')
                    else:
                        data = response.get('message')
                        data = str(data).lower()
                        if hasattr(data, 'success'):
                            return
            elif code == 301:
                msg = _('Token is expired')
                LOG.error(msg)
                raise exception.NetworkException(msg)
            else:
                message = response.get('message')
                msg = (_('Unexpected RestAPI response: %(code)d %(msg)s') % {
                       'code': code, 'msg': message})
                LOG.error(msg)
                raise exception.ShareBackendException(msg)
        except ValueError:
            msg = _("Deal with response failed")
            raise exception.ShareBackendException(msg)

        return data


class AS13000ShareDriver(driver.ShareDriver):

    """AS13000 Share Driver

    Version history:
    V1.0.0:    Initial version
               Driver support:
                   share create/delete,
                   snapshot create/delete,
                   extend size,
                   create_share_from_snapshot,
                   update_access.
                   protocol: NFS/CIFS

    """

    VENDOR = 'INSPUR'
    VERSION = '1.0.0'
    PROTOCOL = 'NFS_CIFS'

    def __init__(self, *args, **kwargs):
        super(AS13000ShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(inspur_as13000_opts)
        self.hostname = self.configuration.as13000_nas_ip
        self.port = self.configuration.as13000_nas_port
        self.username = self.configuration.as13000_nas_login
        self.password = self.configuration.as13000_nas_password
        self.token_available_time = (self.configuration.
                                     as13000_token_available_time)
        self.pools = self.configuration.as13000_share_pools
        # base dir detail contain the information which we will use
        # when we create subdirectorys
        self.base_dir_detail = None
        self._token_time = 0
        self.ips = []
        self._rest = RestAPIExecutor(self.hostname, self.port,
                                     self.username, self.password)

    @inspur_driver_debug_trace
    def do_setup(self, context):
        # get access tokens
        self._rest.logins()
        self._token_time = time.time()

        # Check the pool in conf exist in the backend
        self._validate_pools_exist()

        # get the base directory detail
        self.base_dir_detail = self._get_directory_detail(self.pools[0])

        # get all backend node ip
        self.ips = self._get_nodes_ips()

    @inspur_driver_debug_trace
    def check_for_setup_error(self):
        if self.base_dir_detail is None:
            msg = _('The pool status is not right')
            raise exception.ShareBackendException(msg)

        if len(self.ips) == 0:
            msg = _('All backend nodes are down')
            raise exception.ShareBackendException(msg)

    @inspur_driver_debug_trace
    def create_share(self, context, share, share_server=None):
        """Create a share."""
        pool, name, size, proto = self._get_share_instance_pnsp(share)

        # create directory first
        share_path = self._create_directory(share_name=name,
                                            pool_name=pool)

        # then create nfs or cifs share
        if proto == 'nfs':
            self._create_nfs_share(share_path=share_path)
        else:
            self._create_cifs_share(share_name=name,
                                    share_path=share_path)

        # finally we set the quota of directory
        self._set_directory_quota(share_path, size)

        locations = self._get_location_path(name, share_path, proto)
        LOG.debug('Create share: name:%(name)s'
                  ' protocol:%(proto)s,location: %(loc)s',
                  {'name': name, 'proto': proto, 'loc': locations})
        return locations

    @inspur_driver_debug_trace
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Create a share from snapshot."""
        pool, name, size, proto = self._get_share_instance_pnsp(share)

        # create directory first
        share_path = self._create_directory(share_name=name,
                                            pool_name=pool)

        # as quota must be set when directory is empty
        # then we set the quota of directory
        self._set_directory_quota(share_path, size)

        # and next clone snapshot to dest_path
        self._clone_directory_to_dest(snapshot=snapshot, dest_path=share_path)

        # finally create share
        if proto == 'nfs':
            self._create_nfs_share(share_path=share_path)
        else:
            self._create_cifs_share(share_name=name,
                                    share_path=share_path)

        locations = self._get_location_path(name, share_path, proto)
        LOG.debug('Create share from snapshot:'
                  ' name:%(name)s protocol:%(proto)s,location: %(loc)s',
                  {'name': name, 'proto': proto, 'loc': locations})
        return locations

    @inspur_driver_debug_trace
    def delete_share(self, context, share, share_server=None):
        """Delete share."""
        pool, name, _, proto = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, name)
        if proto == 'nfs':
            share_backend = self._get_nfs_share(share_path)
            if len(share_backend) == 0:
                return
            else:
                self._delete_nfs_share(share_path)
        else:
            share_backend = self._get_cifs_share(name)
            if len(share_backend) == 0:
                return
            else:
                self._delete_cifs_share(name)
        self._delete_directory(share_path)
        LOG.debug('Delete share: %s', name)

    @inspur_driver_debug_trace
    def extend_share(self, share, new_size, share_server=None):
        """extend share to new size"""
        pool, name, size, proto = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, name)
        self._set_directory_quota(share_path, new_size)
        LOG.debug('extend share %(name)s to new size %(size)s GB',
                  {'name': name, 'size': new_size})

    @inspur_driver_debug_trace
    def ensure_share(self, context, share, share_server=None):
        """Ensure that share is exported."""
        pool, name, size, proto = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, name)

        if proto == 'nfs':
            share_backend = self._get_nfs_share(share_path)
        elif proto == 'cifs':
            share_backend = self._get_cifs_share(name)
        else:
            msg = (_('Invalid NAS protocol supplied: %s.') % proto)
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if len(share_backend) == 0:
            raise exception.ShareResourceNotFound(share_id=share['share_id'])

        return self._get_location_path(name, share_path, proto)

    @inspur_driver_debug_trace
    def create_snapshot(self, context, snapshot, share_server=None):
        """create snapshot of share"""
        # !!! Attention the share property is a ShareInstance
        share = snapshot['share']
        pool, share_name, _, _ = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, share_name)

        snap_name = self._generate_snapshot_name(snapshot)

        method = 'snapshot/directory'
        request_type = 'post'
        params = {'path': share_path, 'snapName': snap_name}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('Create snapshot %(snap)s for share %(share)s',
                  {'snap': snap_name, 'share': share_name})

    @inspur_driver_debug_trace
    def delete_snapshot(self, context, snapshot, share_server=None):
        """delete snapshot of share"""
        # !!! Attention the share property is a ShareInstance
        share = snapshot['share']
        pool, share_name, _, _ = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, share_name)

        # if there are no snapshot exist, driver will return directly
        snaps_backend = self._get_snapshots_from_share(share_path)
        if len(snaps_backend) == 0:
            return

        snap_name = self._generate_snapshot_name(snapshot)

        method = ('snapshot/directory?path=%s&snapName=%s'
                  % (share_path, snap_name))
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)
        LOG.debug('Delete snapshot %(snap)s of share %(share)s',
                  {'snap': snap_name, 'share': share_name})

    @staticmethod
    def transfer_rule_to_client(proto, rule):
        """transfer manila access rule to backend client"""
        access_level = rule['access_level']
        if proto == 'cifs' and access_level == 'rw':
            access_level = 'rwx'
        return dict(name=rule['access_to'],
                    type=(0 if proto == 'nfs' else 1),
                    authority=access_level)

    @inspur_driver_debug_trace
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """update access of share"""
        pool, share_name, _, proto = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, share_name)

        method = 'file/share/%s' % proto
        request_type = 'put'
        params = {
            'path': share_path,
            'addedClientList': [],
            'deletedClientList': [],
            'editedClientList': []
        }

        if proto == 'nfs':
            share_backend = self._get_nfs_share(share_path)
            params['pathAuthority'] = share_backend['pathAuthority']
        else:
            params['name'] = share_name

        if add_rules or delete_rules:
            to_add_clients = [self.transfer_rule_to_client(proto, rule)
                              for rule in add_rules]
            params['addedClientList'] = to_add_clients
            to_del_clients = [self.transfer_rule_to_client(proto, rule)
                              for rule in delete_rules]
            params['deletedClientList'] = to_del_clients
        else:
            access_clients = [self.transfer_rule_to_client(proto, rule)
                              for rule in access_rules]
            params['addedClientList'] = access_clients
            self._clear_access(share)

        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('complete the update access work for share %s', share_name)

    @inspur_driver_debug_trace
    def _update_share_stats(self, data=None):
        """update the backend stats including driver info and pools info"""
        # Do a check of the token validity each time we update share stats,
        # do a refresh if token already expires
        time_difference = time.time() - self._token_time
        if time_difference > self.token_available_time:
            self._rest.refresh_token()
            self._token_time = time.time()
            LOG.debug('Token of Driver has been refreshed')

        data = {
            'vendor_name': self.VENDOR,
            'driver_version': self.VERSION,
            'storage_protocol': self.PROTOCOL,
            'share_backend_name':
                self.configuration.safe_get('share_backend_name'),
            'snapshot_support': True,
            'create_share_from_snapshot_support': True,
            'pools': [self._get_pool_stats(pool) for pool in self.pools]
        }

        super(AS13000ShareDriver, self)._update_share_stats(data)

    @inspur_driver_debug_trace
    def _clear_access(self, share):
        """clear all access of share"""
        pool, share_name, size, proto = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, share_name)

        method = 'file/share/%s' % proto
        request_type = 'put'
        params = {
            'path': share_path,
            'addedClientList': [],
            'deletedClientList': [],
            'editedClientList': []
        }

        if proto == 'nfs':
            share_backend = self._get_nfs_share(share_path)
            params['deletedClientList'] = share_backend['clientList']
            params['pathAuthority'] = share_backend['pathAuthority']
        else:
            share_backend = self._get_cifs_share(share_name)
            params['deletedClientList'] = share_backend['userList']
            params['name'] = share_name

        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('Clear all the access of share %s', share_name)

    @inspur_driver_debug_trace
    def _validate_pools_exist(self):
        """Check the pool in conf exist in the backend"""
        available_pools = self._get_directory_list('/')
        for pool in self.pools:
            if pool not in available_pools:
                msg = (_('Pool %s is not exist in backend storage.') % pool)
                LOG.error(msg)
                raise exception.InvalidInput(reason=msg)

    @inspur_driver_debug_trace
    def _get_directory_quota(self, path):
        """get the quota of directory"""
        method = 'file/quota/directory?path=/%s' % path
        request_type = 'get'
        data = self._rest.send_rest_api(method=method,
                                        request_type=request_type)
        quota = data.get('hardthreshold')
        if quota is None:
            # the method of '_update_share_stats' will check quota of pools.
            # To avoid return NONE for pool info, so raise this exception
            msg = (_(r'Quota of pool: /%s is not set, '
                     r'please set it in GUI of AS13000') % path)
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        hardunit = data.get('hardunit')
        used_capacity = data.get('capacity')
        used_capacity = (str(used_capacity)).upper()
        used_capacity = self._unit_convert(used_capacity)

        if hardunit == 1:
            quota = quota * 1024
        total_capacity = int(quota)
        used_capacity = int(used_capacity)
        return total_capacity, used_capacity

    def _get_pool_stats(self, path):
        """Get the stats of pools, such as capacity and other information."""

        total_capacity, used_capacity = self._get_directory_quota(path)
        free_capacity = total_capacity - used_capacity

        pool = {
            'pool_name': path,
            'reserved_percentage':
                self.configuration.reserved_share_percentage,
            'reserved_snapshot_percentage':
                self.configuration.reserved_share_from_snapshot_percentage
                or self.configuration.reserved_share_percentage,
            'reserved_share_extend_percentage':
                self.configuration.reserved_share_extend_percentage
                or self.configuration.reserved_share_percentage,
            'max_over_subscription_ratio':
                self.configuration.max_over_subscription_ratio,
            'dedupe': False,
            'compression': False,
            'qos': False,
            'thin_provisioning': True,
            'total_capacity_gb': total_capacity,
            'free_capacity_gb': free_capacity,
            'allocated_capacity_gb': used_capacity,
            'snapshot_support': True,
            'create_share_from_snapshot_support': True
        }

        return pool

    @inspur_driver_debug_trace
    def _get_directory_list(self, path):
        """Get all the directory list of target path"""
        method = 'file/directory?path=%s' % path
        request_type = 'get'
        directory_list = self._rest.send_rest_api(method=method,
                                                  request_type=request_type)
        dir_list = []
        for directory in directory_list:
            dir_list.append(directory['name'])
        return dir_list

    @inspur_driver_debug_trace
    def _create_directory(self, share_name, pool_name):
        """create a directory for share"""

        method = 'file/directory'
        request_type = 'post'
        params = {'name': share_name,
                  'parentPath': self.base_dir_detail['path'],
                  'authorityInfo': self.base_dir_detail['authorityInfo'],
                  'dataProtection': self.base_dir_detail['dataProtection'],
                  'poolName': self.base_dir_detail['poolName']}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)

        return self._generate_share_path(pool_name, share_name)

    @inspur_driver_debug_trace
    def _delete_directory(self, share_path):
        """delete the directory when delete share"""
        method = 'file/directory?path=%s' % share_path
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)

    @inspur_driver_debug_trace
    def _set_directory_quota(self, share_path, quota):
        """set directory quota for share"""
        method = 'file/quota/directory'
        request_type = 'put'
        params = {'path': share_path, 'hardthreshold': quota, 'hardunit': 2}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)

    @inspur_driver_debug_trace
    def _create_nfs_share(self, share_path):
        """create a NFS share"""
        method = 'file/share/nfs'
        request_type = 'post'
        params = {'path': share_path, 'pathAuthority': 'rw', 'client': []}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)

    @inspur_driver_debug_trace
    def _delete_nfs_share(self, share_path):
        """Delete the NFS share"""
        method = 'file/share/nfs?path=%s' % share_path
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)

    @inspur_driver_debug_trace
    def _get_nfs_share(self, share_path):
        """Get the nfs share in backend"""
        method = 'file/share/nfs?path=%s' % share_path
        request_type = 'get'
        share_backend = self._rest.send_rest_api(method=method,
                                                 request_type=request_type)
        return share_backend

    @inspur_driver_debug_trace
    def _create_cifs_share(self, share_name, share_path):
        """Create a CIFS share."""
        method = 'file/share/cifs'
        request_type = 'post'
        params = {'path': share_path,
                  'name': share_name,
                  'userlist': []}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)

    @inspur_driver_debug_trace
    def _delete_cifs_share(self, share_name):
        """Delete the CIFS share."""
        method = 'file/share/cifs?name=%s' % share_name
        request_type = 'delete'
        self._rest.send_rest_api(method=method, request_type=request_type)

    @inspur_driver_debug_trace
    def _get_cifs_share(self, share_name):
        """Get the CIFS share in backend"""
        method = 'file/share/cifs?name=%s' % share_name
        request_type = 'get'
        share_backend = self._rest.send_rest_api(method=method,
                                                 request_type=request_type)
        return share_backend

    @inspur_driver_debug_trace
    def _clone_directory_to_dest(self, snapshot, dest_path):
        """Clone the directory to the new directory"""
        # get the origin share name of the snapshot
        share_instance = snapshot['share_instance']
        pool, name, _, _ = self._get_share_instance_pnsp(share_instance)
        share_path = self._generate_share_path(pool, name)

        # get the snapshot instance name
        snap_name = self._generate_snapshot_name(snapshot)

        method = 'snapshot/directory/clone'
        request_type = 'post'
        params = {'path': share_path,
                  'snapName': snap_name,
                  'destPath': dest_path}
        self._rest.send_rest_api(method=method,
                                 params=params,
                                 request_type=request_type)
        LOG.debug('Clone Path: %(path)s Snapshot: %(snap)s to Path %(dest)s',
                  {'path': share_path, 'snap': snap_name, 'dest': dest_path})

    @inspur_driver_debug_trace
    def _get_snapshots_from_share(self, path):
        """get all the snapshot of share"""
        method = 'snapshot/directory?path=%s' % path
        request_type = 'get'
        snaps = self._rest.send_rest_api(method=method,
                                         request_type=request_type)
        return snaps

    @inspur_driver_debug_trace
    def _get_location_path(self, share_name, share_path, share_proto):
        """return all the location of all nodes"""
        if share_proto == 'nfs':
            location = [
                {'path': r'%(ip)s:%(share_path)s'
                         % {'ip': ip, 'share_path': share_path}}
                for ip in self.ips]
        else:
            location = [
                {'path': r'\\%(ip)s\%(share_name)s'
                         % {'ip': ip, 'share_name': share_name}}
                for ip in self.ips]

        return location

    def _get_nodes_virtual_ips(self):
        """Get the virtual ip list of the node"""
        method = 'ctdb/set'
        request_type = 'get'
        ctdb_set = self._rest.send_rest_api(method=method,
                                            request_type=request_type)
        virtual_ips = []
        for vip in ctdb_set['virtualIpList']:
            ip = vip['ip'].split('/')[0]
            virtual_ips.append(ip)
        return virtual_ips

    def _get_nodes_physical_ips(self):
        """Get the physical ip of all the backend nodes"""
        method = 'cluster/node/cache'
        request_type = 'get'
        cached_nodes = self._rest.send_rest_api(method=method,
                                                request_type=request_type)
        node_ips = []
        for node in cached_nodes:
            if node['runningStatus'] == 1 and node['healthStatus'] == 1:
                node_ips.append(node['nodeIp'])

        return node_ips

    def _get_nodes_ips(self):
        """Return both the physical ip and virtual ip"""
        virtual_ips = self._get_nodes_virtual_ips()
        physical_ips = self._get_nodes_physical_ips()

        return virtual_ips + physical_ips

    def _get_share_instance_pnsp(self, share_instance):
        """Get pool, name, size, proto information of a share instance.

        AS13000 require all the names can only consist of letters,numbers,
        and undercores,and must begin with a letter.
        Also the length of name must less than 32 character.
        The driver will use the ID as the name in backend,
        add 'share_' to the beginning,and convert '-' to '_'
        """
        pool = share_utils.extract_host(share_instance['host'], level='pool')
        name = self._generate_share_name(share_instance)
        # a share instance may not contain size attr.
        try:
            size = share_instance['size']
        except AttributeError:
            size = None

        # a share instance may not contain proto attr.
        try:
            proto = share_instance['share_proto'].lower()
        except AttributeError:
            proto = None

        LOG.debug("Pool %s, Name: %s, Size: %s, Protocol: %s",
                  pool, name, size, proto)

        return pool, name, size, proto

    def _unit_convert(self, capacity):
        """Convert all units to GB"""
        capacity = str(capacity)
        capacity = capacity.upper()
        try:
            unit_of_used = re.findall(r'[A-Z]', capacity)
            unit_of_used = ''.join(unit_of_used)
        except BaseException:
            unit_of_used = ''
        capacity = capacity.replace(unit_of_used, '')
        capacity = float(capacity.replace(unit_of_used, ''))
        if unit_of_used in ['B', '']:
            capacity = capacity / units.Gi
        elif unit_of_used in ['K', 'KB']:
            capacity = capacity / units.Mi
        elif unit_of_used in ['M', 'MB']:
            capacity = capacity / units.Ki
        elif unit_of_used in ['G', 'GB']:
            capacity = capacity
        elif unit_of_used in ['T', 'TB']:
            capacity = capacity * units.Ki
        elif unit_of_used in ['E', 'EB']:
            capacity = capacity * units.Mi

        capacity = '%.0f' % capacity
        return float(capacity)

    def _format_name(self, name):
        """format name to meet the backend requirements"""
        name = name[0:32]
        name = name.replace('-', '_')
        return name

    def _generate_share_name(self, share_instance):
        share_name = 'share_%s' % share_instance['id']
        return self._format_name(share_name)

    def _generate_snapshot_name(self, snapshot_instance):
        snap_name = 'snap_%s' % snapshot_instance['id']
        return self._format_name(snap_name)

    @staticmethod
    def _generate_share_path(pool, share_name):
        return r'/%s/%s' % (pool, share_name)

    def _get_directory_detail(self, directory):
        method = 'file/directory/detail?path=/%s' % directory
        request_type = 'get'
        details = self._rest.send_rest_api(method=method,
                                           request_type=request_type)
        return details[0]
