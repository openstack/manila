# Copyright 2020 ZTE Corp.
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
Share Driver for ZTE CloveStorage.
"""

import functools
import json
import requests
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units

from manila import exception
from manila.i18n import _
from manila.share import driver
from manila.share import utils as share_utils


zte_clovestorage_opts = [
    cfg.HostAddressOpt(
        'clovestorage_nas_ip',
        required=True,
        help='IP address for the Clove storage.'),
    cfg.PortOpt(
        'clovestorage_nas_port',
        default=8088,
        help='Port number for the Clove storage.'),
    cfg.StrOpt(
        'clovestorage_nas_login',
        required=True,
        help='Username for the Clove storage'),
    cfg.StrOpt(
        'clovestorage_nas_password',
        required=True,
        secret=True,
        help='Password for the Clove storage'),
    #cfg.ListOpt(
    #    'clovestorage_share_pools',
    #    required=True,
    #    help='The Storage Pools Manila should use, a comma separated list'),
    cfg.IntOpt(
        'clovestorage_token_available_time',
        default=3600,
        help='The effective time of token validity in seconds.'),
    cfg.StrOpt(
        'clovestorage_nas_instance_id',
        required=True,
        secret=True,
        help='The Storage Instance ID Manila should use'),
    cfg.StrOpt(
        'clovestorage_export_ips',
        required=True,
        secret=True,
        help='The Storage Export IPs')
]

CONF = cfg.CONF
CONF.register_opts(zte_clovestorage_opts)
LOG = logging.getLogger(__name__)


def clovestorage_driver_debug_trace(f):
    """Log the method entrance and exit including active backend name.

    This should only be used on Share_Driver class methods. It depends on
    having a 'self' argument that is a CloveStorage_Driver.
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

    def login(self):
        """
        login to CloveStorage.
        """
        LOG.debug("login to CloveStorage")

        data = {
            'username': self._username,
            'password': self._password
        }
        jdata = json.dumps(data)
        self.header = {"Content-Type": "application/json; charset=UTF-8"}
        url = '/api/v1/auth/login'

        ret = self.send_rest_api('POST', url, jdata, 201)

        self.token = ret['Token']
        self.header = {
            "Content-Type": "application/json; charset=UTF-8",
            "Authorization": "Token %s" % self.token
        }

    def request_async_task(self, methond, param, url, expected):
        ret = self.send_rest_api(
            methond,
            url,
            json.dumps(param) if param is not None else param,
            expected
        )

        if 'result' in ret and not ret['result']:
            raise RuntimeError("request async task error")

        task_id = ret['request_id']
        self._get_task_progress(task_id)

    def send_rest_api(self, method, url, data, expected):
        """
        Request a url and Raise error when rsponse code not expected

        :param method: request method
        :param url:    request url
        :param data:   request data
        :param expected:   expected response code
        """

        request_url = self._format_url(url)
        ret = self._do_request(method, request_url, data, self.header)

        if ret['code'] in [400, 401, 403]:
            LOG.error("----token update----:{0}".format(ret['code']))
            self.login()
            ret = self._do_request(method, request_url, data, self.header)

        if ret['code'] != expected:
            msg = (_('Access RestAPI {0} by {1} failed,'
                     'response code: {2}', \
                     'error: {3}'.format(
                     request_url, method, ret['code'], ret['response'])))
            LOG.error(msg)
            raise exception.ShareBackendException(msg)

        return ret['response']

    @staticmethod
    def _do_request(method, url, data, header):
        """
        A http request
        Send request to server and Get response
        return response data and code
        """
        LOG.debug('METHOD: %(method)s, URL: %(url)s, DATA: %(data)s',
                  {'method': method, 'url': url, 'data': data})

        if method == 'POST':
            req = requests.post(url, data=data, headers=header, verify=False)
        elif method == 'GET':
            req = requests.get(url, data=data, headers=header, verify=False)
        elif method == 'PUT':
            req = requests.put(url, data=data, headers=header, verify=False)
        elif method == 'PATCH':
            req = requests.patch(url, data=data, headers=header, verify=False)
        elif method == 'DELETE':
            req = requests.delete(url, data=data, headers=header, verify=False)
        else:
            msg = (_('Unsupported method: %s') % method)
            raise exception.ShareBackendException(msg)

        response = json.loads(req.text)
        code = req.status_code
        #LOG.debug('CODE: %(code)s, RESPONSE: %(response)s',
        #          {'code': code, 'response': response})

        return {
            "response": response,
            "code": code
        }

    def get_cluster_id(self):
        ret = self.send_rest_api(
            'GET',
            '/api/v2/user/me/clusters',
            None,
            200
        )
        if not ret:
            return None
        return ret[0]['cluster_id']

    def _get_task_progress(self, task_id):
        time.sleep(5)
        times = 0

        while times < 240:
            ret = self.send_rest_api('GET', '/api/v2/request', None, 200)

            results = ret['results']
            for result in results:
                if result['id'] != task_id:
                    continue
                state = result['state']
                if state != 'complete':
                    LOG.info("task: {0} is still executing".format(task_id))
                    continue
                error = result['error']
                if error:
                    msg = (_('Async task {0} request failed, Reason:{1}'\
                                .format(result['id'], 
                                        result['error_message'])))
                    LOG.error(msg)
                    raise exception.ShareBackendException(msg)
                return
            times += 1
            time.sleep(5)
        else:
            msg = "20 min timed out, but task process not finished!"
            LOG.error(msg)
            raise RuntimeError(error_str)

    def _format_url(self, url):
        return 'https://{0}:{1}{2}'.format(self._hostname, self._port, url)

class CloveStorageShareDriver(driver.ShareDriver):

    """CloveStorage Share Driver

    Version history:
    V1.0.0:    Initial version
               Driver support:
                   share create/delete,
                   #snapshot create/delete,
                   extend size,
                   #create_share_from_snapshot,
                   update_access.
                   protocol: NFS/CIFS

    """

    VENDOR = 'ZTE'
    VERSION = '1.0.0'
    PROTOCOL = 'NFS_CIFS'

    def __init__(self, *args, **kwargs):
        super(CloveStorageShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(zte_clovestorage_opts)
        self.hostname = self.configuration.clovestorage_nas_ip
        self.port = self.configuration.clovestorage_nas_port
        self.username = self.configuration.clovestorage_nas_login
        self.password = self.configuration.clovestorage_nas_password
        self.instance_id = self.configuration.clovestorage_nas_instance_id
        self.ips = self.configuration.clovestorage_export_ips.split(',')
        self.token_available_time = (self.configuration.
                                     clovestorage_token_available_time)
        self._rest = RestAPIExecutor(self.hostname, self.port,
                                     self.username, self.password)

    @clovestorage_driver_debug_trace
    def do_setup(self, context):
        # get access tokens
        
        self._rest.login()
        self.cluster_id = self._rest.get_cluster_id()

        self.nas_url = '/api/v3/clusters/{0}/nas'.format(self.cluster_id)
        self.paths_url = '/api/v3/clusters/{0}/paths'.format(self.cluster_id)
        self.nfs_url = '/api/v3/clusters/{0}/nfs'.format(self.cluster_id)
        self.cifs_url = '/api/v3/clusters/{0}/cifs'.format(self.cluster_id)
        self.group_url = '/api/v3/clusters/{0}/filestore/groups'.format(self.cluster_id)
        self.ad_url = '/api/v3/ad'

    @clovestorage_driver_debug_trace
    def check_for_setup_error(self):
        if len(self.ips) == 0:
            msg = _('All backend nodes are down')
            raise exception.ShareBackendException(msg)

    @clovestorage_driver_debug_trace
    def ensure_share(self, context, share, share_server=None):
        """Ensure that share is exported."""
        pool, name, size, proto = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, name)

        if proto == 'nfs':
            share_backend = self._get_nfs_id(share_path)
        elif proto == 'cifs':
            share_backend = self._get_cifs_id(share_path)
        else:
            msg = (_('Invalid NAS protocol supplied: %s.') % proto)
            LOG.error(msg)
            raise exception.InvalidInput(msg)

        if share_backend is None:
            msg = _('share_backend is not export')
            raise exception.ShareBackendException(msg)

        return self._get_location_path(name, share_path, proto)

    @clovestorage_driver_debug_trace
    def create_share(self, context, share, share_server=None):
        """Create a share."""
        pool, name, size, proto = self._get_share_instance_pnsp(share)

        # create directory and set the quota of directory
        share_path = self._create_directory(share_name=name,
                                            pool_name=pool,
                                            size=size)

        # get clovestorage path id first
        path_id = self._get_path_id(share_path)
        # then create nfs or cifs share
        if proto == 'nfs':
            self._create_nfs_share(share_path=share_path,
                                    path_id=path_id)
        else:
            self._create_cifs_share(share_name=name,
                                    share_path=share_path,
                                    path_id=path_id)

        LOG.debug('Create share: name:%(name)s'
                  ' protocol:%(proto)s,location: %(loc)s',
                  {'name': name, 'proto': proto, 'loc': locations})
        return locations

    @clovestorage_driver_debug_trace
    def create_share_from_snapshot(self, context, share, snapshot,
                                   share_server=None, parent_share=None):
        """Create a share from snapshot."""
        pool, name, size, proto = self._get_share_instance_pnsp(share)

        # create directory and set the quota of directory
        share_path = self._create_directory(share_name=name,
                                            pool_name=pool,
                                            size=size)

        # get clovestorage path id first
        path_id = self._get_path_id(share_path)

        # and next clone snapshot to dest_path
        self._clone_directory_to_dest(snapshot=snapshot, dest_path_id=path_id)

        # finally create share
        if proto == 'nfs':
            self._create_nfs_share(share_path=share_path,
                                    path_id=path_id)
        else:
            self._create_cifs_share(share_name=name,
                                    share_path=share_path,
                                    path_id=path_id)

        locations = self._get_location_path(name, share_path, proto)
        LOG.debug('Create share from snapshot:'
                  ' name:%(name)s protocol:%(proto)s,location: %(loc)s',
                  {'name': name, 'proto': proto, 'loc': locations})
        return locations

    @clovestorage_driver_debug_trace
    def delete_share(self, context, share, share_server=None):
        """Delete share."""
        pool, name, _, proto = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, name)

        if proto == 'nfs':
            nfs_id = self._get_nfs_id(share_path)
            if nfs_id is None:
                return
            else:
                self._delete_nfs_share(nfs_id)
        else:
            cifs_id = self._get_cifs_id(share_path)
            if cifs_id is None:
                return
            else:
                self._delete_cifs_share(cifs_id)
                time.sleep(20)

        path_id = self._get_path_id(share_path)
        if path_id is None:
                return
        else:
            self._delete_directory(path_id)

        LOG.debug('Delete share: %s', name)

    @clovestorage_driver_debug_trace
    def extend_share(self, share, new_size, share_server=None):
        """extend share to new size"""
        pool, name, size, proto = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, name)

        path_id = self._get_path_id(share_path)
        if path_id is None:
            msg = _('Get CloveStorage path_id return None')
            raise exception.ShareBackendException(msg) 
        self._set_directory_quota(share_path, new_size, path_id)
        LOG.debug('extend share %(name)s to new size %(size)s GB',
                  {'name': name, 'size': new_size})

    @clovestorage_driver_debug_trace
    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """update access of share"""
        pool, share_name, _, proto = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, share_name)

        if proto == 'nfs':
            if add_rules:
                for rule in add_rules:
                    access_type = rule['access_level'].upper()
                    client = rule['access_to']
                    self._add_nfs_access_rule(share_path, access_type, client)
            elif delete_rules:
                delete_ids = []
                nfs_rules = self._get_nfs_access_rules(share_path)
                for rule in delete_rules:
                    client = rule['access_to']
                    for nfs_rule in nfs_rules:
                        if nfs_rule["client"] == client:
                            delete_ids.append(nfs_rule["id"])
                self._delete_nfs_access_rules(share_path, delete_ids)
            else:
                self._clear_nfs_rules(share_path)
                for rule in access_rules:
                    access_type = rule['access_level'].upper()
                    client = rule['access_to']
                    self._add_nfs_access_rule(share_path, access_type, client)

        if proto == 'cifs':
            cifs_auth_type = self._get_cifs_auth_type()
            if cifs_auth_type is None:
                msg = 'Get cifs auth type error'
                LOG.error(msg)
                raise exception.ShareBackendException(msg=msg)
            ad_id = None
            if cifs_auth_type == "AD":
                ad_id = self._get_ad_id()
                if ad_id is None:
                    msg = 'Get ad id error'
                    LOG.error(msg)
                    raise exception.ShareBackendException(msg=msg)

            if add_rules:
                for rule in add_rules:
                    access_type = rule['access_level'].upper()
                    client = rule['access_to']
                    group = self._get_group_by_user(cifs_auth_type, client, ad_id)
                    if cifs_auth_type is None:
                        msg = (_(r'Get local group by user error'))
                        LOG.error(msg)
                        raise exception.ShareBackendException(msg=msg)

                    self._add_cifs_access_rule(share_path, cifs_auth_type, access_type, group, client)
            elif delete_rules:
                delete_ids = []
                cifs_rules = self._get_cifs_access_rules(share_path)
                for rule in delete_rules:
                    client = rule['access_to']
                    for cifs_rule in cifs_rules:
                        if cifs_rule["user"] == client:
                            delete_ids.append(cifs_rule["id"])
                self._delete_cifs_access_rules(share_path, delete_ids)
            else:
                self._clear_cifs_rules(share_path)
                for rule in access_rules:
                    access_type = rule['access_level'].upper()
                    client = rule['access_to']
                    group = self._get_group_by_user(cifs_auth_type, client, ad_id)
                    if cifs_auth_type is None:
                        msg = (_(r'Get local group by user error'))
                        LOG.error(msg)
                        raise exception.ShareBackendException(msg=msg)
                    self._add_cifs_access_rule(share_path, cifs_auth_type, access_type, group, client)

    @clovestorage_driver_debug_trace
    def create_snapshot(self, context, snapshot, share_server=None):
        """create snapshot of share"""
        ## !!! Attention the share property is a ShareInstance
        share = snapshot['share']
        pool, share_name, _, _ = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, share_name)

        snap_name = self._generate_snapshot_name(snapshot)

        path_id = self._get_path_id(share_path)
        if path_id is None:
            msg = _('Get CloveStorage path_id return None')
            raise exception.ShareBackendException(msg)

        method = 'POST'
        param = {
            "validity": 0,
            "name": snap_name
        }

        status_code = 200
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

        LOG.debug('Create snapshot %(snap)s for share %(share)s',
                  {'snap': snap_name, 'share': share_name})

    @clovestorage_driver_debug_trace
    def delete_snapshot(self, context, snapshot, share_server=None):
        """delete snapshot of share"""
        # !!! Attention the share property is a ShareInstance
        share = snapshot['share']
        pool, share_name, _, _ = self._get_share_instance_pnsp(share)
        share_path = self._generate_share_path(pool, share_name)

        path_id = self._get_path_id(share_path)
        if path_id is None:
            msg = _('Get CloveStorage path_id return None')
            raise exception.ShareBackendException(msg)

        # if there are no snapshot exist, driver will return directly
        snap_name = self._generate_snapshot_name(snapshot)
        snap_id = self._get_snap_id(path_id, snap_name)
        if snap_id is None:
            return

        method = 'DELETE'
        param = {
            "ids":[snap_id]
        }
        url = self.paths_url + '/{0}/snapshots'.format(path_id)
        status_code = 200
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

        LOG.debug('Delete snapshot %(snap)s of share %(share)s',
                  {'snap': snap_name, 'share': share_name})

    @clovestorage_driver_debug_trace
    def _get_nfs_access_rules(self, share_path):
        nfs_id = self._get_nfs_id(share_path)
        if nfs_id is None:
            msg = (_(r'Get nfs id return None'))
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)
        url = self.nfs_url + '/{0}/clients'.format(nfs_id)
        ret = self._rest.send_rest_api('GET', url, None, 200)
        return ret

    @clovestorage_driver_debug_trace
    def _clear_nfs_rules(self, share_path):
        clear_ids = []
        nfs_rules = self._get_nfs_access_rules(self, share_path)
        for nfs_rule in nfs_rules:
            clear_ids.append(nfs_rule["id"])
        self._delete_nfs_access_rules(share_path, clear_ids)

    @clovestorage_driver_debug_trace
    def _add_nfs_access_rule(self, share_path, access, client):
        nfs_id = self._get_nfs_id(share_path)
        if nfs_id is None:
            msg = (_(r'Get nfs id return None'))
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        method = 'POST'
        param = {
            "client": client,
            "access_type": access,
            "squash": "no_root_squash"
        }
        url = self.nfs_url + '/{0}/clients'.format(nfs_id)
        status_code = 202
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _delete_nfs_access_rules(self, share_path, rule_ids):
        if len(rule_ids) == 0:
            return
        nfs_id = self._get_nfs_id(share_path)
        if nfs_id is None:
            return
        method = 'DELETE'
        param = {
            "ids": rule_ids
        }
        url = self.nfs_url + '/{0}/clients'.format(nfs_id)
        status_code = 202
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _get_group_by_user(self, auth_type, user, ad_id=None):
        """get group by user"""
        if auth_type == "LOCAL":
            url = self.group_url
            expected = 200
        else:
            url = self.ad_url + '/{0}/simple'.format(ad_id)
            expected = 201

        ret = self._rest.send_rest_api('GET', url, None, expected)
        for group in ret:
            for group_user in group["users"]:
                if group_user["name"] == user:
                    return group["name"]
        return None

    @clovestorage_driver_debug_trace
    def _get_cifs_auth_type(self):
        """get cifs auth type"""
        url = self.nas_url
        ret = self._rest.send_rest_api('GET', url, None, 200)
        for instance in ret:
            if instance["id"] == int(self.instance_id):
                return instance["cifs_auth"]
        return None

    @clovestorage_driver_debug_trace
    def _get_cifs_access_rules(self, share_path):
        cifs_id = self._get_cifs_id(share_path)
        if cifs_id is None:
            msg = (_(r'Get cifs id return None'))
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        url = self.cifs_url + '/{0}/roles'.format(cifs_id)
        ret = self._rest.send_rest_api('GET', url, None, 200)
        return ret

    @clovestorage_driver_debug_trace
    def _clear_cifs_rules(self, share_path):
        clear_ids = []
        cifs_rules = self._get_cifs_access_rules(self, share_path)
        for cifs_rule in cifs_rules:
            clear_ids.append(cifs_rule["id"])
        self._delete_cifs_access_rules(share_path, clear_ids)

    @clovestorage_driver_debug_trace
    def _add_cifs_access_rule(self, share_path, auth_type, access, group, user):
        cifs_id = self._get_cifs_id(share_path)
        if cifs_id is None:
            msg = (_(r'Get cifs id return None'))
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        method = 'POST'
        param = {
            "source": auth_type,
            "group": group,
            "user": user,
            "role": access,
        }
        url = self.cifs_url + '/{0}/roles'.format(cifs_id)
        status_code = 201
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _delete_cifs_access_rules(self, share_path, rule_ids):
        if len(rule_ids) == 0:
            return
        cifs_id = self._get_cifs_id(share_path)
        if cifs_id is None:
            return
        method = 'DELETE'
        param = {
            "ids": rule_ids
        }
        url = self.cifs_url + '/{0}/roles'.format(cifs_id)
        status_code = 202
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _get_path_id(self, share_path):
        """get clovestorage path id"""
        url = self.paths_url
        ret = self._rest.send_rest_api('GET', url, None, 200)
        for path_info in ret:
            if path_info["path"] == share_path:
                return path_info["id"]
        return None

    @clovestorage_driver_debug_trace
    def _get_cifs_id(self, share_path):
        """get cifs id"""
        url = self.cifs_url
        ret = self._rest.send_rest_api('GET', url, None, 200)
        for cifs in ret:
            if cifs["path"] == share_path:
                return cifs["id"]
        return None

    @clovestorage_driver_debug_trace
    def _get_nfs_id(self, share_path):
        """get cifs id"""
        url = self.nfs_url
        ret = self._rest.send_rest_api('GET', url, None, 200)
        for nfs in ret:
            if nfs["path"] == share_path:
                return nfs["id"]
        return None

    @clovestorage_driver_debug_trace
    def _get_ad_id(self):
        """get ad id"""
        url = self.ad_url
        ret = self._rest.send_rest_api('GET', url, None, 201)
        for info in ret:
            ad_id = info["id"]
            return ad_id
        return None

    @clovestorage_driver_debug_trace
    def _get_snap_id(self, path_id, snapshot):
        """get snapshot id"""
        url = self.paths_url + '/{0}/snapshots'.format(path_id)
        ret = self._rest.send_rest_api('GET', url, None, 200)
        for info in ret:
            if info["name"] ==  snapshot:
                return info["id"]
        return None

    @clovestorage_driver_debug_trace
    def _create_directory(self, share_name, pool_name, size):
        """create a directory for share"""
        path = self._generate_share_path(pool_name, share_name)
        method = 'POST'
        param = {
            'path': path,
            'nas_id': self.instance_id,
            'max_bytes': size * 1024 * 1024 * 1024,
            'max_files': "0"
        }
        url = self.paths_url
        status_code = 202
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)
        return path

    @clovestorage_driver_debug_trace
    def _delete_directory(self, path_id):
        """delete a directory for share"""
        method = 'DELETE'
        param = None
        url = self.paths_url + '/{0}'.format(path_id)
        status_code = 202
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _set_directory_quota(self, share_path, quota, path_id):
        """set directory quota for share"""
        method = 'PATCH'
        param = {
            'path': share_path,
            'max_bytes': quota * 1024 * 1024 * 1024,
            'max_files': "0"
        }
        url = self.paths_url + '/{0}'.format(path_id)
        status_code = 202
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _create_nfs_share(self, share_path, path_id):
        """create a NFS share"""
        method = 'POST'
        param = {
            "protocols": "3,4",
            "access_type": "None",
            "squash":"no_root_squash",
            "nas_id": self.instance_id,
            "path_id":path_id,
            "path":share_path
        }
        url = self.nfs_url
        status_code = 202
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _delete_nfs_share(self, nfs_id):
        """delete a NFS share"""
        method = 'DELETE'
        param = {
            "ids":[nfs_id]
        }
        url = self.nfs_url
        status_code = 202
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _create_cifs_share(self, share_name, share_path, path_id):
        """Create a CIFS share."""
        method = 'POST'
        param = {
            "abe": "false",
            "csc_policy": "manual",
            "nas_id": self.instance_id,
            "path_id": path_id,
            "share_name":share_name,
            "path":share_path
        }
        url = self.cifs_url
        status_code = 201
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _delete_cifs_share(self, cifs_id):
        """delete a NFS share"""
        method = 'DELETE'
        param = {
            "ids":[cifs_id]
        }
        url = self.cifs_url
        status_code = 202
        params = (method, param, url, status_code)
        self._rest.request_async_task(*params)

    @clovestorage_driver_debug_trace
    def _clone_directory_to_dest(self, snapshot, dest_path_id):
        """Clone the directory to the new directory"""
        # get the origin share name of the snapshot
        share_instance = snapshot['share_instance']
        pool, name, _, _ = self._get_share_instance_pnsp(share_instance)
        share_path = self._generate_share_path(pool, name)

        path_id = self._get_path_id(share_path)
        if path_id is None:
            msg = _('Get CloveStorage path_id return None')
            raise exception.ShareBackendException(msg)

        # get the snapshot instance name
        snap_name = self._generate_snapshot_name(snapshot)
        snap_id = self._get_snap_id(path_id, snap_name)
        if snap_id is None:
            msg = _('Get CloveStorage snap_id return None')
            raise exception.ShareBackendException(msg)

        url = self.paths_url + '/{0}/snapshots/{1}'.format(path_id, snap_id)
        param = {
            "dest_path_id":dest_path_id
        }
        params = ('PUT', param, url, 200)
        self._rest.request_async_task(*params)

        LOG.debug('Clone Path: %(path)s Snapshot: %(snap)s to Path %(dest)s',
                  {'path': share_path, 'snap': snap_name, 'dest': dest_path_id})

    @clovestorage_driver_debug_trace
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

    def _get_share_instance_pnsp(self, share_instance):
        """Get pool, name, size, proto information of a share instance.

        CloveStorage require all the names can only consist of letters,
        numbers, and undercores, and must begin with a letter.
        To be confirmed:
        Also the length of name must less than 32 character.
        The driver will use the ID as the name in backend,
        add 'share_' to the beginning, and convert '-' to '_'
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

    def _format_name(self, name):
        """format name to meet the backend requirements"""
        #name = name[0:32]
        #name = name.replace('-', '_')
        return name

    def _generate_snapshot_name(self, snapshot_instance):
        snap_name = 'snap_%s' % snapshot_instance['id']
        return self._format_name(snap_name)

    def _generate_share_name(self, share_instance):
        share_name = 'share_%s' % share_instance['id']
        return self._format_name(share_name)

    @staticmethod
    def _generate_share_path(pool, share_name):
        return r'/%s/%s' % (pool, share_name)

