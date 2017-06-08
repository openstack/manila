# Copyright 2017 Veritas Technologies LLC.
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
Veritas Access Driver for manila shares.

Limitation:

1) single tenant
"""

import hashlib
import json

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import units
from random import shuffle
import requests
import requests.auth
import six
from six.moves import http_client

from manila.common import constants as const
from manila import exception
from manila.share import driver

LOG = logging.getLogger(__name__)


va_share_opts = [
    cfg.StrOpt('va_server_ip',
               help='Console IP of Veritas Access server.'),
    cfg.IntOpt('va_port',
               default=14161,
               help='Veritas Access server REST port.'),
    cfg.StrOpt('va_user',
               help='Veritas Access server REST login name.'),
    cfg.StrOpt('va_pwd',
               secret=True,
               help='Veritas Access server REST password.'),
    cfg.StrOpt('va_pool',
               help='Veritas Access storage pool from which'
                    'shares are served.'),
    cfg.StrOpt('va_fstype',
               default='simple',
               help='Type of VA file system to be created.')
]


CONF = cfg.CONF
CONF.register_opts(va_share_opts)


class NoAuth(requests.auth.AuthBase):
    """This is a 'authentication' handler.

    It exists for use with custom authentication systems, such as the
    one for the Access API, it simply passes the Authorization header as-is.

    The default authentication handler for requests will clobber the
    Authorization header.
    """

    def __call__(self, r):
        return r


class ACCESSShareDriver(driver.ExecuteMixin, driver.ShareDriver):
    """ACCESS Share Driver.

    Executes commands relating to Manila Shares.
    Supports creation of shares on ACCESS.

    API version history:

        1.0 - Initial version.
    """

    VA_SHARE_PATH_STR = '/vx/'

    def __init__(self, *args, **kwargs):
        """Do initialization."""

        super(ACCESSShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(va_share_opts)
        self.backend_name = self.configuration.safe_get(
            'share_backend_name') or "VeritasACCESS"
        self._va_ip = None
        self._va_url = None
        self._pool = None
        self._fstype = None
        self._port = None
        self._user = None
        self._pwd = None
        self._cred = None
        self._connect_resp = None
        self._verify_ssl_cert = None
        self._fs_create_str = '/fs/create'
        self._fs_list_str = '/fs'
        self._fs_delete_str = '/fs/destroy'
        self._fs_extend_str = '/fs/grow'
        self._fs_shrink_str = '/fs/shrink'
        self._snap_create_str = '/snapshot/create'
        self._snap_delete_str = '/snapshot/delete'
        self._snap_list_str = '/snapshot/getSnapShotList'
        self._nfs_add_str = '/share/create'
        self._nfs_delete_str = '/share/delete'
        self._nfs_share_list_str = '/share/all_shares_details_by_path/?path='
        self._ip_addr_show_str = '/common/get_all_ips'
        self._pool_free_str = '/storage/pool'
        self._update_object = '/objecttags'
        self.session = None
        self.host = None
        LOG.debug("ACCESSShareDriver called")

    def do_setup(self, context):
        """Any initialization the share driver does while starting."""
        super(ACCESSShareDriver, self).do_setup(context)

        self._va_ip = self.configuration.va_server_ip
        self._pool = self.configuration.va_pool
        self._user = self.configuration.va_user
        self._pwd = self.configuration.va_pwd
        self._port = self.configuration.va_port
        self._fstype = self.configuration.va_fstype
        self.session = self._authenticate_access(self._va_ip, self._user,
                                                 self._pwd)

    def _get_va_share_name(self, name):
        length = len(name)
        index = int(length / 2)
        name1 = name[:index]
        name2 = name[index:]
        crc1 = hashlib.md5(name1.encode('utf-8')).hexdigest()[:8]
        crc2 = hashlib.md5(name2.encode('utf-8')).hexdigest()[:8]
        return crc1 + '-' + crc2

    def _get_va_snap_name(self, name):
        return self._get_va_share_name(name)

    def _get_va_share_path(self, name):
        return self.VA_SHARE_PATH_STR + name

    def _does_item_exist_at_va_backend(self, item_name, path_given):
        """Check given share is exists on backend"""

        path = path_given
        provider = '%s:%s' % (self.host, self._port)
        data = {}
        item_list = self._access_api(self.session, provider, path,
                                     json.dumps(data), 'GET')

        for item in item_list:
            if item['name'] == item_name:
                return True

        return False

    def _return_access_lists_difference(self, list_a, list_b):
        """Returns a list of elements in list_a that are not in list_b"""

        sub_list = [{"access_to": s.get('access_to'),
                     "access_type": s.get('access_type'),
                     "access_level": s.get('access_level')}
                    for s in list_b]

        return [r for r in list_a if (
            {"access_to": r.get("access_to"),
             "access_type": r.get("access_type"),
             "access_level": r.get("access_level")} not in sub_list)]

    def _fetch_existing_rule(self, share_name):
        """Return list of access rules on given share"""

        share_path = self._get_va_share_path(share_name)
        path = self._nfs_share_list_str + share_path
        provider = '%s:%s' % (self.host, self._port)
        data = {}
        share_list = self._access_api(self.session, provider, path,
                                      json.dumps(data), 'GET')

        va_access_list = []
        for share in share_list:
            if share['shareType'] == 'NFS':
                for share_info in share['shares']:
                    if share_info['name'] == share_path:
                        access_to = share_info['host_name']
                        a_level = const.ACCESS_LEVEL_RO
                        if const.ACCESS_LEVEL_RW in share_info['privilege']:
                            a_level = const.ACCESS_LEVEL_RW
                        va_access_list.append({
                            'access_to': access_to,
                            'access_level': a_level,
                            'access_type': 'ip'
                        })

        return va_access_list

    def create_share(self, ctx, share, share_server=None):
        """Create an ACCESS file system that will be represented as share."""

        sharename = share['name']
        sizestr = '%sg' % share['size']
        LOG.debug("ACCESSShareDriver create_share sharename %s sizestr %r",
                  sharename, sizestr)
        va_sharename = self._get_va_share_name(sharename)
        va_sharepath = self._get_va_share_path(va_sharename)
        va_fs_type = self._fstype
        path = self._fs_create_str
        provider = '%s:%s' % (self.host, self._port)
        data1 = {
            "largefs": "no",
            "blkSize": "blksize=8192",
            "pdirEnable": "pdir_enable=yes"
        }
        data1["layout"] = va_fs_type
        data1["fs_name"] = va_sharename
        data1["fs_size"] = sizestr
        data1["pool_disks"] = self._pool
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data1), 'POST')
        if not result:
            message = (('ACCESSShareDriver create share failed %s'), sharename)
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        data2 = {"type": "FS", "key": "manila"}
        data2["id"] = va_sharename
        data2["value"] = 'manila_fs'
        path = self._update_object
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data2), 'POST')

        vip = self._get_vip()
        location = vip + ':' + va_sharepath
        LOG.debug("ACCESSShareDriver create_share location %s", location)
        return location

    def _get_vip(self):
        """Get a virtual IP from ACCESS."""
        ip_list = self._get_access_ips(self.session, self.host)
        vip = []
        for ips in ip_list:
            if ips['isconsoleip'] == 1:
                continue
            if ips['type'] == 'Virtual' and ips['status'] == 'ONLINE':
                vip.append(ips['ip'])
        shuffle(vip)
        return six.text_type(vip[0])

    def delete_share(self, context, share, share_server=None):
        """Delete a share from ACCESS."""

        sharename = share['name']
        va_sharename = self._get_va_share_name(sharename)
        LOG.debug("ACCESSShareDriver delete_share %s called",
                  sharename)
        if share['snapshot_id']:
            message = (('ACCESSShareDriver delete share %s'
                        ' early return'), sharename)
            LOG.debug(message)
            return

        ret_val = self._does_item_exist_at_va_backend(va_sharename,
                                                      self._fs_list_str)
        if not ret_val:
            return

        path = self._fs_delete_str
        provider = '%s:%s' % (self.host, self._port)
        data = {}
        data["fs_name"] = va_sharename
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data), 'POST')
        if not result:
            message = (('ACCESSShareDriver delete share failed %s'), sharename)
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        data2 = {"type": "FS", "key": "manila"}
        data2["id"] = va_sharename
        path = self._update_object
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data2), 'DELETE')

    def extend_share(self, share, new_size, share_server=None):
        """Extend existing share to new size."""
        sharename = share['name']
        size = '%s%s' % (six.text_type(new_size), 'g')
        va_sharename = self._get_va_share_name(sharename)
        path = self._fs_extend_str
        provider = '%s:%s' % (self.host, self._port)
        data1 = {"operationOption": "growto", "tier": "primary"}
        data1["fs_name"] = va_sharename
        data1["fs_size"] = size
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data1), 'POST')
        if not result:
            message = (('ACCESSShareDriver extend share failed %s'), sharename)
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        LOG.debug('ACCESSShareDriver extended share'
                  ' successfully %s', sharename)

    def shrink_share(self, share, new_size, share_server=None):
        """Shrink existing share to new size."""
        sharename = share['name']
        va_sharename = self._get_va_share_name(sharename)
        size = '%s%s' % (six.text_type(new_size), 'g')
        path = self._fs_extend_str
        provider = '%s:%s' % (self.host, self._port)
        data1 = {"operationOption": "shrinkto", "tier": "primary"}
        data1["fs_name"] = va_sharename
        data1["fs_size"] = size
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data1), 'POST')
        if not result:
            message = (('ACCESSShareDriver shrink share failed %s'), sharename)
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        LOG.debug('ACCESSShareDriver shrunk share successfully %s', sharename)

    def _allow_access(self, context, share, access, share_server=None):
        """Give access of a share to an IP."""

        access_type = access['access_type']
        server = access['access_to']
        if access_type != 'ip':
            raise exception.InvalidShareAccess('Only ip access type '
                                               'supported.')
        access_level = access['access_level']

        if access_level not in (const.ACCESS_LEVEL_RW, const.ACCESS_LEVEL_RO):
            raise exception.InvalidShareAccessLevel(level=access_level)
        export_path = share['export_locations'][0]['path'].split(':', 1)
        va_sharepath = six.text_type(export_path[1])
        access_level = '%s,%s' % (six.text_type(access_level),
                                  'sync,no_root_squash')

        path = self._nfs_add_str
        provider = '%s:%s' % (self.host, self._port)
        data = {}
        va_share_info = ("{\"share\":[{\"fileSystemPath\":\""+va_sharepath +
                         "\",\"shareType\":\"NFS\",\"shareDetails\":" +
                         "[{\"client\":\""+server+"\",\"exportOptions\":\"" +
                         access_level+"\"}]}]}")

        data["shareDetails"] = va_share_info

        result = self._access_api(self.session, provider, path,
                                  json.dumps(data), 'POST')

        if not result:
            message = (('ACCESSShareDriver access failed sharepath %s'
                        'server %s'),
                       va_sharepath,
                       server)
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        LOG.debug("ACCESSShareDriver allow_access sharepath %s server %s",
                  va_sharepath, server)

        data2 = {"type": "SHARE", "key": "manila"}
        data2["id"] = va_sharepath
        data2["value"] = 'manila_share'
        path = self._update_object
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data2), 'POST')

    def _deny_access(self, context, share, access, share_server=None):
        """Deny access to the share."""

        server = access['access_to']
        access_type = access['access_type']
        if access_type != 'ip':
            return
        export_path = share['export_locations'][0]['path'].split(':', 1)
        va_sharepath = six.text_type(export_path[1])
        LOG.debug("ACCESSShareDriver deny_access sharepath %s server %s",
                  va_sharepath, server)

        path = self._nfs_delete_str
        provider = '%s:%s' % (self.host, self._port)
        data = {}
        va_share_info = ("{\"share\":[{\"fileSystemPath\":\""+va_sharepath +
                         "\",\"shareType\":\"NFS\",\"shareDetails\":" +
                         "[{\"client\":\""+server+"\"}]}]}")

        data["shareDetails"] = va_share_info
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data), 'DELETE')
        if not result:
            message = (('ACCESSShareDriver deny failed'
                        ' sharepath %s server %s'),
                       va_sharepath,
                       server)
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        LOG.debug("ACCESSShareDriver deny_access sharepath %s server %s",
                  va_sharepath, server)

        data2 = {"type": "SHARE", "key": "manila"}
        data2["id"] = va_sharepath
        path = self._update_object
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data2), 'DELETE')

    def update_access(self, context, share, access_rules, add_rules,
                      delete_rules, share_server=None):
        """Update access to the share."""

        if (add_rules or delete_rules):
            # deleting rules
            for rule in delete_rules:
                self._deny_access(context, share, rule, share_server)

            # adding rules
            for rule in add_rules:
                self._allow_access(context, share, rule, share_server)
        else:
            if not access_rules:
                LOG.warning("No access rules provided in update_access.")
            else:
                sharename = self._get_va_share_name(share['name'])
                existing_a_rules = self._fetch_existing_rule(sharename)

                d_rule = self._return_access_lists_difference(existing_a_rules,
                                                              access_rules)
                for rule in d_rule:
                    LOG.debug("Removing rule %s in recovery.",
                              six.text_type(rule))
                    self._deny_access(context, share, rule, share_server)

                a_rule = self._return_access_lists_difference(access_rules,
                                                              existing_a_rules)
                for rule in a_rule:
                    LOG.debug("Adding rule %s in recovery.",
                              six.text_type(rule))
                    self._allow_access(context, share, rule, share_server)

    def create_snapshot(self, context, snapshot, share_server=None):
        """create snapshot of a share."""
        LOG.debug('ACCESSShareDriver create_snapshot called '
                  'for snapshot ID %s.',
                  snapshot['snapshot_id'])

        sharename = snapshot['share_name']
        va_sharename = self._get_va_share_name(sharename)
        snapname = snapshot['name']
        va_snapname = self._get_va_snap_name(snapname)

        path = self._snap_create_str
        provider = '%s:%s' % (self.host, self._port)
        data = {}
        data["snapShotname"] = va_snapname
        data["fileSystem"] = va_sharename
        data["removable"] = 'yes'
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data), 'PUT')
        if not result:
            message = (('ACCESSShareDriver create snapshot failed snapname %s'
                        ' sharename %s'),
                       snapname,
                       va_sharename)
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        data2 = {"type": "SNAPSHOT", "key": "manila"}
        data2["id"] = va_snapname
        data2["value"] = 'manila_snapshot'
        path = self._update_object
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data2), 'POST')

    def delete_snapshot(self, context, snapshot, share_server=None):
        """Deletes a snapshot."""
        sharename = snapshot['share_name']
        va_sharename = self._get_va_share_name(sharename)
        snapname = snapshot['name']
        va_snapname = self._get_va_snap_name(snapname)

        ret_val = self._does_item_exist_at_va_backend(va_snapname,
                                                      self._snap_list_str)
        if not ret_val:
            return

        path = self._snap_delete_str
        provider = '%s:%s' % (self.host, self._port)

        data = {}
        data["name"] = va_snapname
        data["fsName"] = va_sharename
        data_to_send = {"snapShotDetails": {"snapshot": [data]}}
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data_to_send), 'DELETE')
        if not result:
            message = (('ACCESSShareDriver delete snapshot failed snapname %s'
                        ' sharename %s'),
                       snapname,
                       va_sharename)
            LOG.error(message)
            raise exception.ShareBackendException(msg=message)

        data2 = {"type": "SNAPSHOT", "key": "manila"}
        data2["id"] = va_snapname
        path = self._update_object
        result = self._access_api(self.session, provider, path,
                                  json.dumps(data2), 'DELETE')

    def create_share_from_snapshot(self, ctx, share, snapshot,
                                   share_server=None):
        """create share from a snapshot."""
        sharename = snapshot['share_name']
        va_sharename = self._get_va_share_name(sharename)
        snapname = snapshot['name']
        va_snapname = self._get_va_snap_name(snapname)
        va_sharepath = self._get_va_share_path(va_sharename)
        LOG.debug(('ACCESSShareDriver create_share_from_snapshot snapname %s'
                   ' sharename %s'),
                  va_snapname,
                  va_sharename)
        vip = self._get_vip()
        location = vip + ':' + va_sharepath + ':' + va_snapname
        LOG.debug("ACCESSShareDriver create_share location %s", location)
        return location

    def _get_api(self, provider, tail):
        api_root = 'https://%s/api' % (provider)
        return api_root + tail

    def _access_api(self, session, provider, path, input_data, method):
        """Returns False if failure occurs."""
        kwargs = {'data': input_data}
        if not isinstance(input_data, dict):
            kwargs['headers'] = {'Content-Type': 'application/json'}
        full_url = self._get_api(provider, path)
        response = session.request(method, full_url, **kwargs)
        if response.status_code != http_client.OK:
            LOG.debug('Access API operation Failed.')
            return False
        if path == self._update_object:
            return True
        result = response.json()
        return result

    def _get_access_ips(self, session, host):

        path = self._ip_addr_show_str
        provider = '%s:%s' % (host, self._port)
        data = {}
        ip_list = self._access_api(session, provider, path,
                                   json.dumps(data), 'GET')
        return ip_list

    def _authenticate_access(self, address, username, password):
        session = requests.session()
        session.verify = False
        session.auth = NoAuth()

        response = session.post('https://%s:%s/api/rest/authenticate'
                                % (address, self._port),
                                data={'username': username,
                                      'password': password})
        if response.status_code != http_client.OK:
            LOG.debug(('failed to authenticate to remote cluster at %s as %s'),
                      address, username)
            raise exception.NotAuthorized('Authentication failure.')
        result = response.json()
        session.headers.update({'Authorization': 'Bearer {}'
                                .format(result['token'])})
        session.headers.update({'Content-Type': 'application/json'})

        return session

    def _get_access_pool_details(self):
        """Get access pool details."""
        path = self._pool_free_str
        provider = '%s:%s' % (self.host, self._port)
        data = {}
        pool_details = self._access_api(self.session, provider, path,
                                        json.dumps(data), 'GET')

        for pool in pool_details:
            if pool['device_group_name'] == six.text_type(self._pool):
                total_capacity = (int(pool['capacity']) / units.Gi)
                used_size = (int(pool['used_size']) / units.Gi)
                return (total_capacity, (total_capacity - used_size))

        message = 'Fetching pool details operation failed.'
        LOG.error(message)
        raise exception.ShareBackendException(msg=message)

    def _update_share_stats(self):
        """Retrieve status info from share volume group."""

        LOG.debug("VRTSISA Updating share status.")
        self.host = six.text_type(self._va_ip)
        self.session = self._authenticate_access(self._va_ip,
                                                 self._user, self._pwd)
        total_capacity, free_capacity = self._get_access_pool_details()
        data = {
            'share_backend_name': self.backend_name,
            'vendor_name': 'Veritas',
            'driver_version': '1.0',
            'storage_protocol': 'NFS',
            'total_capacity_gb': total_capacity,
            'free_capacity_gb': free_capacity,
            'reserved_percentage': 0,
            'QoS_support': False,
            'snapshot_support': True,
            'create_share_from_snapshot_support': True
        }
        super(ACCESSShareDriver, self)._update_share_stats(data)
