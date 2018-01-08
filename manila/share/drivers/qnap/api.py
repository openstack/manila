# Copyright (c) 2016 QNAP Systems, Inc.
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
API for QNAP Storage.
"""
import base64
import functools
import re
import ssl

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from oslo_log import log as logging
import six
from six.moves import http_client
from six.moves import urllib

from manila import exception
from manila.i18n import _
from manila import utils

LOG = logging.getLogger(__name__)
MSG_SESSION_EXPIRED = _("Session ID expired")
MSG_UNEXPECT_RESP = _("Unexpected response from QNAP API")


def _connection_checker(func):
    """Decorator to check session has expired or not."""
    @utils.retry(exception=exception.ShareBackendException,
                 retries=5)
    @functools.wraps(func)
    def inner_connection_checker(self, *args, **kwargs):
        LOG.debug('in _connection_checker')
        pattern = re.compile(r".*Session ID expired.$")
        try:
            return func(self, *args, **kwargs)
        except exception.ShareBackendException as e:
            matches = pattern.match(six.text_type(e))
            if matches:
                LOG.debug('Session might have expired.'
                          ' Trying to relogin')
                self._login()
            raise
    return inner_connection_checker


class QnapAPIExecutor(object):
    """Makes QNAP API calls for ES NAS."""

    def __init__(self, *args, **kwargs):
        self.sid = None
        self.username = kwargs['username']
        self.password = kwargs['password']
        self.ip, self.port, self.ssl = (
            self._parse_management_url(kwargs['management_url']))
        self._login()

    def _parse_management_url(self, management_url):
        pattern = re.compile(r"(http|https)\:\/\/(\S+)\:(\d+)")
        matches = pattern.match(management_url)
        if matches.group(1) == 'http':
            management_ssl = False
        else:
            management_ssl = True
        management_ip = matches.group(2)
        management_port = matches.group(3)
        return management_ip, management_port, management_ssl

    def _prepare_connection(self, isSSL, ip, port):
        if isSSL:
            if hasattr(ssl, '_create_unverified_context'):
                context = ssl._create_unverified_context()
                connection = http_client.HTTPSConnection(ip,
                                                         port=port,
                                                         context=context)
            else:
                connection = http_client.HTTPSConnection(ip,
                                                         port=port)
        else:
            connection = http_client.HTTPConnection(ip, port)
        return connection

    def get_basic_info(self, management_url):
        """Get the basic information of NAS."""
        LOG.debug('in get_basic_info')
        management_ip, management_port, management_ssl = (
            self._parse_management_url(management_url))
        connection = self._prepare_connection(management_ssl,
                                              management_ip,
                                              management_port)

        connection.request('GET', '/cgi-bin/authLogin.cgi')
        response = connection.getresponse()
        data = response.read()
        LOG.debug('response data: %s', data)

        root = ET.fromstring(data)

        display_model_name = root.find('model/displayModelName').text
        internal_model_name = root.find('model/internalModelName').text
        fw_version = root.find('firmware/version').text

        connection.close()
        return display_model_name, internal_model_name, fw_version

    def _execute_and_get_response_details(self, nas_ip, url):
        """Will prepare response after executing a http request."""
        LOG.debug('port: %(port)s, ssl: %(ssl)s',
                  {'port': self.port, 'ssl': self.ssl})

        res_details = {}

        # Prepare the connection
        connection = self._prepare_connection(self.ssl,
                                              nas_ip,
                                              self.port)

        # Make the connection
        LOG.debug('url : %s', url)
        connection.request('GET', url)
        # Extract the response as the connection was successful
        response = connection.getresponse()
        # Read the response
        data = response.read()
        LOG.debug('response data: %s', data)

        res_details['data'] = data
        res_details['error'] = None
        res_details['http_status'] = response.status

        connection.close()
        return res_details

    def execute_login(self):
        """Login and return sid."""
        params = {
            'user': self.username,
            'pwd': base64.b64encode(self.password.encode("utf-8")),
            'serviceKey': '1',
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/authLogin.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])

        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)

        session_id = root.find('authSid').text
        return session_id

    def _login(self):
        """Execute Https Login API."""
        self.sid = self.execute_login()
        LOG.debug('sid: %s', self.sid)

    def _sanitize_params(self, params):
        sanitized_params = {}
        for key in params:
            value = params[key]
            if value is not None:
                if isinstance(value, list):
                    sanitized_params[key] = [six.text_type(v) for v in value]
                else:
                    sanitized_params[key] = six.text_type(value)
        return sanitized_params

    @_connection_checker
    def create_share(self, share, pool_name, create_share_name,
                     share_proto, **kwargs):
        """Create share."""
        LOG.debug('create_share_name: %s', create_share_name)

        params = {
            'wiz_func': 'share_create',
            'action': 'add_share',
            'vol_name': create_share_name,
            'vol_size': six.text_type(share['size']) + 'GB',
            'threshold': '80',
            'dedup': ('sha512'
                      if kwargs['qnap_deduplication'] is True
                      else 'off'),
            'compression': '1' if kwargs['qnap_compression'] is True else '0',
            'thin_pro': '1' if kwargs['qnap_thin_provision'] is True else '0',
            'cache': '1' if kwargs['qnap_ssd_cache'] is True else '0',
            'cifs_enable': '0' if share_proto == 'NFS' else '1',
            'nfs_enable': '0' if share_proto == 'CIFS' else '1',
            'afp_enable': '0',
            'ftp_enable': '0',
            'encryption': '0',
            'hidden': '0',
            'oplocks': '1',
            'sync': 'always',
            'userrw0': 'admin',
            'userrd_len': '0',
            'userrw_len': '1',
            'userno_len': '0',
            'access_r': 'setup_users',
            'path_type': 'auto',
            'recycle_bin': '1',
            'recycle_bin_administrators_only': '0',
            'pool_name': pool_name,
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/wizReq.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])

        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('ES_RET_CODE').text < '0':
            msg = _("Fail to create share %s on NAS.") % create_share_name
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)

        vol_list = root.find('func').find('ownContent').find('volumeList')
        vol_info_tree = vol_list.findall('volume')
        for vol in vol_info_tree:
            LOG.debug('Iterating vol name: %(name)s, index: %(id)s',
                      {'name': vol.find('volumeLabel').text,
                       'id': vol.find('volumeValue').text})
            if (create_share_name == vol.find('volumeLabel').text):
                LOG.debug('volumeLabel:%s', vol.find('volumeLabel').text)
                return vol.find('volumeValue').text

        return res_details['data']

    @_connection_checker
    def delete_share(self, vol_id, *args, **kwargs):
        """Execute delete share API."""
        params = {
            'func': 'volume_mgmt',
            'vol_remove': '1',
            'volumeID': vol_id,
            'stop_service': 'no',
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/disk/disk_manage.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])

        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            msg = _('Delete share id: %s failed') % vol_id
            raise exception.ShareBackendException(msg=msg)

    @_connection_checker
    def get_specific_poolinfo(self, pool_id):
        """Execute get_specific_poolinfo API."""
        params = {
            'store': 'poolInfo',
            'func': 'extra_get',
            'poolID': pool_id,
            'Pool_Info': '1',
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/disk/disk_manage.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)

        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            msg = _('get_specific_poolinfo failed')
            raise exception.ShareBackendException(msg=msg)

        pool_list = root.find('Pool_Index')
        pool_info_tree = pool_list.findall('row')
        for pool in pool_info_tree:
            if pool_id == pool.find('poolID').text:
                LOG.debug('poolID: %s', pool.find('poolID').text)
                return pool

    @_connection_checker
    def get_share_info(self, pool_id, **kwargs):
        """Execute get_share_info API."""
        for key, value in kwargs.items():
            LOG.debug('%(key)s = %(val)s',
                      {'key': key, 'val': value})

        params = {
            'store': 'poolVolumeList',
            'poolID': pool_id,
            'func': 'extra_get',
            'Pool_Vol_Info': '1',
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/disk/disk_manage.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)

        vol_list = root.find('Volume_Info')
        vol_info_tree = vol_list.findall('row')
        for vol in vol_info_tree:
            LOG.debug('Iterating vol name: %(name)s, index: %(id)s',
                      {'name': vol.find('vol_label').text,
                       'id': vol.find('vol_no').text})
            if 'vol_no' in kwargs:
                if kwargs['vol_no'] == vol.find('vol_no').text:
                    LOG.debug('vol_no:%s',
                              vol.find('vol_no').text)
                    return vol
            elif 'vol_label' in kwargs:
                if kwargs['vol_label'] == vol.find('vol_label').text:
                    LOG.debug('vol_label:%s', vol.find('vol_label').text)
                    return vol
        return None

    @_connection_checker
    def get_specific_volinfo(self, vol_id, **kwargs):
        """Execute get_specific_volinfo API."""
        params = {
            'store': 'volumeInfo',
            'volumeID': vol_id,
            'func': 'extra_get',
            'Volume_Info': '1',
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/disk/disk_manage.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)

        vol_list = root.find('Volume_Info')
        vol_info_tree = vol_list.findall('row')
        for vol in vol_info_tree:
            if vol_id == vol.find('vol_no').text:
                LOG.debug('vol_no: %s', vol.find('vol_no').text)
                return vol

    @_connection_checker
    def get_snapshot_info(self, **kwargs):
        """Execute get_snapshot_info API."""
        params = {
            'func': 'extra_get',
            'volumeID': kwargs['volID'],
            'snapshot_list': '1',
            'snap_start': '0',
            'snap_count': '100',
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/disk/snapshot.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            raise exception.ShareBackendException(msg=MSG_UNEXPECT_RESP)

        snapshot_list = root.find('SnapshotList')
        # if snapshot_list is None:
        if not snapshot_list:
            return None
        if ('snapshot_name' in kwargs):
            snapshot_tree = snapshot_list.findall('row')
            for snapshot in snapshot_tree:
                if (kwargs['snapshot_name'] ==
                        snapshot.find('snapshot_name').text):
                    LOG.debug('snapshot_name:%s', kwargs['snapshot_name'])
                    return snapshot
                if (snapshot is snapshot_tree[-1]):
                    return None

        return res_details['data']

    @_connection_checker
    def create_snapshot_api(self, volumeID, snapshot_name):
        """Execute CGI to create snapshot from source share."""
        LOG.debug('volumeID: %s', volumeID)
        LOG.debug('snapshot_name: %s', snapshot_name)

        params = {
            'func': 'create_snapshot',
            'volumeID': volumeID,
            'snapshot_name': snapshot_name,
            'expire_min': '0',
            'vital': '1',
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/disk/snapshot.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])

        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('ES_RET_CODE').text < '0':
            msg = _('Create snapshot failed')
            raise exception.ShareBackendException(msg=msg)

    @_connection_checker
    def delete_snapshot_api(self, snapshot_id):
        """Execute CGI to delete snapshot from snapshot_id."""
        params = {
            'func': 'del_snapshots',
            'snapshotID': snapshot_id,
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/disk/snapshot.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        # snapshot not exist
        if root.find('result').text == '-206021':
            LOG.warning('Snapshot id %s does not exist', snapshot_id)
            return
        # share not exist
        if root.find('result').text == '-200005':
            LOG.warning('Share of snapshot id %s does not exist', snapshot_id)
            return
        if root.find('result').text < '0':
            msg = _('Failed to delete snapshot.')
            raise exception.ShareBackendException(msg=msg)

    @_connection_checker
    def clone_snapshot(self, snapshot_id, new_sharename):
        """Execute CGI to clone snapshot as share."""
        params = {
            'func': 'clone_qsnapshot',
            'by_vol': '1',
            'snapshotID': snapshot_id,
            'new_name': new_sharename,
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/disk/snapshot.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            msg = _('Failed to clone snapshot.')
            raise exception.ShareBackendException(msg=msg)

    @_connection_checker
    def edit_share(self, share_dict):
        """Edit share properties."""
        LOG.debug('share_dict[sharename]: %s', share_dict['sharename'])

        params = {
            'wiz_func': 'share_property',
            'action': 'share_property',
            'sharename': share_dict['sharename'],
            'old_sharename': share_dict['old_sharename'],
            'vol_size': six.text_type(share_dict['new_size']) + 'GB',
            'dedup': 'sha512' if share_dict['deduplication'] else 'off',
            'compression': '1' if share_dict['compression'] else '0',
            'thin_pro': '1' if share_dict['thin_provision'] else '0',
            'cache': '1' if share_dict['ssd_cache'] else '0',
            'cifs_enable': '1' if share_dict['share_proto'] == 'CIFS' else '0',
            'nfs_enable': '1' if share_dict['share_proto'] == 'NFS' else '0',
            'afp_enable': '0',
            'ftp_enable': '0',
            'hidden': '0',
            'oplocks': '1',
            'sync': 'always',
            'recycle_bin': '1',
            'recycle_bin_administrators_only': '0',
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/priv/privWizard.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])

        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('ES_RET_CODE').text < '0':
            msg = _('Edit sharename %s failed') % share_dict['sharename']
            raise exception.ShareBackendException(msg=msg)

    @_connection_checker
    def get_host_list(self, **kwargs):
        """Execute get_host_list API."""
        params = {
            'module': 'hosts',
            'func': 'get_hostlist',
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/accessrights/accessrightsRequest.cgi?%s' %
               sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            raise exception.ShareBackendException(msg=MSG_UNEXPECT_RESP)

        host_list = root.find('content').find('host_list')
        # if host_list is None:
        if not host_list:
            return None

        return_hosts = []
        host_tree = host_list.findall('host')
        for host in host_tree:
            LOG.debug('host:%s', host)
            return_hosts.append(host)

        return return_hosts

    @_connection_checker
    def add_host(self, hostname, ipv4):
        """Execute add_host API."""
        params = {
            'module': 'hosts',
            'func': 'apply_addhost',
            'name': hostname,
            'ipaddr_v4': ipv4,
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/accessrights/accessrightsRequest.cgi?%s' %
               sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            raise exception.ShareBackendException(msg=MSG_UNEXPECT_RESP)

    @_connection_checker
    def edit_host(self, hostname, ipv4_list):
        """Execute edit_host API."""
        params = {
            'module': 'hosts',
            'func': 'apply_sethost',
            'name': hostname,
            'ipaddr_v4': ipv4_list,
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        # urlencode with True parameter to parse ipv4_list
        sanitized_params = urllib.parse.urlencode(sanitized_params, True)
        url = ('/cgi-bin/accessrights/accessrightsRequest.cgi?%s' %
               sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            raise exception.ShareBackendException(msg=MSG_UNEXPECT_RESP)

    @_connection_checker
    def delete_host(self, hostname):
        """Execute delete_host API."""
        params = {
            'module': 'hosts',
            'func': 'apply_delhost',
            'host_name': hostname,
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/accessrights/accessrightsRequest.cgi?%s' %
               sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            raise exception.ShareBackendException(msg=MSG_UNEXPECT_RESP)

    @_connection_checker
    def set_nfs_access(self, sharename, access, host_name):
        """Execute set_nfs_access API."""
        params = {
            'wiz_func': 'share_nfs_control',
            'action': 'share_nfs_control',
            'sharename': sharename,
            'access': access,
            'host_name': host_name,
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/priv/privWizard.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            raise exception.ShareBackendException(msg=MSG_UNEXPECT_RESP)


class QnapAPIExecutorTS(QnapAPIExecutor):
    """Makes QNAP API calls for TS NAS."""

    @_connection_checker
    def get_snapshot_info(self, **kwargs):
        """Execute get_snapshot_info API."""
        for key, value in kwargs.items():
            LOG.debug('%(key)s = %(val)s',
                      {'key': key, 'val': value})

        params = {
            'func': 'extra_get',
            'LUNIndex': kwargs['lun_index'],
            'smb_snapshot_list': '1',
            'smb_snapshot': '1',
            'snapshot_list': '1',
            'sid': self.sid,
        }
        sanitized_params = self._sanitize_params(params)

        sanitized_params = urllib.parse.urlencode(sanitized_params)
        url = ('/cgi-bin/disk/snapshot.cgi?%s' % sanitized_params)

        res_details = self._execute_and_get_response_details(self.ip, url)
        root = ET.fromstring(res_details['data'])
        if root.find('authPassed').text == '0':
            raise exception.ShareBackendException(msg=MSG_SESSION_EXPIRED)
        if root.find('result').text < '0':
            raise exception.ShareBackendException(msg=MSG_UNEXPECT_RESP)

        snapshot_list = root.find('SnapshotList')
        if snapshot_list is None:
            return None
        snapshot_tree = snapshot_list.findall('row')
        for snapshot in snapshot_tree:
            if (kwargs['snapshot_name'] ==
                    snapshot.find('snapshot_name').text):
                LOG.debug('snapshot_name:%s', kwargs['snapshot_name'])
                return snapshot

        return None
