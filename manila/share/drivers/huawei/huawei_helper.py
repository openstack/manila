# Copyright (c) 2014 Huawei Technologies Co., Ltd.
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

import base64
from xml import etree

from oslo_serialization import jsonutils
from oslo_utils import units
import six
from six.moves import http_cookiejar
from six.moves.urllib import request as urlreq  # pylint: disable=E0611

from manila import exception
from manila.i18n import _, _LE, _LW
from manila.openstack.common import log as logging
from manila.share.drivers.huawei import constants
from manila import utils

LOG = logging.getLogger(__name__)


class RestHelper():
    """Helper class for Huawei OceanStor V3 storage system."""

    def __init__(self, configuration):
        self.configuration = configuration
        self.cookie = http_cookiejar.CookieJar()
        self.url = None
        self.headers = {
            "Connection": "keep-alive",
            "Content-Type": "application/json",
        }

    def call(self, url, data=None, method=None):
        """Send requests to server.

        Send HTTPS call, get response in JSON.
        Convert response into Python Object and return it.
        """
        if "xx/sessions" not in url:
            LOG.debug('Request URL: %(url)s\n'
                      'Call Method: %(method)s\n'
                      'Request Data: %(data)s\n',
                      {'url': url,
                       'method': method,
                       'data': data})
        opener = urlreq.build_opener(urlreq.HTTPCookieProcessor(self.cookie))
        urlreq.install_opener(opener)

        try:
            req = urlreq.Request(url, data, self.headers)
            if method:
                req.get_method = lambda: method
            res_temp = urlreq.urlopen(req, timeout=constants.SOCKET_TIMEOUT)
            res = res_temp.read().decode("utf-8")

            LOG.debug('Response Data: %(res)s.', {'res': res})

        except Exception as err:
            LOG.error(_LE('Bad response from server: %s.') % err)
            raise err

        try:
            res_json = jsonutils.loads(res)
        except Exception as err:
            err_msg = (_('JSON transfer error: %s.') % err)
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

        return res_json

    def login(self):
        """Log in huawei array."""
        login_info = self._get_login_info()
        url = login_info['RestURL'] + "xx/sessions"
        data = jsonutils.dumps({"username": login_info['UserName'],
                                "password": login_info['UserPassword'],
                                "scope": "0"})
        result = self.call(url, data)
        if (result['error']['code'] != 0) or ("data" not in result):
            err_msg = (_("Login error, reason is %s.") % result)
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

        deviceid = result['data']['deviceid']
        self.url = login_info['RestURL'] + deviceid
        self.headers['iBaseToken'] = result['data']['iBaseToken']
        return deviceid

    def _create_filesystem(self, fs_param):
        """Create file system."""
        url = self.url + "/filesystem"
        data = jsonutils.dumps(fs_param)
        result = self.call(url, data)

        msg = 'Create filesystem error.'
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        return result['data']['ID']

    def _assert_rest_result(self, result, err_str):
        if result['error']['code'] != 0:
            err_msg = (_('%(err)s\nresult: %(res)s.') % {'err': err_str,
                                                         'res': result})
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

    def _assert_data_in_result(self, result, msg):
        if "data" not in result:
            err_msg = (_('%s "data" was not in result.') % msg)
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

    def _get_login_info(self):
        """Get login IP, username and password from config file."""
        logininfo = {}
        filename = self.configuration.manila_huawei_conf_file
        tree = etree.ElementTree.parse(filename)
        root = tree.getroot()
        RestURL = root.findtext('Storage/RestURL')
        logininfo['RestURL'] = RestURL.strip()

        # Prefix !$$$ means encoded already.
        prefix_name = '!$$$'
        need_encode = False
        for key in ['UserName', 'UserPassword']:
            node = root.find('Storage/%s' % key)
            node_text = node.text
            if node_text.find(prefix_name) > -1:
                logininfo[key] = base64.b64decode(node_text[4:])
            else:
                logininfo[key] = node_text
                node.text = prefix_name + base64.b64encode(node_text)
                need_encode = True
        if need_encode:
            self._change_file_mode(filename)
            try:
                tree.write(filename, 'UTF-8')
            except Exception as err:
                err_msg = (_('File write error %s.') % err)
                LOG.error(err_msg)
                raise exception.InvalidShare(reason=err_msg)

        return logininfo

    def _change_file_mode(self, filepath):
        try:
            utils.execute('chmod', '666', filepath, run_as_root=True)

        except Exception as err:
            LOG.error(_LE('Bad response from change file: %s.') % err)
            raise err

    def _create_share(self, share_name, fs_id, share_proto):
        """Create a share."""
        share_type = self._get_share_type(share_proto)
        share_path = self._get_share_path(share_name)

        filepath = {}
        if share_proto == 'NFS':
            filepath = {
                "DESCRIPTION": "",
                "FSID": fs_id,
                "SHAREPATH": share_path,
            }
        elif share_proto == 'CIFS':
            filepath = {
                "SHAREPATH": share_path,
                "DESCRIPTION": "",
                "ABEENABLE": "false",
                "ENABLENOTIFY": "true",
                "ENABLEOPLOCK": "true",
                "NAME": share_name.replace("-", "_"),
                "FSID": fs_id,
                "TENANCYID": "0",
            }
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))

        url = self.url + "/" + share_type
        data = jsonutils.dumps(filepath)

        result = self.call(url, data, "POST")

        msg = 'Create share error.'
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        return result['data']['ID']

    def _delete_share(self, share_name, share_proto):
        """Delete share."""
        share_type = self._get_share_type(share_proto)
        share = self._get_share_by_name(share_name, share_type)

        if not share:
            LOG.warn(_LW('The share was not found. share_name:%s'), share_name)
            fsid = self._get_fsid_by_name(share_name)
            if fsid:
                self._delete_fs(fsid)
                return
            LOG.warn(_LW('The filesystem was not found.'))
            return

        share_id = share['ID']
        share_fs_id = share['FSID']

        if share_id:
            self._delete_share_by_id(share_id, share_type)

        if share_fs_id:
            self._delete_fs(share_fs_id)

        return share

    def _delete_share_by_id(self, share_id, share_type):
        """Delete share by share id."""
        url = self.url + "/" + share_type + "/" + share_id

        result = self.call(url, None, "DELETE")
        self._assert_rest_result(result, 'Delete share error.')

    def _delete_fs(self, fs_id):
        """Delete file system."""
        # Get available file system
        url = self.url + "/filesystem/" + fs_id

        result = self.call(url, None, "DELETE")
        self._assert_rest_result(result, 'Delete file system error.')

    def _get_cifs_service_status(self):
        url = self.url + "/CIFSSERVICE"
        result = self.call(url, None, "GET")

        msg = 'Get CIFS service status error.'
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        return result['data']['RUNNINGSTATUS']

    def _get_nfs_service_status(self):
        url = self.url + "/NFSSERVICE"
        result = self.call(url, None, "GET")

        msg = 'Get NFS service status error.'
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        service = {}

        service['RUNNINGSTATUS'] = result['data']['RUNNINGSTATUS']
        service['SUPPORTV3'] = result['data']['SUPPORTV3']
        service['SUPPORTV4'] = result['data']['SUPPORTV4']
        return service

    def _start_nfs_service_status(self):
        url = self.url + "/NFSSERVICE"
        nfsserviceinfo = {
            "NFSV4DOMAIN": "localdomain",
            "RUNNINGSTATUS": "2",
            "SUPPORTV3": 'true',
            "SUPPORTV4": 'true',
            "TYPE": "16452",
        }

        data = jsonutils.dumps(nfsserviceinfo)
        result = self.call(url, data, "PUT")

        self._assert_rest_result(result, 'Start NFS service error.')

    def _start_cifs_service_status(self):
        url = self.url + "/CIFSSERVICE"
        cifsserviceinfo = {
            "ENABLENOTIFY": "true",
            "ENABLEOPLOCK": "true",
            "ENABLEOPLOCKLEASE": "false",
            "GUESTENABLE": "false",
            "OPLOCKTIMEOUT": "35",
            "RUNNINGSTATUS": "2",
            "SECURITYMODEL": "3",
            "SIGNINGENABLE": "false",
            "SIGNINGREQUIRED": "false",
            "TYPE": "16453",
        }

        data = jsonutils.dumps(cifsserviceinfo)
        result = self.call(url, data, "PUT")

        self._assert_rest_result(result, 'Start CIFS service error.')

    def _find_pool_info(self):
        root = self._read_xml()
        pool_name = root.findtext('Filesystem/StoragePool')
        if not pool_name:
            err_msg = (_("Invalid resource pool: %s.") % pool_name)
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        url = self.url + "/storagepool"
        result = self.call(url, None)
        self._assert_rest_result(result, 'Query resource pool error.')

        poolinfo = {}
        pool_name = pool_name.strip()
        if "data" in result:
            for item in result['data']:
                if pool_name == item['NAME']:
                    poolinfo['ID'] = item['ID']
                    poolinfo['CAPACITY'] = item['USERFREECAPACITY']
                    poolinfo['TOTALCAPACITY'] = item['USERTOTALCAPACITY']
                    break

        return poolinfo

    def _get_capacity(self):
        """Get free capacity and total capacity of the pools."""
        poolinfo = self._find_pool_info()
        pool_capacity = {
            'total_capacity': 0.0,
            'free_capacity': 0.0
        }

        if poolinfo:
            total = int(poolinfo['TOTALCAPACITY']) / units.Mi / 2
            free = int(poolinfo['CAPACITY']) / units.Mi / 2
            pool_capacity['total_capacity'] = total
            pool_capacity['free_capacity'] = free

        return pool_capacity

    def _read_xml(self):
        """Open xml file and parse the content."""
        filename = self.configuration.manila_huawei_conf_file
        try:
            tree = etree.ElementTree.parse(filename)
            root = tree.getroot()
        except Exception as err:
            LOG.error(_LE('Read Huawei config file(%(filename)s)'
                      ' for Manila error: %(err)s') %
                      {'filename': filename,
                       'err': err})
            raise err
        return root

    def _init_filesys_para(self, name, size):
        """Init basic filesystem parameters."""
        poolinfo = self._find_pool_info()
        fileparam = {
            "NAME": name.replace("-", "_"),
            "DESCRIPTION": "",
            "ALLOCTYPE": 1,
            "CAPACITY": size,
            "PARENTID": poolinfo['ID'],
            "INITIALALLOCCAPACITY": units.Ki * 20,
            "PARENTTYPE": 216,
            "SNAPSHOTRESERVEPER": 20,
            "INITIALDISTRIBUTEPOLICY": 0,
            "ISSHOWSNAPDIR": 'true',
            "RECYCLESWITCH": 0,
            "RECYCLEHOLDTIME": 15,
            "RECYCLETHRESHOLD": 0,
            "RECYCLEAUTOCLEANSWITCH": 0,
        }

        root = self._read_xml()
        fstype = root.findtext('FILESYSTEM/AllocType')
        if fstype:
            fstype = fstype.strip()
            if fstype == 'Thin':
                fileparam['ALLOCTYPE'] = 1
            elif fstype == 'Thick':
                fileparam['ALLOCTYPE'] = 0
            else:
                err_msg = (_(
                    'Config file is wrong. Filesystem Type must be "Thin"'
                    ' or "Thick". AllocType:%(fetchtype)s') %
                    {'fetchtype': fstype})
                LOG.error(err_msg)
                raise exception.InvalidShare(reason=err_msg)
        return fileparam

    def _deny_access(self, share_name, access, share_proto):
        """Deny access to share."""
        share_type = self._get_share_type(share_proto)
        share_client_type = self._get_share_client_type(share_proto)
        access_type = access['access_type']
        if share_proto == 'NFS' and access_type != 'ip':
            LOG.warn(_LW('Only ip access type allowed.'))
            return

        if share_proto == 'CIFS' and access_type != 'user':
            LOG.warn(_LW('Only user access type allowed.'))
            return

        access_to = access['access_to']
        share = self._get_share_by_name(share_name, share_type)
        if not share:
            LOG.warn(_LW('Can not get share. share_name: %s'), share_name)
            return

        access_id = self._get_access_from_share(share['ID'], access_to,
                                                share_client_type)
        if not access_id:
            LOG.warn(_LW('Can not get access id from share. share_name: %s'),
                     share_name)
            return

        self._remove_access_from_share(access_id, share_client_type)

    def _remove_access_from_share(self, access_id, access_type):
        url = self.url + "/" + access_type + "/" + access_id
        result = self.call(url, None, "DELETE")
        self._assert_rest_result(result, 'delete access from share error!')

    def _get_access_from_count(self, share_id, share_client_type):
        url_subfix = ("/" + share_client_type + "/count?"
                      + "filter=PARENTID::" + share_id)
        url = self.url + url_subfix
        result = self.call(url, None, "GET")

        msg = "Get access count by share error!"
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        return int(result['data']['COUNT'])

    def _get_access_from_share(self, share_id, access_to, share_client_type):
        """Segments to find access for a period of 100."""
        count = self._get_access_from_count(share_id, share_client_type)

        access_id = None
        range_begin = 0
        while True:
            if count < 0 or access_id:
                break
            access_id = self._get_access_from_share_range(share_id,
                                                          access_to,
                                                          range_begin,
                                                          share_client_type)
            range_begin += 100
            count -= 100

        return access_id

    def _get_access_from_share_range(self, share_id,
                                     access_to, range_begin,
                                     share_client_type):
        range_end = range_begin + 100
        url = (self.url + "/" + share_client_type + "?filter=PARENTID::"
               + share_id + "&range=[" + six.text_type(range_begin)
               + "-" + six.text_type(range_end) + "]")
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, 'Get access id by share error!')

        if "data" in result:
            for item in result['data']:
                if access_to == item['NAME']:
                    return item['ID']

    def _allow_access(self, share_name, access, share_proto):
        """Allow access to the share."""

        share_type = self._get_share_type(share_proto)
        access_type = access['access_type']
        if share_proto == 'NFS' and access_type != 'ip':
            message = _('Only IP access type is allowed for NFS shares.')
            raise exception.InvalidShareAccess(reason=message)

        if share_proto == 'CIFS' and access_type != 'user':
            message = _('Only USER access type is allowed for CIFS shares.')
            raise exception.InvalidShareAccess(reason=message)

        access_to = access['access_to']

        share = self._get_share_by_name(share_name, share_type)
        if not share:
            err_msg = (_('Can not get share.'))
            LOG.error(err_msg)
            raise exception.InvalidShareAccess(reason=err_msg)

        share_id = share['ID']
        self._allow_access_rest(share_id, access_to, share_proto)

    def _allow_access_rest(self, share_id, access_to, share_proto):
        """Allow access to the share."""
        access_type = self._get_share_client_type(share_proto)
        url = self.url + "/" + access_type

        access = {}
        if access_type == "NFS_SHARE_AUTH_CLIENT":
            access = {
                "TYPE": "16409",
                "NAME": access_to,
                "PARENTID": share_id,
                "ACCESSVAL": "1",
                "SYNC": "0",
                "ALLSQUASH": "1",
                "ROOTSQUASH": "0",
            }
        elif access_type == "CIFS_SHARE_AUTH_CLIENT":
            access = {
                "NAME": access_to,
                "PARENTID": share_id,
                "PERMISSION": "5",
                "DOMAINTYPE": "2",
            }
        data = jsonutils.dumps(access)
        result = self.call(url, data, "POST")

        msg = 'Allow access error.'
        self._assert_rest_result(result, msg)

    def _get_share_client_type(self, share_proto):
        share_client_type = None
        if share_proto == 'NFS':
            share_client_type = "NFS_SHARE_AUTH_CLIENT"
        elif share_proto == 'CIFS':
            share_client_type = "CIFS_SHARE_AUTH_CLIENT"
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))

        return share_client_type

    def _get_snapshot_id_by_name(self, sharefsid, snap_name):
        """Get snapshot id in Array by snapshot name."""

        url_subfix = ("/FSSNAPSHOT?TYPE=48&"
                      "PARENTID=%s&&sortby=TIMESTAMP,d&"
                      "range=[0-2000]" % sharefsid)

        url = self.url + url_subfix
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, 'Get snapshot id by name error!')

        snapshot_name = "share_snapshot_" + snap_name.replace("-", "_")
        snapshot_id = None
        if "data" in result:
            for item in result['data']:
                if snapshot_name == item['NAME']:
                    snapshot_id = item['ID']
                    break

        return snapshot_id

    def _delete_snapshot(self, snap_id):
        """Deletes snapshot."""
        url = self.url + "/FSSNAPSHOT/%s" % snap_id
        data = jsonutils.dumps({"TYPE": "48", "ID": snap_id})
        result = self.call(url, data, "DELETE")
        self._assert_rest_result(result, 'Delete snapshot error.')

    def _create_snapshot(self, sharefsid, snapshot_name):
        """Create a snapshot."""
        filepath = {
            "PARENTTYPE": "40",
            "TYPE": "48",
            "PARENTID": sharefsid,
            "NAME": snapshot_name.replace("-", "_"),
            "DESCRIPTION": "",
        }

        url = self.url + "/FSSNAPSHOT"
        data = jsonutils.dumps(filepath)

        result = self.call(url, data, "POST")

        msg = 'Create a snapshot error.'
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        return result['data']['ID']

    def _get_share_by_name(self, share_name, share_type):
        """Segments to find share for a period of 100."""
        count = self._get_share_count(share_type)

        share = {}
        range_begin = 0
        while True:
            if count < 0 or share:
                break
            share = self._get_share_by_name_range(share_name,
                                                  range_begin,
                                                  share_type)
            range_begin += 100
            count -= 100

        return share

    def _get_share_count(self, share_type):
        """Get share count."""
        url = self.url + "/" + share_type + "/count"
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, 'Get share count error!')

        return int(result['data']['COUNT'])

    def _get_share_by_name_range(self, share_name,
                                 range_begin, share_type):
        """Get share by share name."""
        range_end = range_begin + 100
        url = (self.url + "/" + share_type + "?range=["
               + six.text_type(range_begin) + "-"
               + six.text_type(range_end) + "]")
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, 'Get share by name error!')

        share_path = self._get_share_path(share_name)

        share = {}
        if "data" in result:
            for item in result['data']:
                if share_path == item['SHAREPATH']:
                    share['ID'] = item['ID']
                    share['FSID'] = item['FSID']
                    break

        return share

    def _get_share_type(self, share_proto):
        share_type = None
        if share_proto == 'NFS':
            share_type = "NFSHARE"
        elif share_proto == 'CIFS':
            share_type = "CIFSHARE"
        else:
            raise exception.InvalidShare(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))

        return share_type

    def _get_fsid_by_name(self, share_name):
        url = self.url + "/FILESYSTEM?range=[0-8191]"
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, 'Get filesystem by name error!')
        sharename = share_name.replace("-", "_")

        if "data" in result:
            for item in result['data']:
                if sharename == item['NAME']:
                    return item['ID']

    def _get_fs_info_by_id(self, fsid):
        url = self.url + "/filesystem/%s" % fsid
        result = self.call(url, None, "GET")

        msg = "Get filesystem info by id error!"
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        fs = {}
        fs['HEALTHSTATUS'] = result['data']['HEALTHSTATUS']
        fs['RUNNINGSTATUS'] = result['data']['RUNNINGSTATUS']
        return fs

    def allocate_container(self, share_name, size):
        """Creates filesystem associated to share by name."""
        fileParam = self._init_filesys_para(share_name, size)
        fsid = self._create_filesystem(fileParam)
        return fsid

    def _check_conf_file(self):
        """Check the config file, make sure the essential items are set."""
        root = self._read_xml()
        resturl = root.findtext('Storage/RestURL')
        username = root.findtext('Storage/UserName')
        pwd = root.findtext('Storage/UserPassword')
        product = root.findtext('Storage/Product')
        pool_node = root.findall('Filesystem/StoragePool')

        if product != "V3":
            err_msg = (_(
                '_check_conf_file: Config file invalid. '
                'Product must be set to V3.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        if (not resturl) or (not username) or (not pwd):
            err_msg = (_(
                '_check_conf_file: Config file invalid. RestURL,'
                ' UserName and UserPassword must be set.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

        if not pool_node:
            err_msg = (_(
                '_check_conf_file: Config file invalid. '
                'StoragePool must be set.'))
            LOG.error(err_msg)
            raise exception.InvalidInput(err_msg)

    def _get_share_path(self, share_name):
        share_path = "/" + share_name.replace("-", "_") + "/"
        return share_path

    def _get_share_name_by_id(self, share_id):
        share_name = "share_" + share_id
        return share_name

    def _check_service(self):
        running_status = self._get_cifs_service_status()
        if running_status != constants.STATUS_SERVICE_RUNNING:
            self._start_cifs_service_status()

        service = self._get_nfs_service_status()
        if ((service['RUNNINGSTATUS'] != constants.STATUS_SERVICE_RUNNING) or
           (service['SUPPORTV3'] == 'false') or
           (service['SUPPORTV4'] == 'false')):
            self._start_nfs_service_status()
