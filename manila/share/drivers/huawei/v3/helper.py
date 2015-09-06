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
from xml.etree import ElementTree as ET

from oslo_log import log
from oslo_serialization import jsonutils
import six
from six.moves import http_cookiejar
from six.moves.urllib import request as urlreq  # pylint: disable=E0611

from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.share.drivers.huawei import constants
from manila import utils

LOG = log.getLogger(__name__)


class RestHelper(object):
    """Helper class for Huawei OceanStor V3 storage system."""

    def __init__(self, configuration):
        self.configuration = configuration
        self.init_http_head()

    def init_http_head(self):
        self.cookie = http_cookiejar.CookieJar()
        self.url = None
        self.headers = {
            "Connection": "keep-alive",
            "Content-Type": "application/json",
        }

    def do_call(self, url, data=None, method=None,
                calltimeout=constants.SOCKET_TIMEOUT):
        """Send requests to server.

        Send HTTPS call, get response in JSON.
        Convert response into Python Object and return it.
        """
        if self.url:
            url = self.url + url
        if "xx/sessions" not in url:
            LOG.debug('Request URL: %(url)s\n'
                      'Call Method: %(method)s\n'
                      'Request Data: %(data)s\n',
                      {'url': url,
                       'method': method,
                       'data': data})
        opener = urlreq.build_opener(urlreq.HTTPCookieProcessor(self.cookie))
        urlreq.install_opener(opener)
        result = None

        try:
            req = urlreq.Request(url, data, self.headers)
            if method:
                req.get_method = lambda: method
            res_temp = urlreq.urlopen(req, timeout=calltimeout)
            res = res_temp.read().decode("utf-8")

            LOG.debug('Response Data: %(res)s.', {'res': res})

        except Exception as err:
            LOG.error(_LE('\nBad response from server: %(url)s.'
                          ' Error: %(err)s'), {'url': url, 'err': err})
            res = '{"error":{"code":%s,' \
                  '"description":"Connect server error"}}' \
                  % constants.ERROR_CONNECT_TO_SERVER

        try:
            result = jsonutils.loads(res)
        except Exception as err:
            err_msg = (_('JSON transfer error: %s.') % err)
            LOG.error(err_msg)
            raise exception.InvalidInput(reason=err_msg)

        return result

    def login(self):
        """Login huawei array."""
        login_info = self._get_login_info()
        urlstr = login_info['RestURL']
        url_list = urlstr.split(";")
        deviceid = None
        for item_url in url_list:
            url = item_url.strip('').strip('\n') + "xx/sessions"
            data = jsonutils.dumps({"username": login_info['UserName'],
                                    "password": login_info['UserPassword'],
                                    "scope": "0"})
            self.init_http_head()
            result = self.do_call(url, data,
                                  calltimeout=constants.LOGIN_SOCKET_TIMEOUT)

            if((result['error']['code'] != 0)
               or ("data" not in result)
               or (result['data']['deviceid'] is None)):
                err_msg = (_("Login to %s failed, try another") % item_url)
                LOG.error(err_msg)
                continue

            LOG.debug('Login success: %(url)s\n',
                      {'url': item_url})
            deviceid = result['data']['deviceid']
            self.url = item_url + deviceid
            self.headers['iBaseToken'] = result['data']['iBaseToken']
            break

        if deviceid is None:
            err_msg = (_("All url Login fail"))
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

        return deviceid

    @utils.synchronized('huawei_manila', external=True)
    def call(self, url, data=None, method=None):
        """Send requests to server.

        if fail, try another RestURL
        """
        deviceid = None
        old_url = self.url
        result = self.do_call(url, data, method)
        error_code = result['error']['code']
        if(error_code == constants.ERROR_CONNECT_TO_SERVER
           or error_code == constants.ERROR_UNAUTHORIZED_TO_SERVER):
            err_msg = (_("Can't open the recent url, re-login."))
            LOG.error(err_msg)
            deviceid = self.login()

        if deviceid is not None:
            LOG.debug('Replace URL: \n'
                      'Old URL: %(old_url)s\n'
                      'New URL: %(new_url)s\n',
                      {'old_url': old_url,
                       'new_url': self.url})
            result = self.do_call(url, data, method)
        return result

    def _create_filesystem(self, fs_param):
        """Create file system."""
        url = "/filesystem"
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
        tree = ET.parse(filename)
        root = tree.getroot()
        RestURL = root.findtext('Storage/RestURL')
        logininfo['RestURL'] = RestURL.strip()

        # Prefix !$$$ means encoded already.
        prefix_name = '!$$$'
        need_encode = False
        for key in ['UserName', 'UserPassword']:
            node = root.find('Storage/%s' % key)
            if node.text.find(prefix_name) > -1:
                logininfo[key] = base64.b64decode(six.b(node.text[4:]))
            else:
                logininfo[key] = node.text
                node.text = prefix_name + six.text_type(
                    base64.b64encode(six.b(node.text)))
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
        share_url_type = self._get_share_url_type(share_proto)
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

        url = "/" + share_url_type
        data = jsonutils.dumps(filepath)

        result = self.call(url, data, "POST")

        msg = 'Create share error.'
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        return result['data']['ID']

    def _delete_share_by_id(self, share_id, share_url_type):
        """Delete share by share id."""
        url = "/" + share_url_type + "/" + share_id

        result = self.call(url, None, "DELETE")
        self._assert_rest_result(result, 'Delete share error.')

    def _delete_fs(self, fs_id):
        """Delete file system."""
        # Get available file system
        url = "/filesystem/" + fs_id

        result = self.call(url, None, "DELETE")
        self._assert_rest_result(result, 'Delete file system error.')

    def _get_cifs_service_status(self):
        url = "/CIFSSERVICE"
        result = self.call(url, None, "GET")

        msg = 'Get CIFS service status error.'
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        return result['data']['RUNNINGSTATUS']

    def _get_nfs_service_status(self):
        url = "/NFSSERVICE"
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
        url = "/NFSSERVICE"
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
        url = "/CIFSSERVICE"
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

    def _find_pool_type(self, poolinfo):
        root = self._read_xml()
        for pool_type in ('Thin', 'Thick'):
            pool_name_list = root.findtext(('Filesystem/%s_StoragePool'
                                            % pool_type))
            pool_name_list = pool_name_list.split(";")
            for pool_name in pool_name_list:
                pool_name = pool_name.strip().strip('\n')
                if poolinfo['name'] == pool_name:
                    poolinfo['type'] = pool_type

    def _find_pool_info(self, pool_name, result):
        if pool_name is None:
            return

        poolinfo = {}
        pool_name = pool_name.strip()
        for item in result.get('data', []):
            if pool_name == item['NAME'] and '2' == item['USAGETYPE']:
                poolinfo['name'] = pool_name
                poolinfo['ID'] = item['ID']
                poolinfo['CAPACITY'] = item['USERFREECAPACITY']
                poolinfo['TOTALCAPACITY'] = item['USERTOTALCAPACITY']
                poolinfo['CONSUMEDCAPACITY'] = item['USERCONSUMEDCAPACITY']
                self._find_pool_type(poolinfo)
                break

        return poolinfo

    def _find_all_pool_info(self):
        url = "/storagepool"
        result = self.call(url, None)

        msg = "Query resource pool error."
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        return result

    def _read_xml(self):
        """Open xml file and parse the content."""
        filename = self.configuration.manila_huawei_conf_file
        try:
            tree = ET.parse(filename)
            root = tree.getroot()
        except Exception as err:
            message = (_('Read Huawei config file(%(filename)s)'
                         ' for Manila error: %(err)s')
                       % {'filename': filename,
                          'err': err})
            LOG.error(message)
            raise exception.InvalidInput(reason=message)
        return root

    def _remove_access_from_share(self, access_id, access_type):
        url = "/" + access_type + "/" + access_id
        result = self.call(url, None, "DELETE")
        self._assert_rest_result(result, 'delete access from share error!')

    def _get_access_from_count(self, share_id, share_client_type):
        url_subfix = ("/" + share_client_type + "/count?"
                      + "filter=PARENTID::" + share_id)
        url = url_subfix
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
        url = ("/" + share_client_type + "?filter=PARENTID::"
               + share_id + "&range=[" + six.text_type(range_begin)
               + "-" + six.text_type(range_end) + "]")
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, 'Get access id by share error!')

        for item in result.get('data', []):
            if access_to == item['NAME']:
                return item['ID']

    def _allow_access_rest(self, share_id, access_to,
                           share_proto, access_level):
        """Allow access to the share."""
        access_type = self._get_share_client_type(share_proto)
        url = "/" + access_type

        access = {}
        if access_type == "NFS_SHARE_AUTH_CLIENT":
            access = {
                "TYPE": "16409",
                "NAME": access_to,
                "PARENTID": share_id,
                "ACCESSVAL": access_level,
                "SYNC": "0",
                "ALLSQUASH": "1",
                "ROOTSQUASH": "0",
            }
        elif access_type == "CIFS_SHARE_AUTH_CLIENT":
            access = {
                "NAME": access_to,
                "PARENTID": share_id,
                "PERMISSION": access_level,
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
            raise exception.InvalidInput(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))

        return share_client_type

    def _check_snapshot_id_exist(self, snap_id):
        """Check the snapshot id exists."""
        url_subfix = "/FSSNAPSHOT/" + snap_id

        url = url_subfix
        result = self.call(url, None, "GET")

        if result['error']['code'] == constants.MSG_SNAPSHOT_NOT_FOUND:
            return False
        elif result['error']['code'] == 0:
            return True
        else:
            err_str = "Check the snapshot id exists error!"
            err_msg = (_('%(err)s\nresult: %(res)s.') % {'err': err_str,
                                                         'res': result})
            LOG.error(err_msg)
            raise exception.InvalidShare(reason=err_msg)

    def _delete_snapshot(self, snap_id):
        """Deletes snapshot."""
        url = "/FSSNAPSHOT/%s" % snap_id
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

        url = "/FSSNAPSHOT"
        data = jsonutils.dumps(filepath)

        result = self.call(url, data, "POST")

        msg = 'Create a snapshot error.'
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        return result['data']['ID']

    def _get_share_by_name(self, share_name, share_url_type):
        """Segments to find share for a period of 100."""
        count = self._get_share_count(share_url_type)

        share = {}
        range_begin = 0
        while True:
            if count < 0 or share:
                break
            share = self._get_share_by_name_range(share_name,
                                                  range_begin,
                                                  share_url_type)
            range_begin += 100
            count -= 100

        return share

    def _get_share_count(self, share_url_type):
        """Get share count."""
        url = "/" + share_url_type + "/count"
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, 'Get share count error!')

        return int(result['data']['COUNT'])

    def _get_share_by_name_range(self, share_name,
                                 range_begin, share_url_type):
        """Get share by share name."""
        range_end = range_begin + 100
        url = ("/" + share_url_type + "?range=["
               + six.text_type(range_begin) + "-"
               + six.text_type(range_end) + "]")
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, 'Get share by name error!')

        share_path = self._get_share_path(share_name)

        share = {}
        for item in result.get('data', []):
            if share_path == item['SHAREPATH']:
                share['ID'] = item['ID']
                share['FSID'] = item['FSID']
                break

        return share

    def _get_share_url_type(self, share_proto):
        share_url_type = None
        if share_proto == 'NFS':
            share_url_type = "NFSHARE"
        elif share_proto == 'CIFS':
            share_url_type = "CIFSHARE"
        else:
            raise exception.InvalidInput(
                reason=(_('Invalid NAS protocol supplied: %s.')
                        % share_proto))

        return share_url_type

    def _get_fsid_by_name(self, share_name):
        url = "/FILESYSTEM?range=[0-8191]"
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, 'Get filesystem by name error!')
        sharename = share_name.replace("-", "_")

        for item in result.get('data', []):
            if sharename == item['NAME']:
                return item['ID']

    def _get_fs_info_by_id(self, fsid):
        url = "/filesystem/%s" % fsid
        result = self.call(url, None, "GET")

        msg = "Get filesystem info by id error!"
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

        fs = {}
        fs['HEALTHSTATUS'] = result['data']['HEALTHSTATUS']
        fs['RUNNINGSTATUS'] = result['data']['RUNNINGSTATUS']
        fs['CAPACITY'] = result['data']['CAPACITY']
        fs['ALLOCTYPE'] = result['data']['ALLOCTYPE']
        fs['POOLNAME'] = result['data']['PARENTNAME']
        return fs

    def _get_share_path(self, share_name):
        share_path = "/" + share_name.replace("-", "_") + "/"
        return share_path

    def _get_share_name_by_id(self, share_id):
        share_name = "share_" + share_id
        return share_name

    def _get_share_name_by_export_location(self, export_location, share_proto):
        export_location_split = None
        share_name = None
        share_ip = None
        if export_location:
            if share_proto == 'NFS':
                export_location_split = export_location.split(':/')
                if len(export_location_split) == 2:
                    share_name = export_location_split[1]
                    share_ip = export_location_split[0]
            elif share_proto == 'CIFS':
                export_location_split = export_location.split('\\')
                if (len(export_location_split) == 4 and
                        export_location_split[0] == "" and
                        export_location_split[1] == ""):
                    share_ip = export_location_split[2]
                    share_name = export_location_split[3]

        if share_name is None:
            raise exception.InvalidInput(
                reason=(_('No share with export location %s could be found.')
                        % export_location))

        root = self._read_xml()
        target_ip = root.findtext('Storage/LogicalPortIP')

        if target_ip:
            if share_ip != target_ip.strip():
                raise exception.InvalidInput(
                    reason=(_('The share IP %s is not configured.')
                            % share_ip))
        else:
            raise exception.InvalidInput(
                reason=(_('The config parameter LogicalPortIP is not set.')))

        return share_name

    def _get_snapshot_id(self, fs_id, snap_name):
        snapshot_id = (fs_id + "@" + "share_snapshot_"
                       + snap_name.replace("-", "_"))
        return snapshot_id

    def _change_share_size(self, fsid, new_size):
        url = "/filesystem/%s" % fsid

        capacityinfo = {
            "CAPACITY": new_size,
        }

        data = jsonutils.dumps(capacityinfo)
        result = self.call(url, data, "PUT")

        msg = "Change a share size error!"
        self._assert_rest_result(result, msg)
        self._assert_data_in_result(result, msg)

    def _change_fs_name(self, fsid, name):
        url = "/filesystem/%s" % fsid
        fs_param = {
            "NAME": name.replace("-", "_"),
        }
        data = jsonutils.dumps(fs_param)
        result = self.call(url, data, "PUT")

        msg = _("Change filesystem name error.")
        self._assert_rest_result(result, msg)

    def _get_partition_id_by_name(self, name):
        url = "/cachepartition"
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, _('Get partition by name error.'))

        if "data" in result:
            for item in result['data']:
                if name == item['NAME']:
                    return item['ID']
        return None

    def _add_fs_to_partition(self, fs_id, partition_id):
        url = "/filesystem/associate/cachepartition"
        data = jsonutils.dumps({"ID": partition_id,
                                "ASSOCIATEOBJTYPE": 40,
                                "ASSOCIATEOBJID": fs_id,
                                "TYPE": 268})
        result = self.call(url, data, "POST")

        self._assert_rest_result(result,
                                 _('Add filesystem to partition error.'))

    def _get_cache_id_by_name(self, name):
        url = "/SMARTCACHEPARTITION"
        result = self.call(url, None, "GET")
        self._assert_rest_result(result, _('Get cache by name error.'))

        if "data" in result:
            for item in result['data']:
                if name == item['NAME']:
                    return item['ID']
        return None

    def _add_fs_to_cache(self, fs_id, cache_id):
        url = "/SMARTCACHEPARTITION/CREATE_ASSOCIATE"
        data = jsonutils.dumps({"ID": cache_id,
                                "ASSOCIATEOBJTYPE": 40,
                                "ASSOCIATEOBJID": fs_id,
                                "TYPE": 273})
        result = self.call(url, data, "PUT")

        self._assert_rest_result(result, _('Add filesystem to cache error.'))
