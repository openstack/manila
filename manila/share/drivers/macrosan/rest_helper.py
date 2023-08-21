# Copyright (c) 2022 MacroSAN Technologies Co., Ltd.
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

import requests

from oslo_log import log

from manila import exception
from manila.i18n import _
from manila.share.drivers.macrosan import macrosan_constants as constants
from manila import utils

LOG = log.getLogger(__name__)


class RestHelper(object):
    def __init__(self, configuration):
        self.configuration = configuration
        self._protocol = self.configuration.macrosan_nas_http_protocol
        self._ip = self.configuration.macrosan_nas_ip
        self._port = self.configuration.macrosan_nas_port
        self._prefix = self.configuration.macrosan_nas_prefix
        self._token = None
        self._username = self.configuration.macrosan_nas_username
        self._password = self.configuration.macrosan_nas_password
        self.request_timeout = self.configuration.macrosan_timeout
        self.ssl_verify = self.configuration.macrosan_ssl_cert_verify
        if not self.ssl_verify:
            # Suppress the Insecure request warnings
            requests.packages.urllib3.disable_warnings(
                requests.packages.urllib3.exceptions.InsecureRequestWarning)

    @utils.synchronized('macrosan_manila')
    def call(self, url, data, method):
        """Send requests.

        If token is expired,re-login.
        """
        header = {'Authorization': self._token}
        if self._token is None:
            self.login()

        result = self.do_request(url, data, method, header)
        if result['code'] == constants.TOKEN_EXPIRED:
            LOG.error("Token is expired, re-login.")
            self.login()
            # token refresh, Re-assign
            header['Authorization'] = self._token
            result = self.do_request(url, data, method, header)
        elif (result['code'] == constants.TOKEN_FORMAT_ERROR or
              result['code'] == constants.TOKEN_VERIFY_FAILED or
              result['code'] == constants.TOKEN_REQUIRED):
            msg = _('Token authentication error.')
            LOG.error(msg)
            raise exception.MacrosanBackendExeption(msg)
        return result

    def do_request(self, url, data, method, header=None):
        final_url = (f'{self._protocol}://{self._ip}:{self._port}/'
                     f'{self._prefix}/{url}')
        LOG.debug(f'Request URL: {final_url}, Method: {method}, Data: {data}')

        if method == 'POST':
            res = requests.post(final_url, data=data, headers=header,
                                timeout=self.request_timeout,
                                verify=self.ssl_verify)
        elif method == 'GET':
            res = requests.get(final_url, data=data, headers=header,
                               timeout=self.request_timeout,
                               verify=self.ssl_verify)
        elif method == 'PUT':
            res = requests.put(final_url, data=data, headers=header,
                               timeout=self.request_timeout,
                               verify=self.ssl_verify)
        elif method == 'DELETE':
            res = requests.delete(final_url, data=data, headers=header,
                                  timeout=self.request_timeout,
                                  verify=self.ssl_verify)
        else:
            msg = (_("Request method %s invalid.") % method)
            raise exception.ShareBackendException(msg=msg)

        code = res.status_code
        if code != 200:
            msg = (_('Code: %(code)s, URL: %(url)s, Message: %(msg)s')
                   % {'code': res.status_code,
                      'url': final_url,
                      'msg': res.text})
            LOG.error(msg)
            raise exception.NetworkException(msg)
        response = res.json()
        LOG.debug('CODE: %(code)s, RESPONSE: %(response)s',
                  {'code': code, 'response': response})
        return response

    def login(self):
        """Login array and return token."""
        url = 'rest/token'

        data = {'userName': self._username,
                'userPasswd': self._password}
        result = self.do_request(url, data, 'POST')
        if result['code'] != 0:
            msg = f"Login failed. code: {result['code']}"
            msg = _(msg)
            LOG.error(msg)
            raise exception.ShareBackendException(msg=msg)
        LOG.debug(f'Login successful. URL {self._ip}\n')
        self._token = result['data']

    def _assert_result_code(self, result, msg):
        if (result['code'] != constants.CODE_SUCCESS
                and result['code'] != constants.CODE_NOT_FOUND):
            error_msg = (_('%(err)s\nresult: %(res)s.') % {'err': msg,
                                                           'res': result})
            LOG.error(error_msg)
            raise exception.ShareBackendException(msg=error_msg)

    def _assert_result_data(self, result, msg):
        if "data" not in result:
            error_msg = (_('Error:"data" not in result. %s') % msg)
            LOG.error(error_msg)
            raise exception.ShareBackendException(msg=error_msg)

    def _create_nfs_share(self, share_path):
        url = 'rest/nfsShare'
        # IPv4 Address Blocks Reserved for Documentation
        params = {
            'path': share_path,
            'authority': 'ro',
            'accessClient': '192.0.2.0',
        }
        result = self.call(url, params, 'POST')

        msg = 'Failed to create a nfs share.'
        self._assert_result_code(result, msg)

    def _get_nfs_share(self, share_path):
        # GET method: param need be after url
        url = f'rest/nfsShare?path={share_path}'
        result = self.call(url, None, 'GET')

        msg = 'Failed to get nfs share.'
        self._assert_result_code(result, msg)
        return result['data']

    def _delete_nfs_share(self, share_path):
        url = f'rest/nfsShare?path={share_path}'
        result = self.call(url, None, 'DELETE')

        msg = 'Failed to delete nfs share.'
        self._assert_result_code(result, msg)

    def _create_cifs_share(self, share_name, share_path,
                           rw_list, rw_list_type):
        url = 'rest/cifsShare'

        params = {
            'path': share_path,
            'cifsName': share_name,
            'cifsDescription': '',
            'RoList': [],
            'RoListType': [],
            'RwList': rw_list,
            'RwListType': rw_list_type,
            'allowList': [],
            'denyList': [],
        }
        result = self.call(url, params, 'POST')

        msg = 'Failed to create a CIFS share.'
        self._assert_result_code(result, msg)

    def _get_cifs_share(self, share_path):
        url = f'rest/cifsShare?path={share_path}'
        result = self.call(url, None, 'GET')

        msg = 'Failed to get the cifs share.'
        self._assert_result_code(result, msg)
        return result['data']

    def _delete_cifs_share(self, share_name, share_path):
        url = f'rest/cifsShare?path={share_path}&cifsName={share_name}'
        result = self.call(url, None, 'DELETE')
        msg = 'Failed to delete the cifs share.'

        self._assert_result_code(result, msg)

    def _update_share_size(self, fs_name, new_size):
        url = f'rest/filesystem/{fs_name}'

        params = {
            'capacity': new_size,
        }

        result = self.call(url, params, 'PUT')
        msg = 'Failed to update the filesystem size.'

        self._assert_result_code(result, msg)

    def _create_filesystem(self, fs_name, pool_name, filesystem_quota):
        url = 'rest/filesystem'
        fsinfo = {
            'fsName': fs_name,
            'poolName': pool_name,
            'createType': '0',
            'fileSystemQuota': filesystem_quota,
            'fileSystemReserve': filesystem_quota,
            'wormStatus': 0,
            'defaultTimeStatus': 0,
            'defaultTimeNum': 0,
            'defaultTimeUnit': 'year',
            'isAutoLock': 0,
            'isAutoDelete': 0,
            'lockTime': 0
        }
        result = self.call(url, fsinfo, 'POST')

        msg = 'Failed to create the filesystem.'
        self._assert_result_code(result, msg)

    def _delete_filesystem(self, fs_name):
        """Delete filesystem"""
        url = f'rest/filesystem/{fs_name}'
        result = self.call(url, None, 'DELETE')

        msg = 'Failed to delete the filesystem.'
        self._assert_result_code(result, msg)

    def _get_filesystem(self, fs_name):
        """Get filesystem """
        url = f'rest/filesystem/{fs_name}'
        result = self.call(url, None, 'GET')

        msg = 'Failed to get the filesystem.'
        self._assert_result_code(result, msg)

        return result['data']

    def _create_filesystem_dir(self, share_path):
        url = 'rest/fileDir'
        slash = share_path.index(r'/', 1)
        dir_info = {
            'path': share_path[0: slash],
            'dirName': share_path[slash + 1:],
        }
        result = self.call(url, dir_info, 'POST')

        msg = 'Failed to create the filesystem directory.'
        self._assert_result_code(result, msg)

    def _delete_filesystem_dir(self, share_path):
        slash = share_path.index(r'/', 1)
        url = f'rest/fileDir?path={share_path[0: slash]}' \
              f'&dirName={share_path[slash + 1:]}'

        result = self.call(url, None, 'DELETE')

        msg = 'Failed to delete the filesystem directory.'
        self._assert_result_code(result, msg)

    def _allow_access_rest(self, share_path, access_to,
                           access_level, share_proto):
        """Allow access to the share."""
        if share_proto == 'NFS':
            self._allow_nfs_access_rest(share_path, access_to, access_level)
        elif share_proto == 'CIFS':
            self._allow_cifs_access_rest(share_path, access_to, access_level)
        else:
            raise exception.InvalidInput(
                reason=(_('Invalid Nas protocol: %s.') % share_proto))

    def _allow_nfs_access_rest(self, share_path, access_to, access_level):
        url = 'rest/nfsShareClient'
        access = {
            'path': share_path,
            'client': access_to,
            'authority': access_level,
        }
        result = self.call(url, access, 'POST')

        msg = 'Failed to allow access to the NFS share.'
        self._assert_result_code(result, msg)

    def _allow_cifs_access_rest(self, share_path, access_to, access_level):
        url = 'rest/cifsShareClient'
        ug_type = {
            'localUser': '0',
            'localGroup': '1',
            'adUser': '2',
            'adGroup': '3',
        }

        msg = 'Failed to allow access to the CIFS share.'
        access_info = (f'Access info (access_to: {access_to},'
                       f'access_level: {access_level},'
                       f'path: {share_path}.)')

        def send_rest(rest_access_to, rest_ug_type):
            access = {
                'path': share_path,
                'right': access_level,
                'ugName': rest_access_to,
                'ugType': rest_ug_type,
            }
            result = self.call(url, access, 'POST')
            err_code = result['code']
            if err_code == constants.CODE_SUCCESS:
                return True
            elif err_code != constants.CODE_SOURCE_NOT_EXIST:
                self._assert_result_code(result, msg)
            return False

        if '/' not in access_to:
            # First, try to add local user access
            LOG.debug('Attempting to add local user access. %s', access_info)
            if send_rest(access_to, ug_type['localUser']):
                return
            # Second,If add local user access failed,
            # try to add local group access
            LOG.debug('Failed add local user access,'
                      ' attempting to add local group access. %s', access_info)
            if send_rest(access_to, ug_type['localGroup']):
                return
        else:
            str = access_to.index('/')
            access_to = access_to[str + 1:]
            # First, add domain user access
            LOG.debug('Attempting to add domain user access. %s', access_info)
            if send_rest(access_to, ug_type['adUser']):
                return
            # Second, if add domain user access failed,
            # try to add domain group access.
            LOG.debug('Failed add domain user access, '
                      'attempting to add domain group access. %s', access_info)
            if send_rest(access_to, ug_type['adGroup']):
                return

        raise exception.InvalidShare(reason=msg)

    def _get_access_from_nfs_share(self, path, clientName):
        url = f'rest/nfsShareClient?path={path}&client={clientName}'

        result = self.call(url, None, 'GET')
        msg = 'Failed to get share NFS access.'

        self._assert_result_code(result, msg)
        share_client = None
        if result['data'] is not None:
            share_client = {}
            share_client['path'] = result['data']['path']
            share_client['clientName'] = result['data']['clientName']
            share_client['accessRight'] = result['data']['accessRight']

        return share_client

    def _get_access_from_cifs_share(self, share_path, access_to,
                                    ug_input_type=None):

        ug_type = {
            'localUser': '0',
            'localGroup': '1',
            'adUser': '2',
            'adGroup': '3',
        }

        msg = 'Failed to get share cifs access.'
        access_info = (f'Access info (access_to: {access_to},'
                       f'path: {share_path}.)')

        def send_rest(access_to, ug_type):
            url = f'rest/cifsShareClient?path={share_path}' \
                  f'&ugName={access_to}&ugType={ug_type}'
            result = self.call(url, None, 'GET')
            self._assert_result_code(result, msg)
            return result

        share_client = None
        if ug_input_type is not None:
            ret = send_rest(access_to, ug_input_type)
            if ret['data']:
                share_client = {}
                share_client['path'] = ret['data']['path']
                share_client['ugName'] = ret['data']['ugName']
                share_client['ugType'] = ret['data']['ugType']
                share_client['accessRight'] = ret['data']['accessRight']

            return share_client
        elif '/' not in access_to:
            LOG.debug('Attempting to get local user access. %s', access_info)
            user_ret = send_rest(access_to, ug_type['localUser'])
            if user_ret['code'] == constants.CODE_NOT_FOUND:
                return share_client
            if user_ret['data']:
                share_client = {}
                share_client['path'] = user_ret['data']['path']
                share_client['ugName'] = user_ret['data']['ugName']
                share_client['ugType'] = user_ret['data']['ugType']
                share_client['accessRight'] = user_ret['data']['accessRight']
                return share_client

            LOG.debug('Failed get local user access,'
                      ' attempting to get local group access. %s', access_info)
            group_ret = send_rest(access_to, ug_type['localGroup'])
            if group_ret['data']:
                share_client = {}
                share_client['path'] = group_ret['data']['path']
                share_client['ugName'] = group_ret['data']['ugName']
                share_client['ugType'] = group_ret['data']['ugType']
                share_client['accessRight'] = group_ret['data']['accessRight']
                return share_client
        else:
            str = access_to.index('/')
            access_to = access_to[str + 1:]
            LOG.debug('Attempting to get domain user access. %s', access_info)
            aduser_ret = send_rest(access_to, ug_type['adUser'])
            if aduser_ret['code'] == constants.CODE_NOT_FOUND:
                return share_client
            if aduser_ret['data']:
                share_client = {}
                share_client['path'] = aduser_ret['data']['path']
                share_client['ugName'] = aduser_ret['data']['ugName']
                share_client['ugType'] = aduser_ret['data']['ugType']
                share_client['accessRight'] = \
                    aduser_ret['data']['accessRight']
                return share_client

                LOG.debug('Failed get domain user access,'
                          ' attempting to get domain group access. %s',
                          access_info)
            adgroup_ret = send_rest(access_to, ug_type['adGroup'])
            if adgroup_ret['data']:
                share_client = {}
                share_client['path'] = adgroup_ret['data']['path']
                share_client['ugName'] = adgroup_ret['data']['ugName']
                share_client['ugType'] = adgroup_ret['data']['ugType']
                share_client['accessRight'] = \
                    adgroup_ret['data']['accessRight']
                return share_client

        return share_client

    def _get_all_nfs_access_rest(self, share_path):
        url = f'rest/allNfsShareClient?path={share_path}'

        result = self.call(url, None, 'GET')

        msg = 'Get all nfs access error.'
        self._assert_result_code(result, msg)
        access_list = []
        if result['data'] is None:
            pass
        else:
            for item in result.get('data', []):
                access = {}
                access['share_path'] = item['path']
                access['access_to'] = item['clientName']
                access['access_level'] = item['accessRight']
                access_list.append(access)

        return access_list

    def _get_all_cifs_access_rest(self, share_path):
        url = f'rest/allCifsShareClient?path={share_path}'

        result = self.call(url, None, 'GET')

        msg = 'Get all cifs access error.'
        self._assert_result_code(result, msg)
        access_list = []
        for item in result.get('data', []):
            access = {}
            access['share_path'] = item['path']
            access['access_to'] = item['ugName']
            access['ugType'] = item['ugType']
            access['access_level'] = item['accessRight']
            access_list.append(access)

        return access_list

    def _change_nfs_access_rest(self, share_path, access_to, access_level):
        url = 'rest/nfsShareClient'
        access_info = {
            'path': share_path,
            'oldNfsClientName': access_to,
            'clientName': '',
            'accessRight': access_level,
            'allSquash': '',
            'rootSquash': '',
            'secure': '',
            'anonuid': '',
            'anongid': '',
        }
        result = self.call(url, access_info, 'PUT')

        msg = 'Update nfs acess error.'
        self._assert_result_code(result, msg)

    def _change_cifs_access_rest(self, share_path, access_to,
                                 access_level, ug_type):
        url = 'rest/cifsShareClient'
        if '/' in access_to:
            str = access_to.index('/')
            access_to = access_to[str + 1:]
        access_info = {
            'path': share_path,
            'right': access_level,
            'ugName': access_to,
            'ugType': ug_type,
        }

        result = self.call(url, access_info, 'PUT')
        msg = 'Update cifs access error.'

        self._assert_result_code(result, msg)

    def _delete_nfs_access_rest(self, share_path, access_to):
        url = f'rest/nfsShareClient?path={share_path}&client={access_to}'

        result = self.call(url, None, 'DELETE')
        msg = 'Delete nfs access error.'

        self._assert_result_code(result, msg)

    def _delete_cifs_access_rest(self, share_path, access_to, ug_type):
        url = f'rest/cifsShareClient?path={share_path}&ugName={access_to}' \
              f'&ugType={ug_type}'

        result = self.call(url, None, 'DELETE')
        msg = 'Delete cifs access error.'

        self._assert_result_code(result, msg)

    def _get_nfs_service_status(self):
        url = 'rest/nfsService'
        result = self.call(url, None, 'GET')

        msg = 'Get NFS service stauts error.'
        self._assert_result_code(result, msg)

        nfs_service = {}

        nfs_service['serviceStatus'] = result['data']['serviceStatus']
        nfs_service['nfs3Status'] = result['data']['nfs3Status']
        nfs_service['nfs4Status'] = result['data']['nfs4Status']

        return nfs_service

    def _start_nfs_service(self):
        url = 'rest/nfsService'
        nfs_service_info = {
            "openStatus": "1",
        }

        result = self.call(url, nfs_service_info, 'PUT')

        self._assert_result_code(result, 'Start NFS service error.')

    def _config_nfs_service(self):
        url = 'rest/nfsConfig'
        config_nfs = {
            'configNfs3': "yes",
            'configNfs4': "yes",
        }

        result = self.call(url, config_nfs, 'PUT')

        self._assert_result_code(result, 'Config NFS service error.')

    def _get_cifs_service_status(self):
        url = 'rest/cifsService'
        result = self.call(url, None, 'GET')

        msg = 'Get CIFS service status error.'
        self._assert_result_code(result, msg)

        return result['data']

    def _start_cifs_service(self):
        url = 'rest/cifsService'
        cifs_service_info = {
            'openStatus': '1',
        }

        result = self.call(url, cifs_service_info, 'PUT')

        self._assert_result_code(result, 'Start CIFS service error.')

    def _config_cifs_service(self):
        url = 'rest/cifsConfig'
        """config user mode"""
        config_cifs = {
            'workName': 'manila',
            'description': '',
            'access_way': 'user',
            'isCache': 'no',
            'adsName': '',
            'adsIP': '',
            'adsUSER': '',
            'adsPASSWD': '',
            'allowList': [],
            'denyList': [],
        }

        result = self.call(url, config_cifs, 'PUT')

        self._assert_result_code(result, 'Config CIFS service error.')

    def _get_all_pool(self):
        url = 'rest/storagepool'

        result = self.call(url, None, 'GET')

        msg = 'Query pool info error.'
        self._assert_result_code(result, msg)

        return result

    def _query_user(self, user_name):
        url = f'rest/user/{user_name}'

        result = self.call(url, None, 'GET')

        msg = 'Query user error.'
        self._assert_result_code(result, msg)
        return result['data']

    def _add_localuser(self, user_name, user_passwd, group_name):
        url = 'rest/localUser'
        user_info = {
            'userName': user_name,
            'mgGroup': group_name,
            'userPasswd': user_passwd,
            'unusedGroup': [],
        }
        result = self.call(url, user_info, 'POST')
        msg = 'add localuser error.'
        self._assert_result_code(result, msg)

    def _query_group(self, group_name):
        url = f'rest/group/{group_name}'

        result = self.call(url, None, 'GET')
        msg = 'Query group error.'
        self._assert_result_code(result, msg)
        return result['data']

    def _add_localgroup(self, group_name):
        url = 'rest/localGroup'
        group_info = {
            'groupName': group_name,
        }
        result = self.call(url, group_info, 'POST')

        msg = 'add localgroup error.'
        self._assert_result_code(result, msg)
