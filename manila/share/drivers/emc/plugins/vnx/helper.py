# Copyright (c) 2014 EMC Corporation.
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
import cookielib
import random
import re

from eventlet import greenthread
from lxml import builder
from lxml import etree as ET
from oslo_log import log
import six
from six.moves.urllib import error as url_error  # pylint: disable=E0611
from six.moves.urllib import request as url_request  # pylint: disable=E0611

from manila.common import constants as const
import manila.exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LI
from manila.i18n import _LW
from manila.share.drivers.emc.plugins.vnx import constants
from manila.share.drivers.emc.plugins.vnx import utils as vnx_utils
from manila.share.drivers.emc.plugins.vnx import xml_api_parser as parser
from manila import utils

LOG = log.getLogger(__name__)


class XMLAPIConnector(object):
    def __init__(self, configuration, debug=True):
        super(XMLAPIConnector, self).__init__()
        self.storage_ip = configuration.emc_nas_server
        self.user_name = configuration.emc_nas_login
        self.pass_word = configuration.emc_nas_password
        self.debug = debug
        self.auth_url = 'https://' + self.storage_ip + '/Login'
        self._url = ('https://' + self.storage_ip
                     + '/servlets/CelerraManagementServices')
        https_handler = url_request.HTTPSHandler()
        cookie_jar = cookielib.CookieJar()
        cookie_handler = url_request.HTTPCookieProcessor(cookie_jar)
        self.url_opener = url_request.build_opener(https_handler,
                                                   cookie_handler)
        self._do_setup()

    def _do_setup(self):
        credential = ('user=' + self.user_name
                      + '&password=' + self.pass_word
                      + '&Login=Login')
        req = url_request.Request(self.auth_url, credential,
                                  constants.CONTENT_TYPE_URLENCODE)
        resp = self.url_opener.open(req)
        resp_body = resp.read()
        self._http_log_resp(resp, resp_body)

    def _http_log_req(self, req):
        if not self.debug:
            return

        string_parts = ['curl -i']
        string_parts.append(' -X %s' % req.get_method())

        for k in req.headers:
            header = ' -H "%s: %s"' % (k, req.headers[k])
            string_parts.append(header)

        if req.data:
            string_parts.append(" -d '%s'" % req.data)
        string_parts.append(' ' + req.get_full_url())
        LOG.debug("\nREQ: %s\n", "".join(string_parts))

    def _http_log_resp(self, resp, body, failed_req=None):
        if not self.debug and failed_req is None:
            return

        headers = six.text_type(resp.headers).replace('\n', '\\n')
        if failed_req:
            LOG.error(
                _LE('REQ: [%(method)s] %(url)s %(req_hdrs)s\n'
                    'REQ BODY: %(req_b)s\n'
                    'RESP: [%(code)s] %(resp_hdrs)s\n'
                    'RESP BODY: %(resp_b)s\n'),
                {
                    'method': failed_req.get_method(),
                    'url': failed_req.get_full_url(),
                    'req_hdrs': failed_req.headers,
                    'req_b': failed_req.data,
                    'code': resp.getcode(),
                    'resp_hdrs': headers,
                    'resp_b': body,
                }
            )
        else:
            LOG.debug(
                'RESP: [%(code)s] %(resp_hdrs)s\n'
                'RESP BODY: %(resp_b)s\n',
                {
                    'code': resp.getcode(),
                    'resp_hdrs': headers,
                    'resp_b': body,
                }
            )

    def _request(self, req_body=None, method=None,
                 header=constants.CONTENT_TYPE_URLENCODE):
        req = url_request.Request(self._url, req_body, header)
        if method not in (None, 'GET', 'POST'):
            req.get_method = lambda: method
        self._http_log_req(req)
        try:
            resp = self.url_opener.open(req)
            resp_body = resp.read()
            self._http_log_resp(resp, resp_body)
        except url_error.HTTPError as http_err:
            err = {'errorCode': -1,
                   'httpStatusCode': http_err.code,
                   'messages': six.text_type(http_err),
                   'request': req_body}
            msg = (_("The request is invalid. Reason: %(reason)s") %
                   {'reason': err})
            if '403' == six.text_type(http_err.code):
                raise manila.exception.NotAuthorized()
            else:
                raise manila.exception.ManilaException(message=msg)

        return resp_body

    def request(self, req_body=None, method=None,
                header=constants.CONTENT_TYPE_URLENCODE):
        try:
            resp_body = self._request(req_body, method, header)
        except manila.exception.NotAuthorized:
            LOG.debug("Login again because client certification "
                      "may be expired.")
            self._do_setup()
            resp_body = self._request(req_body, method, header)

        return resp_body


@vnx_utils.decorate_all_methods(vnx_utils.log_enter_exit,
                                debug_only=True)
class XMLAPIHelper(object):
    def __init__(self, configuration):
        super(XMLAPIHelper, self).__init__()
        self._conn = XMLAPIConnector(configuration)

        self.elt_maker = builder.ElementMaker(
            nsmap={None: constants.XML_NAMESPACE})

    def _translate_response(self, status, info):
        """Translate different status to ok/error status."""
        if constants.STATUS_OK == status or constants.STATUS_ERROR == status:
            return status

        status_before = status
        if status in [constants.STATUS_DEBUG,
                      constants.STATUS_INFO,
                      constants.STATUS_WARNING]:
            status = constants.STATUS_OK
        else:
            status = constants.STATUS_ERROR

        LOG.warn(_LW("Translated status from %(old)s to %(new)s. "
                     "Message: %(info)s."),
                 {'old': status_before,
                  'new': status,
                  'info': info})
        return status

    def _verify_response(self, response, translate=True):

        data = {'info': []}
        status = constants.STATUS_OK

        for child in response:
            if (child[0] == 'Fault' or
                    child[0] == 'QueryStatus' or child[0] == 'TaskResponse'):

                if 'maxSeverity' in child[1].keys():
                    status = child[1]['maxSeverity']

                if 'taskId' in child[1].keys():
                    task_id = child[1]['taskId']
                else:
                    task_id = None

                # It indicate that there is a problem in this operation
                if len(child) > 2 and len(child[2]) > 0:
                    problems = child[2]

                    for item in problems:
                        if item[0] == 'Problem':
                            info = {
                                'taskId': task_id,
                                'message': None,
                                'messageCode': None,
                                'description': None,
                                'diagnostics': None,
                            }

                            list_properties = [
                                'description',
                                'messageCode',
                                'message',
                                'severity',
                            ]
                            self._copy_properties(item[1],
                                                  info,
                                                  list_properties)
                            info['diagnostics'] = item[1].get('Diagnostics')
                            data['info'].append(info)

                if len(data['info']) == 0:
                    data['info'].append(
                        {
                            'taskId': task_id,
                            'message': None,
                            'messageCode': None,
                            'description': None,
                            'diagnostics': None,
                        })

        if translate:
            status = self._translate_response(status, data['info'])
        return status, data

    def _get_message_codes(self, data):
        if 'info' not in data:
            return []
        return map(lambda info: info['messageCode'], data['info'])

    def _build_query_package(self, body):
        return self.elt_maker.RequestPacket(
            self.elt_maker.Request(
                self.elt_maker.Query(body)
            )
        )

    def _build_task_package(self, body):
        return self.elt_maker.RequestPacket(
            self.elt_maker.Request(
                self.elt_maker.StartTask(body, timeout='300')
            )
        )

    def create_file_system(self, fs_name, fs_size, pool_id, mover_id,
                           is_vdm=True):
        if is_vdm:
            mover = self.elt_maker.Vdm(vdm=mover_id)
        else:
            mover = self.elt_maker.Mover(mover=mover_id)

        request = self._build_task_package(
            self.elt_maker.NewFileSystem(
                mover,
                self.elt_maker.StoragePool(
                    pool=pool_id,
                    size=six.text_type(fs_size),
                    mayContainSlices='true'
                ),
                name=fs_name
            )
        )

        status, msg, result = self._send_request(request)
        return status, msg

    def delete_file_system(self, fs_id):
        request = self._build_task_package(
            self.elt_maker.DeleteFileSystem(fileSystem=fs_id)
        )

        status, msg, result = self._send_request(request)
        return status, msg

    def get_file_system_by_name(self, fs_name, need_capacity=True):

        data = {
            'name': '',
            'id': '',
            'type': '',
            'size': '',
            'volume_id': '',
            'pool_id': '',
            'dataServicePolicies': '',
            'containsSlices': '',
            'cwormState': '',
        }

        request = self._build_query_package(
            self.elt_maker.FileSystemQueryParams(
                self.elt_maker.AspectSelection(
                    fileSystems='true',
                    fileSystemCapacityInfos='true' if
                    need_capacity else 'false'
                ),
                self.elt_maker.Alias(name=fs_name)
            )
        )

        status, msg, result = self._send_request(request)

        if constants.STATUS_OK != status:
            return status, msg

        for item in result:
            if item[0] == 'FileSystem':
                list_properties = [
                    'name',
                    'type',
                    'cwormState',
                    'dataServicePolicies',
                    'containsSlices',
                ]
                self._copy_properties(item[1], data, list_properties)
                data['id'] = item[1].get('fileSystem', '')
                data['volume_id'] = item[1].get('volume', '')
                data['pool_id'] = item[1].get('storagePools', '')

            if item[0] == 'FileSystemCapacityInfo':
                data['size'] = item[1].get('volumeSize', '')

        if data['id'] == '':
            status = constants.STATUS_NOT_FOUND

        return status, data

    def create_mount_point(self, fs_id, mount_path, mover_id):
        request = self._build_task_package(
            self.elt_maker.NewMount(
                self.elt_maker.MoverOrVdm(mover=mover_id),
                fileSystem=fs_id,
                path=mount_path
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def delete_mount_point(self, mover_id, mount_path, is_vdm):
        request = self._build_task_package(
            self.elt_maker.DeleteMount(
                mover=mover_id,
                moverIdIsVdm=is_vdm,
                path=mount_path
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def get_mount_point(self, mover_id):

        mount_points = []
        request = self._build_query_package(
            self.elt_maker.MountQueryParams(
                self.elt_maker.MoverOrVdm(mover=mover_id)
            )
        )

        status, msg, result = self._send_request(request)

        if constants.STATUS_OK != status:
            return status, msg

        for item in result:
            if item[0] == 'Mount':
                mount = {
                    'path': '',
                    'fs_id': '',
                    'mover_id': '',
                    'moverIdIsVdm': '',
                    'nfs_ro': '',
                    'cifsSyncwrite': '',
                }

                list_properties = [
                    'path',
                    'moverIdIsVdm',
                    'cifsSyncwrite',
                ]
                self._copy_properties(item[1], mount, list_properties)

                mount['fs_id'] = item[1].get('fileSystem', '')
                mount['mover_id'] = item[1].get('mover', '')
                mount['nfs_ro'] = item[1].get('ro', '')

                mount_points.append(mount)

        if len(mount_points) == 0:
            status = constants.STATUS_NOT_FOUND

        return status, mount_points

    def create_cifs_share(self, share_name, netbios_name, mover_id,
                          is_vdm=True):

        share_path = '/' + share_name

        request = self._build_task_package(
            self.elt_maker.NewCifsShare(
                self.elt_maker.MoverOrVdm(
                    mover=mover_id,
                    moverIdIsVdm='true' if is_vdm else 'false'
                ),
                self.elt_maker.CifsServers(self.elt_maker.li(netbios_name)),
                name=share_name,
                path=share_path
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def delete_cifs_share(self, share_name, mover_id, netbios_names,
                          is_vdm='true'):
        if not isinstance(netbios_names, list):
            netbios_names = [netbios_names]

        request = self._build_task_package(
            self.elt_maker.DeleteCifsShare(
                self.elt_maker.CifsServers(*map(lambda a: self.elt_maker.li(a),
                                                netbios_names)),
                mover=mover_id,
                moverIdIsVdm=is_vdm,
                name=share_name
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def get_cifs_share_by_name(self, name):

        data = {
            "name": '',
            "moverIdIsVdm": 'false',
            "CifsServers": [],
            "fileSystem": '',
            'path': '',
            'mover': '',
        }

        request = self._build_query_package(
            self.elt_maker.CifsShareQueryParams(name=name)
        )

        status, msg, result = self._send_request(request)

        if constants.STATUS_OK != status:
            return status, msg

        for item in result:
            if item[0] == 'CifsShare':
                data = self._copy_properties(item[1], data, data.keys())
                break

        if data['name'] == '':
            status = constants.STATUS_NOT_FOUND

        return status, data

    def _copy_properties(self, source, dest, properties):
        for key in properties:
            if key in source:
                dest[key] = source[key]
        return dest

    def _send_request(self, req):
        req_xml = constants.XML_HEADER + ET.tostring(req)
        rsp_xml = self._conn.request(req_xml)

        result = parser.parse_xml_api(
            parser.xml_to_tupletree(rsp_xml)
        )

        status, msg_info = self._verify_response(result)
        return status, msg_info, result

    def _is_not_internal_device(self, device):
        for device_type in ('mge', 'fxg', 'tks', 'fsn'):
            if device.find(device_type) == 0:
                return False
        return True

    def is_mount_point_nonexistent(self, out):
        for problem in out.get('info', []):
            if ((problem['messageCode'] == constants.MSG_GENERAL_ERROR and
                    problem['message'].find("No such path or invalid "
                                            "operation") != -1) or
                    (problem['messageCode'] == constants.MSG_INVALID_VDM_ID)):
                return True

        return False

    def create_check_point(self, src_fs, ckpt_name, pool_id, ckpt_size=None):

        if ckpt_size:
            elt_pool = self.elt_maker.StoragePool(
                pool=pool_id,
                size=six.text_type(ckpt_size)
            )
        else:
            elt_pool = self.elt_maker.StoragePool(pool=pool_id)

        new_ckpt = self.elt_maker.NewCheckpoint(
            self.elt_maker.SpaceAllocationMethod(
                elt_pool
            ),
            checkpointOf=src_fs,
            name=ckpt_name
        )

        request = self._build_task_package(new_ckpt)

        status, msg, result = self._send_request(request)

        return status, msg

    def delete_check_point(self, ckpt_id):

        request = self._build_task_package(
            self.elt_maker.DeleteCheckpoint(checkpoint=ckpt_id)
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def get_check_point_by_name(self, ckpt_name):

        check_point = {
            'name': '',
            'id': '',
            'state': '',
            'time': '',
            'checkpointOf': '',
            'fileSystemSize': '',
            'baseline': '',
            'writeable': '',
            'readOnly': None,
        }

        request = self._build_query_package(
            self.elt_maker.CheckpointQueryParams(
                self.elt_maker.Alias(name=ckpt_name)
            )
        )

        status, msg, result = self._send_request(request)

        if constants.STATUS_OK != status:
            return status, msg

        for item in result:
            if item[0] == 'Checkpoint':
                list_properties = [
                    'name',
                    'state',
                    'time',
                    'checkpointOf',
                    'fileSystemSize',
                    'baseline',
                    'writeable',
                    'readOnly',
                ]
                self._copy_properties(item[1], check_point, list_properties)

                check_point['id'] = item[1].get('checkpoint', '')
                break

        if check_point['id'] == '':
            status = constants.STATUS_ERROR

        return status, check_point

    def list_storage_pool(self):
        pools = []

        request = self._build_query_package(
            self.elt_maker.StoragePoolQueryParams()
        )

        status, msg, result = self._send_request(request)

        if constants.STATUS_OK != status:
            return status, msg

        for item in result:
            if item[0] == 'StoragePool':
                pool = {
                    'name': '',
                    'id': '',
                    "diskType": '',
                    'used_size': '',
                    'total_size': '',
                    'movers_id': [],
                    'virtualProvisioning': '',
                    'dataServicePolicies': '',
                    'greedy': '',
                    'isBackendPool': '',
                }

                list_properties = [
                    'name',
                    'diskType',
                    'virtualProvisioning',
                    'dataServicePolicies',
                    'greedy',
                    'isBackendPool',
                ]
                self._copy_properties(item[1], pool, list_properties)

                pool['id'] = item[1].get('pool', '')
                pool['used_size'] = item[1].get('usedSize', '')
                pool['total_size'] = item[1].get('autoSize', '')
                if 'movers' in item[1].keys():
                    pool['movers_id'] = item[1]['movers'].split()

                pools.append(pool)

        if not pools:
            status = constants.STATUS_ERROR

        return status, pools

    def get_mover_ref_by_name(self, name):

        mover = {
            'name': '',
            'id': '',
        }

        request = self._build_query_package(
            self.elt_maker.MoverQueryParams(
                self.elt_maker.AspectSelection(movers='true')
            )
        )

        status, msg, result = self._send_request(request)
        if constants.STATUS_ERROR == status:
            return status, msg

        for item in result:
            if (item[0] == 'Mover' and item[1]['name'] == name
                    and 'mover' in item[1].keys()):
                mover['id'] = item[1]['mover']
                mover['name'] = name
                break
        if mover['id'] == '':
            status = constants.STATUS_NOT_FOUND
        return status, mover

    def get_mover_by_id(self, mover_id):

        mover = {
            'name': '',
            'id': '',
            'role': '',
            'Status': '',
            'uptime': '',
            'version': '',
            'interfaces': [],
            'devices': [],
            'dns_domain': [],
        }

        request = self._build_query_package(
            self.elt_maker.MoverQueryParams(
                self.elt_maker.AspectSelection(
                    moverDeduplicationSettings='true',
                    moverDnsDomains='true',
                    moverInterfaces='true',
                    moverNetworkDevices='true',
                    moverNisDomains='true',
                    moverRoutes='true',
                    movers='true',
                    moverStatuses='true'
                ),
                mover=mover_id
            )
        )

        status, msg, result = self._send_request(request)
        if constants.STATUS_OK != status:
            return status, msg

        for item in result:
            if item[0] == 'Mover':
                mover['name'] = item[1].get('name', '')
                mover['id'] = item[1].get('mover', '')
                mover['role'] = item[1].get('role', '')

            elif item[0] == 'MoverStatus':
                self._copy_properties(item[1],
                                      mover,
                                      ['Status', 'uptime', 'version'])
            elif item[0] == 'MoverInterface':
                interface = {
                    'name': '',
                    'device': '',
                    'ipVersion': '',
                    'netMask': '',
                    'vlan_id': '',
                    'ipAddress': '',
                }

                list_properties = [
                    'name',
                    'device',
                    'ipVersion',
                    'netMask',
                    'ipAddress',
                ]
                self._copy_properties(item[1], interface, list_properties)
                interface['vlan_id'] = item[1].get('vlanid', '')

                if (self._is_not_internal_device(interface['device'])
                        and 'ipAddress' in item[1].keys()):
                    mover['interfaces'].append(interface)
            elif item[0] == 'LogicalNetworkDevice':
                logical_network_device = {
                    'speed': '',
                    'interfaces': '',
                    'type': '',
                    'name': '',
                }

                self._copy_properties(item[1],
                                      logical_network_device,
                                      ['speed', 'interfaces', 'type', 'name'])

                mover['devices'].append(logical_network_device)
            elif item[0] == 'MoverDnsDomain':
                dns_domain = {
                    'name': '',
                    'servers': '',
                    'protocol': '',
                }

                self._copy_properties(item[1],
                                      dns_domain,
                                      dns_domain.keys())

                mover['dns_domain'].append(dns_domain)

        if mover['id'] == '':
            status = constants.STATUS_ERROR

        return status, mover

    def extend_file_system(self, fs_id, pool_id, new_size):

        request = self._build_task_package(
            self.elt_maker.ExtendFileSystem(
                self.elt_maker.StoragePool(
                    pool=pool_id,
                    size=six.text_type(new_size)
                ),
                fileSystem=fs_id,
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def create_vdm(self, name, host_mover_id):

        request = self._build_task_package(
            self.elt_maker.NewVdm(mover=host_mover_id, name=name)
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def delete_vdm(self, vdm_id):

        request = self._build_task_package(
            self.elt_maker.DeleteVdm(vdm=vdm_id)
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def get_vdm_by_name(self, name):
        vdm = {
            "name": '',
            "id": '',
            "state": '',
            'host_mover_id': '',
            'interfaces': [],
        }

        request = self._build_query_package(self.elt_maker.VdmQueryParams())

        status, msg, result = self._send_request(request)
        if constants.STATUS_OK != status:
            return status, msg

        for item in result:
            if item[0] == 'Vdm' and item[1]['name'] == name:
                vdm['name'] = item[1].get('name', '')
                vdm['host_mover_id'] = item[1].get('mover', '')
                vdm['interfaces'] = item[1].get('Interfaces', '')
                vdm['state'] = item[1].get('state', '')
                vdm['id'] = item[1].get('vdm', '')
                break

        if vdm['id'] == '':
            status = constants.STATUS_NOT_FOUND

        return status, vdm

    def create_mover_interface(self, name, device_name, ip_addr, mover_id,
                               net_mask='255.255.255.0', vlan_id=None):
        vlan_id = vlan_id if vlan_id else '-1'
        interface = {
            'name': name,
            'device_name': device_name,
            'ip': ip_addr,
            'mover_id': mover_id,
            'net_mask': net_mask,
            'vlan_id': vlan_id,
        }

        request = self._build_task_package(
            self.elt_maker.NewMoverInterface(
                device=device_name,
                ipAddress=six.text_type(ip_addr),
                mover=mover_id,
                name=name,
                netMask=net_mask,
                vlanid=six.text_type(vlan_id)
            )
        )

        status, msg, result = self._send_request(request)

        if constants.STATUS_OK != status:
            return status, msg

        return status, interface

    def delete_mover_interface(self, ip_addr, mover_id):

        request = self._build_task_package(
            self.elt_maker.DeleteMoverInterface(
                ipAddress=six.text_type(ip_addr),
                mover=mover_id
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def create_cifs_server(self, args):

        computer_name = args['compName']
        netbios_name = args['netbios']
        mover_id = args['mover_id']
        domain_name = args['domain']
        interfaces = args['interface']
        alias_names = args['alias']
        user_name = args['admin_username']
        password = args['admin_password']

        alias_name_list = [self.elt_maker.li(alias) for alias in alias_names]

        request = self._build_task_package(
            self.elt_maker.NewW2KCifsServer(
                self.elt_maker.MoverOrVdm(mover=mover_id, moverIdIsVdm='true'),
                self.elt_maker.Aliases(*alias_name_list),
                self.elt_maker.JoinDomain(userName=user_name,
                                          password=password),
                compName=computer_name,
                domain=domain_name,
                interfaces=interfaces,
                name=netbios_name
            )
        )

        status, msg, result = self._send_request(request)

        if constants.STATUS_OK == status:
            if (constants.MSG_JOIN_DOMAIN_FAILED
                    in self._get_message_codes(msg)):
                # Domain Join Failed
                return constants.STATUS_ERROR, msg
            else:
                cifs_server = {
                    'compName': computer_name,
                    'netbios_name': netbios_name,
                    'mover_id': mover_id,
                    'domain_name': domain_name,
                    'interfaces': interfaces,
                    'alias_names': alias_names,
                }

                return status, cifs_server
        else:
            return status, msg

    def modify_cifs_server(self, args):

        mover_id = args['mover_id']
        name = args['name']
        join_domain = args['join_domain']
        user_name = args['admin_username']
        password = args['admin_password']

        is_vdm = args['is_vdm'] if 'is_vdm' in args.keys() else 'true'

        request = self._build_task_package(
            self.elt_maker.ModifyW2KCifsServer(
                self.elt_maker.DomainSetting(
                    joinDomain=join_domain,
                    password=password,
                    userName=user_name,
                ),
                mover=mover_id,
                moverIdIsVdm=is_vdm,
                name=name
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def delete_cifs_server(self, server_name, mover_id, is_vdm='true'):
        request = self._build_task_package(
            self.elt_maker.DeleteCifsServer(
                mover=mover_id,
                moverIdIsVdm=is_vdm,
                name=server_name
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def get_cifs_servers(self, mover_id, is_vdm=True):
        cifs_servers = []

        request = self._build_query_package(
            self.elt_maker.CifsServerQueryParams(
                self.elt_maker.MoverOrVdm(
                    mover=mover_id,
                    moverIdIsVdm='true' if is_vdm else 'false'
                )
            )
        )

        status, msg, result = self._send_request(request)

        if constants.STATUS_OK != status:
            return status, msg

        for item in result:
            if item[0] == 'CifsServer':
                server = {
                    'name': '',
                    'interfaces': '',
                    'type': '',
                    'compName': '',
                    "mover_id": '',
                    'moverIdIsVdm': '',
                    'domain': '',
                    'domainJoined': '',
                }

                list_properties = [
                    'name',
                    'type',
                    'compName',
                    'moverIdIsVdm',
                    'domain',
                    'domainJoined',
                ]
                self._copy_properties(item[1], server, list_properties)

                if 'interfaces' in item[1].keys():
                    server['interfaces'] = item[1]['interfaces'].split(',')

                server['mover_id'] = item[1].get('mover', '')

                cifs_servers.append(server)

        if len(cifs_servers) == 0:
            status = constants.STATUS_NOT_FOUND

        return status, cifs_servers

    def create_dns_domain(self, mover_id, name, servers, protocol='udp'):

        request = self._build_task_package(
            self.elt_maker.NewMoverDnsDomain(
                mover=mover_id,
                name=name,
                servers=servers,
                protocol=protocol
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg

    def delete_dns_domain(self, mover_id, name):

        request = self._build_task_package(
            self.elt_maker.DeleteMoverDnsDomain(
                mover=mover_id,
                name=name
            )
        )

        status, msg, result = self._send_request(request)

        return status, msg


class SSHConnector(object):
    def __init__(self, configuration):
        super(SSHConnector, self).__init__()
        self.storage_ip = configuration.emc_nas_server
        self.user_name = configuration.emc_nas_login
        self.pass_word = configuration.emc_nas_password

        self.sshpool = utils.SSHPool(self.storage_ip,
                                     22,
                                     None,
                                     self.user_name,
                                     password=self.pass_word)

    def run_ssh(self, cmd, attempts=1):

        try:
            if not isinstance(cmd, str):
                cmd = map(str, cmd)
                command = ' '.join(cmd)
            else:
                command = cmd

            with self.sshpool.item() as ssh:
                while attempts > 0:
                    attempts -= 1
                    try:
                        stdin_stream, stdout_stream, stderr_stream = (
                            ssh.exec_command(command))

                        stdout = stdout_stream.read()
                        stderr = stderr_stream.read()
                        stdin_stream.close()

                    except Exception as e:
                        LOG.debug(e)
                        greenthread.sleep(random.randint(20, 500) / 100.0)

        except Exception:
            LOG.error(_LE("Error running SSH command: %s"), command)

        return stdout, stderr


@vnx_utils.decorate_all_methods(vnx_utils.log_enter_exit,
                                debug_only=True)
class NASCommandHelper(object):
    def __init__(self, configuration):
        super(NASCommandHelper, self).__init__()
        self._conn = SSHConnector(configuration)

    def get_interconnect_id(self, src, dest):

        header = [
            'id',
            'name',
            'source_server',
            'destination_system',
            'destination_server',
        ]

        conn_id = None

        command_nas_cel = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_cel',
            '-interconnect', '-l',
        ]
        out, err = self._conn.run_ssh(command_nas_cel)

        lines = out.strip().split('\n')
        for line in lines:
            if line.strip().split() == header:
                LOG.info(_LI('Found the header of the command '
                             '/nas/bin/nas_cel -interconnect -l'))
            else:
                interconn = line.strip().split()
                if interconn[2] == src and interconn[4] == dest:
                    conn_id = interconn[0]

        return conn_id

    def create_fs_from_ckpt(self, fs_name, mover_name,
                            source_ckpt, source_fs,
                            dest_pool_name, connect_id):
        status = constants.STATUS_OK
        msg = ''
        create_fs_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-name', fs_name,
            '-type', 'uxfs',
            '-create',
            'samesize=' + source_fs,
            'pool=' + '"' + dest_pool_name + '"',
            'storage=SINGLE',
            'worm=off',
            '-thin', 'no',
            '-option', 'slice=y',
        ]

        self._execute_cmd(create_fs_cmd)

        ro_mount_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_mount', mover_name,
            '-option', 'ro',
            fs_name,
            '/' + fs_name,
        ]
        self._execute_cmd(ro_mount_cmd)

        session_name = fs_name + ':' + '"' + dest_pool_name + '"'
        copy_ckpt_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_copy',
            '-name', session_name,
            '-source -ckpt', source_ckpt,
            '-destination -fs', fs_name,
            '-interconnect',
            'id=%s' % connect_id,
            '-overwrite_destination',
            '-full_copy',
        ]
        out, err = self._execute_cmd(copy_ckpt_cmd)
        if err.strip().lower() != constants.STATUS_OK:
            # When there is an error happen during nas_copy, we need
            # continue to delete the checkpoint of the target file system
            # if it exists.
            status = constants.STATUS_ERROR
            msg = "nas_copy failed. Reason %s" % out

        query_fs_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
            '-info', fs_name,
        ]
        out, err = self._execute_cmd(query_fs_cmd)
        re_ckpts = r'ckpts\s*=\s*(.*)\s*'
        m = re.search(re_ckpts, out)
        if m is not None:
            ckpts = m.group(1)
            for ckpt in re.split(',', ckpts):
                umount_ckpt_cmd = [
                    'env', 'NAS_DB=/nas',
                    '/nas/bin/server_umount', mover_name,
                    '-perm', ckpt,
                ]
                self._execute_cmd(umount_ckpt_cmd)
                delete_ckpt_cmd = [
                    'env', 'NAS_DB=/nas', '/nas/bin/nas_fs',
                    '-delete', ckpt,
                    '-Force',
                ]
                self._execute_cmd(delete_ckpt_cmd)

        rw_mount_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_mount', mover_name,
            '-option', 'rw',
            fs_name,
            '/' + fs_name,
        ]
        self._execute_cmd(rw_mount_cmd)
        return status, msg

    def enable_nfs_service(self, vdm_name, if_name):

        command_attach_if_on_vdm = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-vdm', vdm_name,
            '-attach', if_name,
        ]

        out, err = self._conn.run_ssh(command_attach_if_on_vdm)

    def disable_nfs_service(self, vdm_name, if_name):

        command_attach_if_on_vdm = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-vdm', vdm_name,
            '-detach', if_name,
        ]

        out, err = self._conn.run_ssh(command_attach_if_on_vdm)

    def get_interfaces_by_vdm(self, vdm_name):

        interfaces = {
            'cifs': [],
            'vdm': [],
        }

        re_pattern = ('Interfaces to services mapping:'
                      '\s*(?P<interfaces>(\s*interface=.*)*)')

        command_get_if_on_vdm = [
            'env', 'NAS_DB=/nas', '/nas/bin/nas_server',
            '-i',
            '-vdm', vdm_name,
        ]

        out, err = self._conn.run_ssh(command_get_if_on_vdm)

        m = re.search(re_pattern, out)
        if m:
            if_list = m.group('interfaces').split('\n')
            for i in if_list:
                m_if = re.search('\s*interface=(?P<if>.*)\s*:'
                                 '\s*(?P<type>.*)\s*', i)
                if m_if:
                    if 'cifs' == m_if.group('type'):
                        interfaces['cifs'].append(m_if.group('if'))
                    elif 'vdm' == m_if.group('type'):
                        interfaces['vdm'].append(m_if.group('if'))

        return interfaces

    def create_nfs_share(self, share_name, mover_name):
        result = (constants.STATUS_OK, '')
        share_path = '/' + share_name
        create_nfs_share_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-option', 'access=-0.0.0.0/0.0.0.0',
            share_path,
        ]

        out, err = self._execute_cmd(create_nfs_share_cmd)
        if re.search(r'%s\s*:\s*done' % mover_name, out):
            return result
        else:
            return constants.STATUS_ERROR, ('output=%(output)s, '
                                            'return=%(err)s'
                                            % {'output': out, 'err': err})

    def delete_nfs_share(self, path, mover_name):
        result = (constants.STATUS_OK, '')
        create_nfs_share_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-unexport',
            '-perm',
            path,
        ]

        out, err = self._execute_cmd(create_nfs_share_cmd)
        if re.search(r'%s\s*:\s*done' % mover_name, out):
            return result
        else:
            return constants.STATUS_ERROR, ('output=%(output)s, '
                                            'return=%(err)s'
                                            % {'output': out, 'err': err})

    def get_nfs_share_by_path(self, path, mover_name):

        data = {
            "mover_name": '',
            "path": '',
            'AccessHosts': [],
            'RwHosts': [],
            'RoHosts': [],
            'RootHosts': [],
            'readOnly': '',
        }

        nfs_query_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-P', 'nfs',
            '-list', path,
        ]

        out, err = self._execute_cmd(nfs_query_cmd)
        re_exports = '%s\s*:\s*\nexport\s*(.*)\n' % mover_name
        m = re.search(re_exports, out)
        if m is not None:
            status = constants.STATUS_OK
            data['path'] = path
            data['mover_name'] = mover_name
            export = m.group(1)
            fields = export.split(" ")
            for field in fields:
                field = field.strip()
                if field.startswith('rw='):
                    data['RwHosts'] = field[3:].split(":")
                elif field.startswith('access='):
                    data['AccessHosts'] = field[7:].split(":")
                elif field.startswith('root='):
                    data['RootHosts'] = field[5:].split(":")
                elif field.startswith('ro='):
                    data['RoHosts'] = field[3:].split(":")
        else:
            status = constants.STATUS_NOT_FOUND
            data = 'output=%(output)s, return=%(err)s' % {'output': out,
                                                          'err': err}
        return status, data

    def allow_nfs_share_access(self, path, host_ip, mover_name,
                               access_level=const.ACCESS_LEVEL_RW):
        sharename = path.strip('/')

        @utils.synchronized('emc-shareaccess-' + sharename)
        def do_allow_access(path, host_ip, mover_name, access_level):
            ok = (constants.STATUS_OK, '')
            status, share = self.get_nfs_share_by_path(path, mover_name)
            if constants.STATUS_OK != status:
                return constants.STATUS_ERROR, ('Query nfs share %(path)s '
                                                'failed. Reason %(err)s'
                                                % {'path': path, 'err': share})

            mover_name = share['mover_name']
            changed = False
            rwhosts = share['RwHosts']
            rohosts = share['RoHosts']
            if access_level == const.ACCESS_LEVEL_RW:
                if host_ip not in rwhosts:
                    rwhosts.append(host_ip)
                    changed = True
                if host_ip in rohosts:
                    rohosts.remove(host_ip)
                    changed = True
            if access_level == const.ACCESS_LEVEL_RO:
                if host_ip not in rohosts:
                    rohosts.append(host_ip)
                    changed = True
                if host_ip in rwhosts:
                    rwhosts.remove(host_ip)
                    changed = True

            roothosts = share['RootHosts']
            if host_ip not in roothosts:
                roothosts.append(host_ip)
                changed = True
            accesshosts = share['AccessHosts']
            if host_ip not in accesshosts:
                accesshosts.append(host_ip)
                changed = True

            if not changed:
                LOG.debug("%(host)s already in access list of share %(path)s",
                          {'host': host_ip, 'path': path})
                return ok
            else:
                return self.set_nfs_share_access(path,
                                                 mover_name,
                                                 rwhosts,
                                                 rohosts,
                                                 roothosts,
                                                 accesshosts)

        return do_allow_access(path, host_ip, mover_name, access_level)

    def deny_nfs_share_access(self, path, host_ip, mover_name):
        sharename = path.strip('/')

        @utils.synchronized('emc-shareaccess-' + sharename)
        def do_deny_access(path, host_ip, mover_name):
            ok = (constants.STATUS_OK, '')
            status, share = self.get_nfs_share_by_path(path, mover_name)
            if constants.STATUS_OK != status:
                return constants.STATUS_ERROR, ('Query nfs share %(path)s '
                                                'failed. Reason %(err)s'
                                                % {'path': path, 'err': share})

            mover_name = share['mover_name']
            changed = False
            rwhosts = set(share['RwHosts'])
            if host_ip in rwhosts:
                rwhosts.remove(host_ip)
                changed = True
            roothosts = set(share['RootHosts'])
            if host_ip in roothosts:
                roothosts.remove(host_ip)
                changed = True
            accesshosts = set(share['AccessHosts'])
            if host_ip in accesshosts:
                accesshosts.remove(host_ip)
                changed = True
            rohosts = set(share['RoHosts'])
            if host_ip in rohosts:
                rohosts.remove(host_ip)
                changed = True
            if not changed:
                LOG.debug("%(host)s already in access list of share %(path)s",
                          {'host': host_ip, 'path': path})
                return ok
            else:
                return self.set_nfs_share_access(path,
                                                 mover_name,
                                                 rwhosts,
                                                 rohosts,
                                                 roothosts,
                                                 accesshosts)

        return do_deny_access(path, host_ip, mover_name)

    def set_nfs_share_access(self, path, mover_name,
                             rw_hosts,
                             ro_hosts,
                             root_hosts,
                             access_hosts):
        ok = (constants.STATUS_OK, '')

        access_str = ('access=%(access)s'
                      % {'access': ':'.join(access_hosts)})
        if root_hosts:
            access_str += (',root=%(root)s' % {'root': ':'.join(root_hosts)})
        if rw_hosts:
            access_str += ',rw=%(rw)s' % {'rw': ':'.join(rw_hosts)}
        if ro_hosts:
            access_str += ',ro=%(ro)s' % {'ro': ':'.join(ro_hosts)}
        create_nfs_share_cmd = [
            'env', 'NAS_DB=/nas', '/nas/bin/server_export', mover_name,
            '-ignore',
            '-option', access_str,
            path,
        ]

        out, err = self._execute_cmd(create_nfs_share_cmd)
        if re.search(r'%s\s*:\s*done' % mover_name, out):
            return ok
        else:
            return constants.STATUS_ERROR, ('output=%(output)s, '
                                            'return=%(err)s'
                                            % {'output': out, 'err': err})

    def disable_cifs_access(self, mover_name, share_name):
        cmd_str = 'sharesd %s set noaccess' % share_name
        disable_access = [
            'env', 'NAS_DB=/nas', '/nas/bin/.server_config', mover_name,
            '-v', '"%s"' % cmd_str,
        ]
        out, err = self._execute_cmd(disable_access)
        if re.search(r'Command succeeded', out):
            return constants.STATUS_OK, out
        else:
            return constants.STATUS_ERROR, out

    def allow_cifs_access(self, mover_name, share_name, user_name, domain,
                          access=constants.CIFS_ACL_FULLCONTROL):
        account = user_name + "@" + domain
        allow_str = ('sharesd %(share_name)s grant %(account)s=%(access)s'
                     % {'share_name': share_name,
                        'account': account,
                        'access': access})

        allow_access = [
            'env', 'NAS_DB=/nas', '/nas/bin/.server_config', mover_name,
            '-v', '"%s"' % allow_str,
        ]
        out, err = self._execute_cmd(allow_access)
        dup_msg = (r'ACE for %(domain)s\\%(user)s unchanged' %
                   {'domain': domain, 'user': user_name})
        if re.search(r'Command succeeded', out):
            return constants.STATUS_OK, out
        elif re.search(dup_msg, out):
            # When ACE is set twice, treat the error as success
            return constants.STATUS_OK, 'duplicate ACEs, skipping allow...'
        else:
            return constants.STATUS_ERROR, out

    def deny_cifs_access(self, mover_name, share_name, user_name, domain,
                         access=constants.CIFS_ACL_FULLCONTROL):
        account = user_name + "@" + domain
        allow_str = ('sharesd %(share_name)s revoke %(account)s=%(access)s'
                     % {'share_name': share_name,
                        'account': account,
                        'access': access})
        not_found_msg = (r'No ACE found for %(domain)s\\%(user)s' %
                         {'domain': domain, 'user': user_name})
        user_err_msg = (r'Cannot get mapping for %(domain)s\\%(user)s' %
                        {'domain': domain, 'user': user_name})
        allow_access = [
            'env', 'NAS_DB=/nas', '/nas/bin/.server_config', mover_name,
            '-v', '"%s"' % allow_str,
        ]
        out, err = self._execute_cmd(allow_access)
        if re.search(r'Command succeeded', out):
            return constants.STATUS_OK, out
        elif re.search(not_found_msg, out):
            # When ACE not found, treat the error as success
            return constants.STATUS_OK, 'No ACE found, skipping deny...'
        elif re.search(user_err_msg, out):
            return constants.STATUS_OK, ('User not found on domain, '
                                         'skipping deny...')
        else:
            return constants.STATUS_ERROR, out

    def _execute_cmd(self, cmd):
        out, err = self._conn.run_ssh(cmd)
        LOG.debug('SSH: cmd = %(cmd)s, output = %(out)s, error = %(err)s',
                  {'cmd': cmd, 'out': out, 'err': err})
        return out, err
