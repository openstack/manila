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

"""
Share driver test for Macrosan Storage Array.
"""
import ddt
import requests

from oslo_config import cfg
from unittest import mock

from manila import context
from manila import exception
from manila.share import configuration
from manila.share import driver
from manila.share.drivers.macrosan import macrosan_constants as constants
from manila.share.drivers.macrosan import macrosan_helper
from manila.share.drivers.macrosan import macrosan_nas
from manila.share.drivers.macrosan import rest_helper
from manila import test
from manila.tests import fake_share

CONF = cfg.CONF


class FakeResponse(object):
    def __init__(self, status, result):
        self.status_code = status
        self.text = 'return message'
        self.response = result

    def json(self):
        return self.response

    def close(self):
        pass


@ddt.ddt
class MacrosanShareDriverTestCase(test.TestCase):

    def setUp(self):
        self.mock_object(macrosan_nas.CONF, '_check_required_opts')
        super(MacrosanShareDriverTestCase, self).setUp()

        def _safe_get(opt):
            return getattr(self.configuration, opt)

        self._context = context.get_admin_context()
        self.configuration = mock.Mock(spec=configuration.Configuration)
        self.configuration.safe_get = mock.Mock(side_effect=_safe_get)
        self.configuration.driver_handles_share_servers = False
        self.configuration.share_backend_name = 'fake_share_backend_name'
        self.configuration.macrosan_nas_http_protocol = 'https'
        self.configuration.macrosan_nas_ip = 'fake_ip'
        self.configuration.macrosan_nas_port = 'fake_port'
        self.configuration.macrosan_nas_username = 'fake_username'
        self.configuration.macrosan_nas_password = 'fake_password'
        self.configuration.macrosan_nas_prefix = 'nas'
        self.configuration.macrosan_share_pools = ['fake_pool']
        self.configuration.macrosan_timeout = 60
        self.configuration.macrosan_ssl_cert_verify = False

        self.configuration.network_config_group = 'fake_network_config_group'
        self.configuration.admin_network_config_group = (
            'fake_admin_network_config_group')
        self.configuration.config_group = 'fake_config_group'
        self.configuration.reserved_share_percentage = 0
        self.configuration.reserved_share_from_snapshot_percentage = 0
        self.configuration.reserved_share_extend_percentage = 0
        self.configuration.filter_function = None
        self.configuration.goodness_function = None
        self.driver = macrosan_nas.MacrosanNasDriver(
            configuration=self.configuration)
        self.result_success_storage_pools = {
            'code': 0,
            'message': 'success',
            'data': [{
                'name': 'fake_pool',
                'size': '1000.0G',
                'allocated': '100G',
                'free': '900G',
                'health': 'ONLINE',
                'rwStatus': 'off'
            }]
        }

    def test_do_setup(self):
        mock_login = self.mock_object(rest_helper.RestHelper, 'login')
        self.driver.do_setup(self._context)
        mock_login.assert_called_once()

    def test_do_setup_login_fail(self):
        mock_login = self.mock_object(
            rest_helper.RestHelper, 'login',
            mock.Mock(
                side_effect=exception.ShareBackendException(
                    msg='fake_exception')))
        self.assertRaises(exception.ShareBackendException,
                          self.driver.do_setup,
                          self._context)
        mock_login.assert_called_once()

    @ddt.data({'nfs_status': constants.NFS_NON_CONFIG,
               'cifs_status': constants.CIFS_NON_CONFIG},
              {'nfs_status': constants.NFS_DISABLED,
               'cifs_status': constants.CIFS_DISABLED},
              {'nfs_status': constants.NFS_ENABLED,
               'cifs_status': constants.CIFS_ENABLED},
              {'nfs_status': constants.NFS_ENABLED,
               'cifs_status': constants.CIFS_SHARE_MODE})
    @ddt.unpack
    def test_check_for_setup_error_non_config(self, nfs_status, cifs_status):
        mock_gnss = self.mock_object(
            rest_helper.RestHelper, '_get_nfs_service_status',
            mock.Mock(return_value={
                "serviceStatus": nfs_status,
                "nfs3Status": constants.NFS_NON_SUPPORTED,
                "nfs4Status": constants.NFS_NON_SUPPORTED
            }))

        mock_cns = self.mock_object(rest_helper.RestHelper,
                                    '_config_nfs_service')
        mock_sns = self.mock_object(rest_helper.RestHelper,
                                    '_start_nfs_service')
        if cifs_status == constants.CIFS_DISABLED:
            mock_gcss = self.mock_object(
                rest_helper.RestHelper, '_get_cifs_service_status',
                mock.Mock(side_effect=[cifs_status,
                                       constants.CIFS_SHARE_MODE]))
        else:
            mock_gcss = self.mock_object(
                rest_helper.RestHelper, '_get_cifs_service_status',
                mock.Mock(return_value=cifs_status))
        mock_ccs = self.mock_object(rest_helper.RestHelper,
                                    '_config_cifs_service')
        mock_scs = self.mock_object(rest_helper.RestHelper,
                                    '_start_cifs_service')
        self.driver.check_for_setup_error()
        if (nfs_status == constants.NFS_NON_CONFIG or
                nfs_status == constants.NFS_DISABLED):
            mock_cns.assert_called_once()
            mock_sns.assert_called_once()
        else:
            mock_cns.assert_called_once()
        mock_gnss.assert_called_once()
        if cifs_status == constants.CIFS_NON_CONFIG:
            mock_gcss.assert_called_once()
            mock_ccs.assert_called_once()
            mock_scs.assert_called_once()
        elif cifs_status == constants.CIFS_DISABLED:
            mock_gcss.assert_called()
            mock_ccs.assert_called_once()
            mock_scs.assert_called_once()
        elif cifs_status == constants.CIFS_SHARE_MODE:
            mock_gcss.assert_called_once()
            mock_ccs.assert_called_once()
        else:
            mock_gcss.assert_called_once()

    def test_check_for_setup_error_nfs_service_error(self):
        mock_gnss = self.mock_object(
            rest_helper.RestHelper, '_get_nfs_service_status',
            mock.Mock(return_value={
                "serviceStatus": constants.NFS_EXCEPTION,
                "nfs3Status": constants.NFS_NON_SUPPORTED,
                "nfs4Status": constants.NFS_NON_SUPPORTED
            }))
        self.assertRaises(exception.MacrosanBackendExeption,
                          self.driver.check_for_setup_error)
        mock_gnss.assert_called_once()

    def test_check_for_setup_error_cifs_service_error(self):
        mock_gnss = self.mock_object(
            rest_helper.RestHelper, '_get_nfs_service_status',
            mock.Mock(return_value={
                "serviceStatus": constants.NFS_ENABLED,
                "nfs3Status": constants.NFS_SUPPORTED,
                "nfs4Status": constants.NFS_SUPPORTED
            }))
        mock_gcss = self.mock_object(
            rest_helper.RestHelper, '_get_cifs_service_status',
            mock.Mock(return_value=constants.CIFS_EXCEPTION))
        self.assertRaises(exception.MacrosanBackendExeption,
                          self.driver.check_for_setup_error)
        mock_gnss.assert_called_once()
        mock_gcss.assert_called_once()

    @ddt.data('nfs', 'cifs')
    def test_create_share(self, share_proto):
        share = fake_share.fake_share(
            share_proto=share_proto, host="fake_host@fake_backend#fake_pool")
        mock_cf = self.mock_object(rest_helper.RestHelper,
                                   '_create_filesystem')
        mock_cfd = self.mock_object(rest_helper.RestHelper,
                                    '_create_filesystem_dir')
        mock_cns = self.mock_object(rest_helper.RestHelper,
                                    '_create_nfs_share')
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_ensure_user',
                         mock.Mock(return_value=True))
        mock_ccs = self.mock_object(rest_helper.RestHelper,
                                    '_create_cifs_share')
        self.driver.helper.configuration.macrosan_nas_ip = "172.0.0.1"

        location = self.driver.create_share(self._context, share)
        if share_proto == 'nfs':
            expect_location = r'172.0.0.1:/manila_fakeid/manila_fakeid'
            print('test location:', location)
            self.assertEqual(location, expect_location)
        else:
            expect_location = r'\\172.0.0.1\manila_fakeid'
            self.assertEqual(location, expect_location)
        mock_cf.assert_called_once_with(fs_name='manila_fakeid',
                                        pool_name='fake_pool',
                                        filesystem_quota='1GB')
        mock_cf.assert_called()
        share_path = self.driver.helper._generate_share_path('manila_fakeid')
        mock_cfd.assert_called_once_with(share_path)
        if share_proto == 'nfs':
            mock_cns.assert_called_once_with(share_path=share_path)
        else:
            mock_ccs.assert_called_once()

    def test_create_share_user_error(self):
        share = fake_share.fake_share(
            share_proto='cifs', host="fake_host@fake_backend#fake_pool")
        mock_cf = self.mock_object(rest_helper.RestHelper,
                                   '_create_filesystem')
        mock_cfd = self.mock_object(rest_helper.RestHelper,
                                    '_create_filesystem_dir')
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_ensure_user',
                         mock.Mock(return_value=False))
        mock_df = self.mock_object(rest_helper.RestHelper,
                                   '_delete_filesystem')
        self.assertRaises(exception.MacrosanBackendExeption,
                          self.driver.create_share,
                          self._context,
                          share)
        mock_cf.assert_called_once()
        share_path = self.driver.helper._generate_share_path('manila_fakeid')
        mock_cfd.assert_called_once_with(share_path)
        mock_df.assert_called_once_with('manila_fakeid')

    @ddt.data('nfs', 'cifs')
    def test_delete_share(self, share_proto):
        share = fake_share.fake_share(
            share_proto=share_proto, host="fake_host@fake_backend#fake_pool")
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')

        mock_gns = self.mock_object(rest_helper.RestHelper, '_get_nfs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "clients": ["client"],
                                        "protocol": "fake_protocol"
                                    }))
        mock_dns = self.mock_object(
            rest_helper.RestHelper, '_delete_nfs_share')
        mock_gcs = self.mock_object(rest_helper.RestHelper, '_get_cifs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "cifsname": "fake_cifsname",
                                        "protocol": "fake_protocol",
                                        "roList": ["fake_ro"],
                                        "rwList": ["fake_rw"],
                                        "allowList": ["fake_allow"],
                                        "denyList": ["fake_deny"]
                                    }))
        mock_dcs = self.mock_object(rest_helper.RestHelper,
                                    '_delete_cifs_share')
        mock_df = self.mock_object(rest_helper.RestHelper,
                                   '_delete_filesystem')
        self.driver.delete_share(self._context, share)

        if share_proto == "nfs":
            mock_gns.assert_called_once_with(expect_share_path)
            mock_dns.assert_called_once_with(expect_share_path)
        else:
            mock_gcs.assert_called_once_with(expect_share_path)
            mock_dcs.assert_called_once_with('manila_fakeid',
                                             expect_share_path)
        mock_df.assert_called_once_with('manila_fakeid')

    @ddt.data('nfs', 'cifs')
    def test_delete_share_not_exist(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      host="fake_host@fake_backend#fake_pool")
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gns = self.mock_object(rest_helper.RestHelper, '_get_nfs_share',
                                    mock.Mock(return_value=None))
        mock_gf = self.mock_object(rest_helper.RestHelper, '_get_filesystem',
                                   mock.Mock(return_value={
                                       "name": "fake_name",
                                       "poolName": "fake_pool",
                                       "quotaStatus": "1GB"
                                   }))
        mock_gcs = self.mock_object(rest_helper.RestHelper, '_get_cifs_share',
                                    mock.Mock(return_value=None))
        mock_df = self.mock_object(rest_helper.RestHelper,
                                   '_delete_filesystem')
        self.driver.delete_share(self._context, share)

        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(expect_share_path)
        else:
            mock_gcs.assert_called_once_with(expect_share_path)

        mock_gf.assert_called_once_with('manila_fakeid')
        mock_df.assert_called_once_with('manila_fakeid')

    @ddt.data('nfs', 'cifs')
    def test_extend_share(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      host="fake_host@fake_backend#fake_pool")
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gns = self.mock_object(rest_helper.RestHelper, '_get_nfs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "clients": ["client"],
                                        "protocol": "fake_protocol"
                                    }))
        mock_gcs = self.mock_object(rest_helper.RestHelper, '_get_cifs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "cifsname": "fake_cifsname",
                                        "protocol": "fake_protocol",
                                        "roList": ["fake_ro"],
                                        "rwList": ["fake_rw"],
                                        "allowList": ["fake_allow"],
                                        "denyList": ["fake_deny"]
                                    }))
        mock_uss = self.mock_object(rest_helper.RestHelper,
                                    '_update_share_size')
        self.driver.extend_share(share, 2)

        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(expect_share_path)
        else:
            mock_gcs.assert_called_once_with(expect_share_path)

        mock_uss.assert_called_once_with('manila_fakeid', '2GB')

    def test_extend_share_not_exist(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      size=1,
                                      host="fake_host@fake_backend#fake_pool")
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gns = self.mock_object(rest_helper.RestHelper,
                                    '_get_nfs_share',
                                    mock.Mock(return_value=None))
        self.assertRaises(exception.ShareResourceNotFound,
                          self.driver.extend_share,
                          share,
                          2)

        mock_gns.assert_called_once_with(expect_share_path)

    @ddt.data('nfs', 'cifs')
    def test_shrink_share(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      size=5,
                                      host="fake_host@fake_backend#fake_pool")
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gns = self.mock_object(rest_helper.RestHelper,
                                    '_get_nfs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "clients": ["client"],
                                        "protocol": "fake_protocol"
                                    }))
        mock_gcs = self.mock_object(rest_helper.RestHelper, '_get_cifs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "cifsname": "fake_cifsname",
                                        "protocol": "fake_protocol",
                                        "roList": ["fake_ro"],
                                        "rwList": ["fake_rw"],
                                        "allowList": ["fake_allow"],
                                        "denyList": ["fake_deny"]
                                    }))
        mock_gf = self.mock_object(rest_helper.RestHelper, '_get_filesystem',
                                   mock.Mock(return_value={
                                       "name": "fake_name",
                                       "poolName": "fake_pool",
                                       "quotaStatus": "5GB",
                                       "usedCapacity": '1GB'
                                   }))
        mock_uss = self.mock_object(rest_helper.RestHelper,
                                    '_update_share_size')
        self.driver.shrink_share(share, 3)
        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(expect_share_path)
        else:
            mock_gcs.assert_called_once_with(expect_share_path)

        mock_gf.assert_called_once_with('manila_fakeid')
        mock_uss.assert_called_once_with('manila_fakeid', '3GB')

    @ddt.data('nfs', 'cifs')
    def test_shrink_share_not_exist(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      size=3,
                                      host="fake_host@fake_backend#fake_pool")
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gns = self.mock_object(rest_helper.RestHelper, '_get_nfs_share',
                                    mock.Mock(return_value=None))
        mock_gcs = self.mock_object(rest_helper.RestHelper, '_get_cifs_share',
                                    mock.Mock(return_value=None))

        self.assertRaises(exception.ShareResourceNotFound,
                          self.driver.shrink_share,
                          share,
                          1)
        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(expect_share_path)
        elif share_proto == 'cifs':
            mock_gcs.assert_called_once_with(expect_share_path)

    def test_shrink_share_size_fail(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      size=3,
                                      host="fake_host@fake_backend#fake_pool")
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gns = self.mock_object(rest_helper.RestHelper,
                                    '_get_nfs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "clients": ["client"],
                                        "protocol": "fake_protocol"
                                    }))
        mock_gf = self.mock_object(rest_helper.RestHelper, '_get_filesystem',
                                   mock.Mock(return_value={
                                       "name": "fake_name",
                                       "poolName": "fake_pool",
                                       "quotaStatus": "3GB",
                                       "usedCapacity": '2GB'
                                   }))
        self.assertRaises(exception.ShareShrinkingPossibleDataLoss,
                          self.driver.shrink_share,
                          share,
                          1)
        mock_gf.assert_called_once_with('manila_fakeid')
        mock_gns.assert_called_once_with(expect_share_path)

    @ddt.data('nfs', 'cifs')
    def test_ensure_share(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      host="fake_host@fake_backend#fake_pool")
        mock_gns = self.mock_object(rest_helper.RestHelper, '_get_nfs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "clients": ["client"],
                                        "protocol": "fake_protocol"
                                    }))
        mock_gcs = self.mock_object(rest_helper.RestHelper, '_get_cifs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "cifsname": "fake_cifsname",
                                        "protocol": "fake_protocol",
                                        "roList": ["fake_ro"],
                                        "rwList": ["fake_rw"],
                                        "allowList": ["fake_allow"],
                                        "denyList": ["fake_deny"],
                                    }))
        self.driver.helper.configuration.macrosan_nas_ip = "172.0.0.1"
        locations = self.driver.ensure_share(self._context, share)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        if share_proto == 'nfs':
            expect_locations = [r'172.0.0.1:/manila_fakeid/manila_fakeid']
            self.assertEqual(locations, expect_locations)
            mock_gns.assert_called_once_with(expect_share_path)
        else:
            expect_locations = [r'\\172.0.0.1\manila_fakeid']
            self.assertEqual(locations, expect_locations)
            mock_gcs.assert_called_once_with(expect_share_path)

    def test_ensure_share_proto_fail(self):
        share = fake_share.fake_share(host="fake_host@fake_backend#fake_pool")
        self.mock_object(rest_helper.RestHelper, '_get_nfs_share',
                         mock.Mock(return_value={
                             "path": "fake_path",
                             "clients": ["client"],
                             "protocol": "fake_protocol"
                         }))
        self.assertRaises(exception.MacrosanBackendExeption,
                          self.driver.ensure_share,
                          self._context,
                          share)

    def test_ensure_share_not_exist(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      host="fake_host@fake_backend#fake_pool")
        mock_gns = self.mock_object(rest_helper.RestHelper, '_get_nfs_share',
                                    mock.Mock(return_value=None))
        self.assertRaises(exception.ShareResourceNotFound,
                          self.driver.ensure_share,
                          self._context,
                          share)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gns.assert_called_once_with(expect_share_path)

    @ddt.data('nfs', 'cifs')
    def test_allow_access_success(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      host="fake_host@fake_backend#fake_pool")
        if share_proto == 'nfs':
            access = {
                'access_type': 'ip',
                'access_to': '0.0.0.0/0',
                'access_level': 'rw',
            }
        else:
            access = {
                'access_type': 'user',
                'access_to': 'fake_user',
                'access_level': 'rw',
            }
        mock_gns = self.mock_object(rest_helper.RestHelper,
                                    '_get_nfs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "clients": ["client"],
                                        "protocol": "fake_protocol"
                                    }))
        mock_gafns = self.mock_object(rest_helper.RestHelper,
                                      '_get_access_from_nfs_share',
                                      mock.Mock(return_value=None))
        mock_anar = self.mock_object(rest_helper.RestHelper,
                                     '_allow_nfs_access_rest')
        mock_gcs = self.mock_object(rest_helper.RestHelper,
                                    '_get_cifs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "cifsname": "fake_cifsname",
                                        "protocol": "fake_protocol",
                                        "roList": ["fake_ro"],
                                        "rwList": ["fake_rw"],
                                        "allowList": ["fake_allow"],
                                        "denyList": ["fake_deny"],
                                    }))
        mock_gafcs = self.mock_object(rest_helper.RestHelper,
                                      '_get_access_from_cifs_share',
                                      mock.Mock(return_value=None))
        mock_acar = self.mock_object(rest_helper.RestHelper,
                                     '_allow_cifs_access_rest')
        self.driver.helper._allow_access(share, access)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        if access['access_to'] == '0.0.0.0/0':
            access['access_to'] = '*'
        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(expect_share_path)
            mock_gafns.assert_called_once_with(expect_share_path,
                                               access['access_to'])
            mock_anar.assert_called_once_with(expect_share_path,
                                              access['access_to'],
                                              access['access_level'])
        else:
            mock_gcs.assert_called_once_with(expect_share_path)
            mock_gafcs.assert_called_once_with(expect_share_path,
                                               access['access_to'])
            mock_acar.assert_called_once_with(expect_share_path,
                                              access['access_to'],
                                              access['access_level'])

    def test_allow_access_nfs_change(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'ip',
            'access_to': '172.0.0.1',
            'access_level': 'rw',
        }
        mock_gns = self.mock_object(rest_helper.RestHelper, '_get_nfs_share',
                                    mock.Mock(return_value={
                                        "path": "/manila_fakeid",
                                        "clients": ["client"],
                                        "protocol": "fake_protocol"
                                    }))
        mock_gafns = self.mock_object(rest_helper.RestHelper,
                                      '_get_access_from_nfs_share',
                                      mock.Mock(return_value={
                                          "path": "/manila_fakeid",
                                          "clientName": "fake_client_name",
                                          "accessRight": "ro",
                                      }))
        mock_cnar = self.mock_object(rest_helper.RestHelper,
                                     '_change_nfs_access_rest')
        self.driver.helper._allow_access(share, access)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gns.assert_called_once_with(expect_share_path)
        mock_gafns.assert_called_once_with(expect_share_path,
                                           access['access_to'])
        mock_cnar.assert_called_once_with(expect_share_path,
                                          access['access_to'],
                                          access['access_level'])

    def test_allow_access_cifs_change(self):
        share = fake_share.fake_share(share_proto='cifs',
                                      host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'user',
            'access_to': 'fake_user',
            'access_level': 'rw',
        }
        mock_gcs = self.mock_object(rest_helper.RestHelper,
                                    '_get_cifs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "cifsname": "fake_cifsname",
                                        "protocol": "fake_protocol",
                                        "roList": ["fake_ro"],
                                        "rwList": ["fake_rw"],
                                        "allowList": ["fake_allow"],
                                        "denyList": ["fake_deny"],
                                    }))
        mock_gafcs = self.mock_object(rest_helper.RestHelper,
                                      '_get_access_from_cifs_share',
                                      mock.Mock(return_value={
                                          "path": "fake_path",
                                          "ugName": "fake_user",
                                          "ugType": "0",
                                          "accessRight": "ro",
                                      }))
        mock_ccar = self.mock_object(rest_helper.RestHelper,
                                     '_change_cifs_access_rest')
        self.driver.helper._allow_access(share, access)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gcs.assert_called_once_with(expect_share_path)
        mock_gafcs.assert_called_once_with(expect_share_path,
                                           access['access_to'])
        mock_ccar.assert_called_once_with(expect_share_path,
                                          access['access_to'],
                                          access['access_level'],
                                          '0')

    @ddt.data(
        {
            'access_type': 'user',
            'access_to': 'user_name',
            'access_level': 'rw',
        },
        {
            'access_type': 'user',
            'access_to': 'group_name',
            'access_level': 'rw',
        },
        {
            'access_type': 'user',
            'access_to': '/domain_user',
            'access_level': 'rw',
        },
        {
            'access_type': 'user',
            'access_to': '/domain_group',
            'access_level': 'rw',
        },
    )
    def test_allow_access_cifs(self, access):
        share = fake_share.fake_share(share_proto='cifs',
                                      host="fake_host@fake_backend#fake_pool")
        mock_gcs = self.mock_object(rest_helper.RestHelper,
                                    '_get_cifs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "cifsname": "fake_cifsname",
                                        "protocol": "fake_protocol",
                                        "roList": ["fake_ro"],
                                        "rwList": ["fake_rw"],
                                        "allowList": ["fake_allow"],
                                        "denyList": ["fake_deny"],
                                    }))
        mock_gafcs = self.mock_object(rest_helper.RestHelper,
                                      '_get_access_from_cifs_share',
                                      mock.Mock(return_value=None))
        mock_acar = self.mock_object(rest_helper.RestHelper,
                                     '_allow_cifs_access_rest')

        self.driver.helper._allow_access(share, access)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gcs.assert_called_once_with(expect_share_path)
        mock_gafcs.assert_called_once_with(expect_share_path,
                                           access['access_to'])
        mock_acar.assert_called_once_with(expect_share_path,
                                          access['access_to'],
                                          access['access_level'])

    @ddt.data('nfs', 'cifs')
    def test_allow_access_share_not_exist(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      host="fake_host@fake_backend#fake_pool")
        access = {}
        if share_proto == 'nfs':
            access = {
                'access_type': 'ip',
                'access_to': '172.0.0.1',
                'access_level': 'rw',
            }
        else:
            access = {
                'access_type': 'user',
                'access_to': 'fake_user',
                'access_level': 'rw',
            }
        mock_gns = self.mock_object(rest_helper.RestHelper, '_get_nfs_share',
                                    mock.Mock(return_value=None))
        mock_gcs = self.mock_object(rest_helper.RestHelper, '_get_cifs_share',
                                    mock.Mock(return_value=None))
        self.assertRaises(exception.ShareResourceNotFound,
                          self.driver.helper._allow_access,
                          share,
                          access)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        if share_proto == 'nfs':
            mock_gns.assert_called_once_with(expect_share_path)
        else:
            mock_gcs.assert_called_once_with(expect_share_path)

    def test_allow_access_proto_fail(self):
        share = fake_share.fake_share(host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'user',
            'access_to': 'fake_user',
            'access_level': 'rw',
        }
        self.assertRaises(exception.MacrosanBackendExeption,
                          self.driver.helper._allow_access,
                          share,
                          access)

    def test_allow_access_nfs_user_fail(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'user',
            'access_to': 'fake_user',
            'access_level': 'rw',
        }
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.helper._allow_access,
                          share,
                          access)

    def test_allow_access_cifs_ip_fail(self):
        share = fake_share.fake_share(share_proto='cifs',
                                      host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'ip',
            'access_to': '172.0.0.1',
            'access_level': 'rw',
        }
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.helper._allow_access,
                          share,
                          access)

    def test_allow_access_nfs_level_fail(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'ip',
            'access_to': '172.0.0.1',
            'access_level': 'r',
        }
        self.assertRaises(exception.InvalidShareAccess,
                          self.driver.helper._allow_access,
                          share,
                          access)

    @ddt.data('nfs', 'cifs')
    def test_deny_access(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      host="fake_host@fake_backend#fake_pool")
        if share_proto == 'nfs':
            access = {
                'access_type': 'ip',
                'access_to': '0.0.0.0/0',
                'access_level': 'rw',
            }
        else:
            access = {
                'access_type': 'user',
                'access_to': 'fake_user',
                'access_level': 'rw',
            }
        mock_gafns = self.mock_object(rest_helper.RestHelper,
                                      '_get_access_from_nfs_share',
                                      mock.Mock(return_value={
                                          "path": "fake_path",
                                          "clientName": "fake_client_name",
                                          "accessRight": "rw",
                                      }))
        mock_dnar = self.mock_object(rest_helper.RestHelper,
                                     '_delete_nfs_access_rest')
        mock_gafcs = self.mock_object(rest_helper.RestHelper,
                                      '_get_access_from_cifs_share',
                                      mock.Mock(return_value={
                                          "path": "fake_path",
                                          "ugName": "fake_user",
                                          "ugType": "0",
                                          "accessRight": "rw",
                                      }))
        mock_dcar = self.mock_object(rest_helper.RestHelper,
                                     '_delete_cifs_access_rest')
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        self.driver.helper._deny_access(share, access)
        if access['access_to'] == '0.0.0.0/0':
            access['access_to'] = '*'
        if share_proto == 'nfs':
            mock_gafns.assert_called_once_with(expect_share_path,
                                               access['access_to'])
            mock_dnar.assert_called_once_with(expect_share_path,
                                              access['access_to'])
        else:
            mock_gafcs.assert_called_once_with(expect_share_path,
                                               access['access_to'])
            mock_dcar.assert_called_once_with(expect_share_path,
                                              "fake_user", "0")

    def test_deny_access_nfs_type_fail(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'fake_type',
            'access_to': '172.0.0.1',
            'access_level': 'rw',
        }
        result = self.driver.helper._deny_access(share, access)
        self.assertIsNone(result)

    def test_deny_access_nfs_share_not_exist(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'ip',
            'access_to': '172.0.0.1',
            'access_level': 'rw',
        }
        mock_gafns = self.mock_object(rest_helper.RestHelper,
                                      '_get_access_from_nfs_share',
                                      mock.Mock(return_value=None))
        result = self.driver.helper._deny_access(share, access)
        self.assertIsNone(result)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gafns.assert_called_once_with(expect_share_path,
                                           access['access_to'])

    def test_deny_access_cifs_type_fail(self):
        share = fake_share.fake_share(share_proto='cifs',
                                      host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'fake_type',
            'access_to': 'fake_user',
            'access_level': 'rw',
        }
        result = self.driver.helper._deny_access(share, access)
        self.assertIsNone(result)

    def test_deny_access_cifs_share_not_exist(self):
        share = fake_share.fake_share(share_proto='cifs',
                                      host="fake_host@fake_backend#fake_pool")
        access = {
            'access_type': 'user',
            'access_to': 'fake_user',
            'access_level': 'rw',
        }
        mock_gafcs = self.mock_object(rest_helper.RestHelper,
                                      '_get_access_from_cifs_share',
                                      mock.Mock(return_value=None))
        result = self.driver.helper._deny_access(share, access)
        self.assertIsNone(result)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        mock_gafcs.assert_called_once_with(expect_share_path,
                                           access['access_to'])

    def test_update_access_add_delete(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      host="fake_host@fake_backend#fake_pool")
        add_rules = [{'access_type': 'ip',
                      'access_to': '172.0.2.1',
                      'access_level': 'rw', }]
        delete_rules = [{'access_type': 'ip',
                         'access_to': '172.0.2.2',
                         'access_level': 'rw', }]
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_allow_access')
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_deny_access')
        self.driver.update_access(self._context, share,
                                  None, add_rules, delete_rules)

    @ddt.data('nfs', 'cifs')
    def test_update_access_nfs(self, proto):
        share = fake_share.fake_share(share_proto=proto,
                                      host="fake_host@fake_backend#fake_pool")
        if proto == 'nfs':
            access_rules = [{'access_type': 'ip',
                             'access_to': '172.0.3.1',
                             'access_level': 'rw', },
                            {'access_type': 'ip',
                             'access_to': '172.0.3.2',
                             'access_level': 'rw', }]
        else:
            access_rules = [{'access_type': 'user',
                             'access_to': 'user_l',
                             'access_level': 'rw', },
                            {'access_type': 'user',
                             'access_to': 'user_a',
                             'access_level': 'rw', }]
        mock_ca = self.mock_object(macrosan_helper.MacrosanHelper,
                                   '_clear_access')
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_allow_access')
        self.driver.update_access(self._context, share,
                                  access_rules, {}, {})
        mock_ca.assert_called_once_with(share, None)

    def test_update_access_fail(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      host="fake_host@fake_backend#fake_pool")
        access_rules = [{'access_id': 'fakeid',
                         'access_type': 'ip',
                         'access_to': '172.0.3.1',
                         'access_level': 'rw', }]
        mock_ca = self.mock_object(macrosan_helper.MacrosanHelper,
                                   '_clear_access')
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_allow_access',
                         mock.Mock(side_effect=exception.InvalidShareAccess(
                             reason='fake_exception')))
        result = self.driver.update_access(self._context, share,
                                           access_rules, None, None)
        expect = {
            'fakeid': {
                'state': 'error',
            }
        }
        self.assertEqual(result, expect)
        mock_ca.assert_called_once_with(share, None)

    def test_update_access_add_fail(self):
        share = fake_share.fake_share(share_proto='nfs',
                                      host="fake_host@fake_backend#fake_pool")
        add_rules = [{'access_id': 'fakeid',
                      'access_type': 'ip',
                      'access_to': '172.0.2.1',
                      'access_level': 'rw', }]
        delete_rules = []
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_allow_access',
                         mock.Mock(side_effect=exception.InvalidShareAccess(
                             reason='fake_exception')))
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_deny_access')
        result = self.driver.update_access(self._context, share,
                                           None, add_rules, delete_rules)
        expect = {
            'fakeid': {
                'state': 'error'
            }
        }
        self.assertEqual(result, expect)

    @ddt.data('nfs', 'cifs')
    def test__clear_access(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      host="fake_host@fake_backend#fake_pool")
        fake_nfs_share_backend = [
            {
                'share_path': 'fake_path',
                'access_to': '172.0.0.1',
                'access_level': 'rw'
            },
            {
                'share_path': 'default_path',
                'access_to': '172.0.0.2',
                'access_level': 'rw'
            }]
        fake_cifs_share_backend = [
            {
                'share_path': 'fake_path',
                'access_to': 'user_name',
                'ugType': '0',
                'access_level': 'rw'
            },
            {
                'share_path': 'default_path',
                'access_to': 'manilanobody',
                'ugType': '0',
                'access_level': 'rw'
            }]
        mock_ganar = self.mock_object(
            rest_helper.RestHelper,
            '_get_all_nfs_access_rest',
            mock.Mock(return_value=fake_nfs_share_backend))
        mock_gacar = self.mock_object(
            rest_helper.RestHelper, '_get_all_cifs_access_rest',
            mock.Mock(return_value=fake_cifs_share_backend))
        self.mock_object(rest_helper.RestHelper,
                         '_delete_nfs_access_rest')
        self.mock_object(rest_helper.RestHelper,
                         '_delete_cifs_access_rest')
        self.driver.helper._clear_access(share)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        if share_proto == 'nfs':
            mock_ganar.assert_called_once_with(expect_share_path)
        else:
            mock_gacar.assert_called_once_with(expect_share_path)

    @ddt.data('nfs', 'cifs')
    def test__clear_access_no_access_list(self, share_proto):
        share = fake_share.fake_share(share_proto=share_proto,
                                      host="fake_host@fake_backend#fake_pool")
        mock_ganar = self.mock_object(
            rest_helper.RestHelper,
            '_get_all_nfs_access_rest',
            mock.Mock(return_value=[]))
        mock_gacar = self.mock_object(
            rest_helper.RestHelper, '_get_all_cifs_access_rest',
            mock.Mock(return_value=[]))
        self.driver.helper._clear_access(share)
        expect_share_path = self.driver.helper._generate_share_path(
            'manila_fakeid')
        if share_proto == 'nfs':
            mock_ganar.assert_called_once_with(expect_share_path)
        else:
            mock_gacar.assert_called_once_with(expect_share_path)

    @ddt.data(constants.USER_NOT_EXIST,
              constants.USER_EXIST,
              constants.USER_FORMAT_ERROR)
    def test__ensure_user(self, query_result):
        mock_qu = self.mock_object(rest_helper.RestHelper,
                                   '_query_user',
                                   mock.Mock(return_value=query_result))
        mock_qg = self.mock_object(
            rest_helper.RestHelper,
            '_query_group',
            mock.Mock(return_value=constants.GROUP_NOT_EXIST))
        mock_alg = self.mock_object(rest_helper.RestHelper,
                                    '_add_localgroup')
        mock_alu = self.mock_object(rest_helper.RestHelper,
                                    '_add_localuser')
        result = self.driver.helper._ensure_user('fake_user',
                                                 'fake_passwd',
                                                 'fake_group')
        if query_result == constants.USER_NOT_EXIST:
            mock_qg.assert_called_once_with('fake_group')
            mock_alg.assert_called_once_with('fake_group')
            mock_alu.assert_called_once_with('fake_user',
                                             'fake_passwd',
                                             'fake_group')
            self.assertTrue(result)
        elif query_result == constants.USER_EXIST:
            self.assertTrue(result)
        else:
            self.assertFalse(result)
        mock_qu.assert_called_once_with('fake_user')

    def test__ensure_user_fail(self):
        mock_qu = self.mock_object(
            rest_helper.RestHelper,
            '_query_user',
            mock.Mock(return_value=constants.USER_NOT_EXIST))
        mock_qg = self.mock_object(
            rest_helper.RestHelper,
            '_query_group',
            mock.Mock(return_value=constants.GROUP_FORMAT_ERROR))
        self.assertRaises(exception.InvalidInput,
                          self.driver.helper._ensure_user,
                          'fake_user',
                          'fake_passwd',
                          'fake_group')
        mock_qu.assert_called_once_with('fake_user')
        mock_qg.assert_called_once_with('fake_group')

    def test__update_share_stats(self):
        self.driver.helper.pools = ['fake_pool']
        mock_gap = self.mock_object(rest_helper.RestHelper,
                                    '_get_all_pool',
                                    mock.Mock(return_value='fake_result'))
        mock_gpc = self.mock_object(macrosan_helper.MacrosanHelper,
                                    '_get_pool_capacity',
                                    mock.Mock(return_value={
                                        "totalcapacity": 10,
                                        "freecapacity": 9,
                                        "allocatedcapacity": 1,
                                    }))
        mock_uss = self.mock_object(driver.ShareDriver, '_update_share_stats')

        self.driver._update_share_stats()

        data = {}
        data['vendor_name'] = self.driver.VENDOR
        data['driver_version'] = self.driver.VERSION
        data['storage_protocol'] = self.driver.PROTOCOL
        data['share_backend_name'] = 'fake_share_backend_name'
        data['pools'] = [{
            'pool_name': 'fake_pool',
            'total_capacity_gb': 10,
            'free_capacity_gb': 9,
            'allocated_capacity_gb': 1,
            'reserved_percentage': 0,
            'reserved_snapshot_percentage': 0,
            'reserved_share_extend_percentage': 0,
            'dedupe': False,
            'compression': False,
            'qos': False,
            'thin_provisioning': False,
            'snapshot_support': False,
            'create_share_from_snapshot_support':
                False,
        }]
        mock_gap.assert_called_once()
        mock_gpc.assert_called_once_with('fake_pool', 'fake_result')
        mock_uss.assert_called_once_with(data)

    def test__update_share_stats_pool_not_exist(self):
        self.driver.helper.pools = ['fake_pool']
        self.mock_object(rest_helper.RestHelper, '_get_all_pool',
                         mock.Mock(return_value='fake_result'))
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_get_pool_capacity',
                         mock.Mock(return_value={}))
        self.assertRaises(exception.InvalidInput,
                          self.driver._update_share_stats
                          )

    def test__get_pool_capacity(self):
        self.mock_object(macrosan_helper.MacrosanHelper,
                         '_find_pool_info',
                         mock.Mock(return_value={
                             "name": "fake_pool",
                             "totalcapacity": "100.0G",
                             "allocatedcapacity": "22G",
                             "freecapacity": "78G",
                             "health": "ONLINE",
                             "rw": "off",
                         }))
        res = self.driver.helper._get_pool_capacity("fake_pool",
                                                    "fake_result")
        self.assertEqual(100, res['totalcapacity'])
        self.assertEqual(78, res['freecapacity'])
        self.assertEqual(22, res['allocatedcapacity'])

    def test__generate_share_name(self):
        share = fake_share.fake_share(host="fake_host@fake_backend#fake_pool")
        result = self.driver.helper._generate_share_name(share)
        self.assertEqual("manila_fakeid", result)

    def test__format_name(self):
        a = 'fake-1234567890-1234567890-1234567890'
        expect = 'fake_1234567890_1234567890_1234'
        result = self.driver.helper._format_name(a)
        self.assertEqual(expect, result)

    def test__generate_share_path(self):
        share_name = 'manila_fakeid'
        result = self.driver.helper._generate_share_path(share_name)

        self.assertEqual(r'/manila_fakeid/manila_fakeid', result)

    @ddt.data('nfs', 'cifs')
    def test__get_location_path(self, share_proto):
        self.driver.helper.configuration.macrosan_nas_ip = "172.0.0.1"
        result = self.driver.helper._get_location_path('fake_path',
                                                       'fake_name',
                                                       share_proto)
        if share_proto == 'nfs':
            expect = r'172.0.0.1:fake_path'
        elif share_proto == 'cifs':
            expect = r'\\172.0.0.1\fake_name'
        self.assertEqual(expect, result)

    def test__get_share_instance_pnp_pool_error(self):
        share = fake_share.fake_share(
            share_proto="nfs", host="fake_host@fake_backend")
        self.assertRaises(exception.InvalidHost,
                          self.driver.helper._get_share_instance_pnp,
                          share)

    def test__get_share_instance_pnp_proto_error(self):
        share = fake_share.fake_share(
            share_proto="CephFS", host="fake_host@fake_backend#fake_pool")
        self.assertRaises(exception.MacrosanBackendExeption,
                          self.driver.helper._get_share_instance_pnp,
                          share)

    @ddt.data('2000000000', '2000000KB', '2000MB', '20GB', '2TB')
    def test__unit_convert_toGB(self, capacity):
        convert = {'2000000000': '%.0f' % (float(2000000000) / 1024 ** 3),
                   '2000000KB': '%.0f' % (float(2000000) / 1024 ** 2),
                   '2000MB': '%.0f' % (float(2000) / 1024),
                   '20GB': '%.0f' % float(20),
                   '2TB': '%.0f' % (float(2) * 1024)}
        expect = float(convert[capacity])
        result = self.driver.helper._unit_convert_toGB(capacity)
        self.assertEqual(expect, result)

    @ddt.data('nfs', 'cifs')
    def test__get_share(self, proto):
        proto = proto.upper()
        mock_gns = self.mock_object(rest_helper.RestHelper,
                                    '_get_nfs_share',
                                    mock.Mock(return_value={
                                        "path": "/manila_fakeid",
                                        "clients": ["client"],
                                        "protocol": "NFS"
                                    }))
        mock_gcs = self.mock_object(rest_helper.RestHelper,
                                    '_get_cifs_share',
                                    mock.Mock(return_value={
                                        "path": "fake_path",
                                        "cifsname": "fake_cifsname",
                                        "protocol": "CIFS",
                                        "roList": ["fake_ro"],
                                        "rwList": ["fake_rw"],
                                        "allowList": ["fake_allow"],
                                        "denyList": ["fake_deny"],
                                    }))
        expect_nfs = {
            "path": "/manila_fakeid",
            "clients": ["client"],
            "protocol": "NFS"}
        expect_cifs = {
            "path": "fake_path",
            "cifsname": "fake_cifsname",
            "protocol": "CIFS",
            "roList": ["fake_ro"],
            "rwList": ["fake_rw"],
            "allowList": ["fake_allow"],
            "denyList": ["fake_deny"]}
        result = self.driver.helper._get_share('fake_path', proto)
        if proto == 'NFS':
            mock_gns.assert_called_once_with('fake_path')
            self.assertEqual(expect_nfs, result)
        elif proto == 'CIFS':
            mock_gcs.assert_called_once_with('fake_path')
            self.assertEqual(expect_cifs, result)

    def test__find_pool_info(self):
        pool_info = self.driver.helper._find_pool_info(
            'fake_pool',
            self.result_success_storage_pools)
        self.assertIsNotNone(pool_info)

    def test__find_pool_info_fail(self):
        pool_info = self.driver.helper._find_pool_info(
            'error_pool',
            self.result_success_storage_pools)
        expect = {}
        self.assertEqual(expect, pool_info)


@ddt.ddt
class RestHelperTestCase(test.TestCase):

    def setUp(self):
        self.mock_object(CONF, '_check_required_opts')
        super(RestHelperTestCase, self).setUp()

        def _safe_get(opt):
            return getattr(self.configuration, opt)

        self.configuration = mock.Mock(spec=configuration.Configuration)
        self.configuration.safe_get = mock.Mock(side_effect=_safe_get)
        self.configuration.macrosan_nas_http_protocol = 'https'
        self.configuration.macrosan_nas_ip = 'fake_ip'
        self.configuration.macrosan_nas_port = 'fake_port'
        self.configuration.macrosan_nas_prefix = 'nas'
        self.configuration.macrosan_nas_username = 'fake_username'
        self.configuration.macrosan_nas_password = 'fake_password'
        self.configuration.macrosan_timeout = 60
        self.configuration.macrosan_ssl_cert_verify = False
        self.resthelper = rest_helper.RestHelper(
            configuration=self.configuration)
        self.post = 'POST'
        self.get = 'GET'
        self.delete = 'DELETE'
        self.put = 'PUT'
        self.fake_message = 'fake_message'
        self.result_success = {
            'code': 0,
            'message': 'success',
            'data': 'fake_data'
        }
        self.result_success_return_0 = {
            'code': 0,
            'message': 'success',
            'data': '0'
        }
        self.result_success_return_1 = {
            'code': 0,
            'message': 'success',
            'data': '1'
        }
        self.result_failed = {
            'code': 1,
            'message': 'failed',
            'data': 'fake_data'
        }
        self.result_failed_not_exist = {
            'code': constants.CODE_SOURCE_NOT_EXIST,
            'message': 'failed',
            'data': '',
        }
        self.result_success_storage_pools = {
            'code': 0,
            'message': 'success',
            'data': [{
                'name': 'fake_pool',
                'size': '1000.0G',
                'allocated': '100G',
                'free': '900G',
                'health': 'ONLINE',
                'rwStatus': 'off'
            }]
        }

    @ddt.data(
        {'url': 'fake_url', 'data': {'fake_data': 'fake_value'},
         'method': 'POST'},
        {'url': 'fake_url', 'data': None,
         'method': 'GET'},
        {'url': 'fake_url', 'data': {'fake_data': 'fake_value'},
         'method': 'DELETE'},
        {'url': 'fake_url', 'data': {'fake_data': 'fake_value'},
         'method': 'PUT'},
    )
    @ddt.unpack
    def test_call(self, url, data, method):
        self.resthelper._token = 'fake_token'
        request_method = method.lower()
        fake_response = FakeResponse(200, self.result_success)
        mock_request = self.mock_object(requests, request_method,
                                        mock.Mock(return_value=fake_response))
        self.resthelper.call(url, data, method)
        expected_url = ('https://%(ip)s:%(port)s/%(rest)s/%(url)s'
                        % {'ip': 'fake_ip',
                           'port': 'fake_port',
                           'rest': 'nas',
                           'url': 'fake_url'})
        header = {'Authorization': 'fake_token'}
        mock_request.assert_called_once_with(
            expected_url, data=data, headers=header,
            timeout=self.configuration.macrosan_timeout,
            verify=False)

    def test_call_method_fail(self):
        self.resthelper._token = 'fake_token'
        self.assertRaises(exception.ShareBackendException,
                          self.resthelper.call,
                          'fake_url',
                          'fake_data',
                          'error_method')

    def test_call_token_fail(self):
        self.resthelper._token = 'fake_token'
        fake_result_fail = {
            'code': 302,
            'message': 'fake_message',
            'data': 'fake_data'
        }
        self.mock_object(self.resthelper, 'do_request',
                         mock.Mock(return_value=fake_result_fail))
        self.assertRaises(exception.MacrosanBackendExeption,
                          self.resthelper.call,
                          'fake_url',
                          'fake_data',
                          self.post)

    def test_call_token_none(self):
        self.resthelper._token = None
        self.mock_object(self.resthelper, 'do_request',
                         mock.Mock(return_value=self.result_success))
        mock_l = self.mock_object(self.resthelper, 'login',
                                  mock.Mock(return_value='fake_token'))
        self.resthelper.call('fake_url', 'fake_data', self.post)
        mock_l.assert_called_once()

    def test_call_token_expired(self):
        self.resthelper._token = 'fake_token'
        fake_result = {
            'code': 301,
            'message': 'token expired',
            'data': 'fake_data'
        }
        self.mock_object(
            self.resthelper, 'do_request',
            mock.Mock(side_effect=[fake_result, self.result_success]))
        mock_l = self.mock_object(self.resthelper, 'login',
                                  mock.Mock(return_value='fake_token'))
        self.resthelper.call('fake_url', 'fake_data', self.post)
        mock_l.assert_called_once()

    def test_call_fail(self):
        self.resthelper._token = 'fake_token'
        fake_response = FakeResponse(302, self.result_success)
        self.mock_object(requests, 'post',
                         mock.Mock(return_value=fake_response))
        self.assertRaises(exception.NetworkException,
                          self.resthelper.call,
                          'fake_url',
                          'fake_data',
                          self.post)

    def test_login(self):
        fake_result = {
            'code': 0,
            'message': 'Login success',
            'data': 'fake_token'
        }
        mock_rd = self.mock_object(self.resthelper, 'do_request',
                                   mock.Mock(return_value=fake_result))
        self.resthelper.login()
        login_data = {'userName': self.configuration.macrosan_nas_username,
                      'userPasswd': self.configuration.macrosan_nas_password}
        mock_rd.assert_called_once_with('rest/token', login_data,
                                        self.post)
        self.assertEqual('fake_token', self.resthelper._token)

    def test_login_fail(self):
        mock_rd = self.mock_object(self.resthelper, 'do_request',
                                   mock.Mock(return_value=self.result_failed))

        self.assertRaises(exception.ShareBackendException,
                          self.resthelper.login)
        login_data = {'userName': self.configuration.macrosan_nas_username,
                      'userPasswd': self.configuration.macrosan_nas_password}
        mock_rd.assert_called_once_with('rest/token', login_data,
                                        self.post)

    def test__assert_result_code(self):
        self.resthelper._assert_result_code(self.result_success,
                                            self.fake_message)

    def test__assert_result_code_fail(self):
        self.assertRaises(exception.ShareBackendException,
                          self.resthelper._assert_result_code,
                          self.result_failed,
                          self.fake_message)

    def test__assert_result_data(self):
        self.resthelper._assert_result_data(self.result_success,
                                            self.fake_message)

    def test__assert_result_data_fail(self):
        fake_result = {
            'code': 0,
            'message': 'fake_message'
        }
        self.assertRaises(exception.ShareBackendException,
                          self.resthelper._assert_result_data,
                          fake_result,
                          self.fake_message)

    def test__create_nfs_share(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._create_nfs_share('fake_path')
        url = 'rest/nfsShare'
        data = {
            'path': 'fake_path',
            'authority': 'ro',
            'accessClient': '192.0.2.0',
        }
        mock_call.assert_called_once_with(url, data, self.post)

    def test__get_nfs_share(self):
        fake_result = {
            'code': 0,
            'message': 'success',
            'data': {
                "path": "fake_path",
                "clients": ["client"],
                "protocol": "fake_protocol"
            }
        }
        mock_call = self.mock_object(self.resthelper,
                                     'call',
                                     mock.Mock(return_value=fake_result))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_nfs_share('fake_path')
        expect = {
            "path": "fake_path",
            "clients": ["client"],
            "protocol": "fake_protocol"
        }
        self.assertEqual(expect, result)
        url = 'rest/nfsShare?path=fake_path'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__delete_nfs_share(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._delete_nfs_share('fake_path')
        url = 'rest/nfsShare?path=fake_path'
        mock_call.assert_called_once_with(url, None, self.delete)

    def test__create_cifs_share(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._create_cifs_share('fake_name',
                                           'fake_path',
                                           ['fake_user'],
                                           ['0'])
        url = 'rest/cifsShare'
        data = {
            'path': 'fake_path',
            'cifsName': 'fake_name',
            'cifsDescription': '',
            'RoList': [],
            'RoListType': [],
            'RwList': ['fake_user'],
            'RwListType': ['0'],
            'allowList': [],
            'denyList': [],
        }
        mock_call.assert_called_once_with(url, data, self.post)

    def test__get_cifs_share(self):
        fake_result = {
            'code': 0,
            'message': 'success',
            'data': {
                "path": "fake_path",
                "cifsname": "fake_cifsname",
                "protocol": "fake_protocol",
                "roList": ["fake_ro"],
                "rwList": ["fake_rw"],
                "allowList": ["fake_allow"],
                "denyList": ["fake_deny"]
            }
        }
        mock_call = self.mock_object(self.resthelper,
                                     'call',
                                     mock.Mock(return_value=fake_result))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_cifs_share('fake_path')
        expect = {
            "path": "fake_path",
            "cifsname": "fake_cifsname",
            "protocol": "fake_protocol",
            "roList": ["fake_ro"],
            "rwList": ["fake_rw"],
            "allowList": ["fake_allow"],
            "denyList": ["fake_deny"]
        }
        self.assertEqual(expect, result)
        url = 'rest/cifsShare?path=fake_path'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__delete_cifs_share(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._delete_cifs_share('fake_name', 'fake_path')
        url = 'rest/cifsShare?path=fake_path&cifsName=fake_name'
        mock_call.assert_called_once_with(url, None, self.delete)

    def test__update_share_size(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._update_share_size('fake_filesystem', '2GB')
        url = 'rest/filesystem/fake_filesystem'
        data = {
            'capacity': '2GB',
        }
        mock_call.assert_called_once_with(url, data, self.put)

    def test___create_filesystem(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._create_filesystem('fake_filesystem',
                                           'fake_pool',
                                           '1GB')
        url = 'rest/filesystem'
        data = {
            'fsName': 'fake_filesystem',
            'poolName': 'fake_pool',
            'createType': '0',
            'fileSystemQuota': '1GB',
            'fileSystemReserve': '1GB',
            'wormStatus': 0,
            'defaultTimeStatus': 0,
            'defaultTimeNum': 0,
            'defaultTimeUnit': 'year',
            'isAutoLock': 0,
            'isAutoDelete': 0,
            'lockTime': 0
        }
        mock_call.assert_called_once_with(url, data, self.post)

    def test__delete_filesystem(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._delete_filesystem('fake_filesystem')
        url = 'rest/filesystem/fake_filesystem'
        mock_call.assert_called_once_with(url, None, self.delete)

    def test__get_filesystem(self):
        fake_result = {
            'code': 0,
            'message': 'success',
            'data': {
                'name': 'fake_filesystem',
                'poolName': 'fake_pool',
            }
        }
        mock_call = self.mock_object(self.resthelper,
                                     'call',
                                     mock.Mock(return_value=fake_result))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_filesystem('fake_filesystem')
        expect = {
            'name': 'fake_filesystem',
            'poolName': 'fake_pool',
        }
        self.assertEqual(expect, result)
        url = 'rest/filesystem/fake_filesystem'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__create_filesystem_dir(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._create_filesystem_dir('/fake_path/fake_dir')
        url = 'rest/fileDir'
        data = {
            'path': '/fake_path',
            'dirName': 'fake_dir',
        }
        mock_call.assert_called_once_with(url, data, self.post)

    def test__delete_filesystem_dir(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._delete_filesystem_dir('/fake_path/fake_dir')
        url = 'rest/fileDir?path=/fake_path&dirName=fake_dir'
        mock_call.assert_called_once_with(url, None, self.delete)

    @ddt.data('nfs', 'cifs')
    def test__allow_access_rest(self, share_proto):
        share_proto = share_proto.upper()
        mock_anar = self.mock_object(self.resthelper,
                                     '_allow_nfs_access_rest')
        mock_acar = self.mock_object(self.resthelper,
                                     '_allow_cifs_access_rest')
        self.resthelper._allow_access_rest('fake_path', 'fake_access',
                                           'rw', share_proto)
        if share_proto == 'NFS':
            mock_anar.assert_called_once_with('fake_path',
                                              'fake_access',
                                              'rw')
        elif share_proto == 'CIFS':
            mock_acar.assert_called_once_with('fake_path',
                                              'fake_access',
                                              'rw')

    def test__allow_access_rest_proto_error(self):
        self.assertRaises(exception.InvalidInput,
                          self.resthelper._allow_access_rest,
                          'fake_path',
                          'fake_access',
                          'rw',
                          'error_proto')

    def test__allow_nfs_access_rest(self):
        mock_call = self.mock_object(
            self.resthelper,
            'call',
            mock.Mock(return_value=self.result_success))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._allow_nfs_access_rest('fake_path', '172.0.0.1', 'rw')
        url = 'rest/nfsShareClient'
        data = {
            'path': 'fake_path',
            'client': '172.0.0.1',
            'authority': 'rw',
        }
        mock_call.assert_called_once_with(url, data, self.post)

    @ddt.data(
        {'access_to': 'fake_user',
         'group': False},
        {'access_to': 'fake_group',
         'group': True},
        {'access_to': '/fake_user',
         'group': False},
        {'access_to': '/fake_group',
         'group': True}
    )
    @ddt.unpack
    def test__allow_cifs_access_rest(self, access_to, group):
        ug_type_list = {
            'localUser': '0',
            'localGroup': '1',
            'adUser': '2',
            'adGroup': '3',
        }
        if not group:
            mock_call = self.mock_object(
                self.resthelper,
                'call',
                mock.Mock(return_value=self.result_success))
        else:
            mock_call = self.mock_object(
                self.resthelper,
                'call',
                mock.Mock(side_effect=[self.result_failed_not_exist,
                                       self.result_success]))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._allow_cifs_access_rest('fake_path',
                                                access_to,
                                                'rw')
        url = 'rest/cifsShareClient'
        actual_type = ug_type_list["localUser"]
        if '/' not in access_to:
            if not group:
                actual_type = ug_type_list["localUser"]
            access_to = access_to
        else:
            if not group:
                actual_type = ug_type_list["adUser"]
            access_to = access_to[access_to.index('/') + 1:]
        data = {
            'path': 'fake_path',
            'right': 'rw',
            'ugName': access_to,
            'ugType': actual_type,
        }
        if not group:
            mock_call.assert_called_once_with(url, data, self.post)
        else:
            mock_call.assert_called()

    def test__allow_cifs_access_rest_fail(self):
        mock_call = self.mock_object(
            self.resthelper,
            'call',
            mock.Mock(side_effect=[self.result_failed_not_exist,
                                   self.result_failed_not_exist]))
        self.assertRaises(exception.InvalidShare,
                          self.resthelper._allow_cifs_access_rest,
                          'fake_path',
                          'fake_user',
                          'rw')
        mock_call.assert_called()

    def test__get_access_from_nfs_share(self):
        fake_result = {
            'code': 0,
            'message': 'success',
            'data': {
                "path": "fake_path",
                "clientName": "fake_client",
                "accessRight": "rw",
            }
        }
        mock_call = self.mock_object(self.resthelper,
                                     'call',
                                     mock.Mock(return_value=fake_result))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_access_from_nfs_share('fake_path',
                                                            'fake_client')
        expect = {
            "path": "fake_path",
            "clientName": "fake_client",
            "accessRight": "rw",
        }
        self.assertEqual(expect, result)
        url = 'rest/nfsShareClient?path=fake_path&client=fake_client'
        mock_call.assert_called_once_with(url, None, self.get)

    @ddt.data({'access_to': 'fake_user',
               'ug_type': '0',
               'code': 0,
               'group': False},
              {'access_to': 'fake_user',
               'ug_type': None,
               'code': 0,
               'group': False},
              {'access_to': 'fake_group',
               'ug_type': None,
               'code': 0,
               'group': True},
              {'access_to': 'fake_user',
               'ug_type': None,
               'code': 4,
               'group': False},
              {'access_to': '/fake_user',
               'ug_type': None,
               'code': 0,
               'group': False},
              {'access_to': '/fake_group',
               'ug_type': None,
               'code': 0,
               'group': True},
              {'access_to': '/fake_user',
               'ug_type': None,
               'code': 4,
               'group': False})
    @ddt.unpack
    def test__get_access_from_cifs_share(self,
                                         access_to, ug_type, code, group):
        fake_result_failed = {
            'code': code,
            'message': 'failed',
            'data': {}
        }
        fake_result = {
            'code': code,
            'message': 'success',
            'data': {
                'path': 'fake_path',
                'ugName': 'fake_user',
                'ugType': '0',
                'accessRight': 'rw'
            }
        }
        fake_result_group = {
            'code': code,
            'message': 'success',
            'data': {
                'path': 'fake_path',
                'ugName': 'fake_group',
                'ugType': '1',
                'accessRight': 'rw'
            }
        }
        if code == 4:
            fake_result = fake_result_failed
        ug_type_list = {
            'localUser': '0',
            'localGroup': '1',
            'adUser': '2',
            'adGroup': '3',
        }
        expect = {
            'path': 'fake_path',
            'ugName': 'fake_user',
            'ugType': '0',
            'accessRight': 'rw'
        }
        expect_group = {
            'path': 'fake_path',
            'ugName': 'fake_group',
            'ugType': '1',
            'accessRight': 'rw'
        }
        if '/' in access_to:
            expect['ugType'] = '2'
            expect_group['ugType'] = '3'
            fake_result['data']['ugType'] = '2'
            fake_result_group['data']['ugType'] = '3'
        if ug_type is not None:
            mock_call = self.mock_object(self.resthelper,
                                         'call',
                                         mock.Mock(return_value=fake_result))
        else:
            if not group:
                mock_call = self.mock_object(
                    self.resthelper,
                    'call',
                    mock.Mock(return_value=fake_result))
            else:
                mock_call = self.mock_object(
                    self.resthelper,
                    'call',
                    mock.Mock(side_effect=[fake_result_failed,
                                           fake_result_group]))

        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_access_from_cifs_share('fake_path',
                                                             access_to,
                                                             ug_type)
        if ug_type:
            self.assertEqual(expect, result)
            url = f'rest/cifsShareClient?path=fake_path&' \
                  f'ugName={access_to}&ugType={ug_type}'
            mock_call.assert_called_once_with(url, None, self.get)
        else:
            if '/' not in access_to:
                if not group:
                    actual_type = ug_type_list["localUser"]
                actual_access = access_to
            else:
                if not group:
                    actual_type = ug_type_list["adUser"]
                actual_access = access_to[access_to.index('/') + 1:]
            if code == 4:
                self.assertIsNone(result)
            else:
                if not group:
                    self.assertEqual(expect, result)
                    url = f'rest/cifsShareClient?path=fake_path&' \
                          f'ugName={actual_access}&' \
                          f'ugType={actual_type}'
                    mock_call.assert_called_once_with(url, None, self.get)
                else:
                    self.assertEqual(expect_group, result)
                    mock_call.assert_called()

    def test__get_all_nfs_access_rest(self):
        fake_result = {
            'code': 0,
            'message': 'success',
            'data': [
                {
                    'path': 'fake_path',
                    'clientName': '172.0.0.1',
                    'accessRight': 'rw'
                },
                {
                    'path': 'default_path',
                    'clientName': '172.0.0.2',
                    'accessRight': 'rw'
                }]
        }
        mock_call = self.mock_object(self.resthelper,
                                     'call',
                                     mock.Mock(return_value=fake_result))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_all_nfs_access_rest(
            '/manila_fakeid/manila_fakeid')
        expect = [
            {
                'share_path': 'fake_path',
                'access_to': '172.0.0.1',
                'access_level': 'rw'
            },
            {
                'share_path': 'default_path',
                'access_to': '172.0.0.2',
                'access_level': 'rw'
            }]
        self.assertEqual(expect, result)
        url = 'rest/allNfsShareClient?path=/manila_fakeid/manila_fakeid'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__get_all_cifs_access_rest(self):
        fake_result = {
            'code': 0,
            'message': 'success',
            'data': [
                {
                    'path': 'fake_path',
                    'ugName': 'user_name',
                    'ugType': '0',
                    'accessRight': 'rw'
                },
                {
                    'path': 'default_path',
                    'ugName': 'manilanobody',
                    'ugType': '0',
                    'accessRight': 'rw'
                }]
        }
        mock_call = self.mock_object(self.resthelper,
                                     'call',
                                     mock.Mock(return_value=fake_result))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_all_cifs_access_rest(
            '/manila_fakeid/manila_fakeid')
        expect = [
            {
                'share_path': 'fake_path',
                'access_to': 'user_name',
                'ugType': '0',
                'access_level': 'rw'
            },
            {
                'share_path': 'default_path',
                'access_to': 'manilanobody',
                'ugType': '0',
                'access_level': 'rw'
            }]
        self.assertEqual(expect, result)
        url = 'rest/allCifsShareClient?path=/manila_fakeid/manila_fakeid'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__change_nfs_access_rest(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._change_nfs_access_rest(
            '/manila_fakeid/manila_fakeid', '172.0.0.1', 'rw')
        url = 'rest/nfsShareClient'
        data = {
            'path': '/manila_fakeid/manila_fakeid',
            'oldNfsClientName': '172.0.0.1',
            'clientName': '',
            'accessRight': 'rw',
            'allSquash': '',
            'rootSquash': '',
            'secure': '',
            'anonuid': '',
            'anongid': '',
        }
        mock_call.assert_called_once_with(url, data, self.put)

    def test__change_cifs_access_rest(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._change_cifs_access_rest(
            '/manila_fakeid/manila_fakeid', '/fake_user', 'rw', '0')
        url = 'rest/cifsShareClient'
        data = {
            'path': '/manila_fakeid/manila_fakeid',
            'right': 'rw',
            'ugName': 'fake_user',
            'ugType': '0',
        }
        mock_call.assert_called_once_with(url, data, self.put)

    def test__delete_nfs_access_rest(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._delete_nfs_access_rest(
            '/manila_fakeid/manila_fakeid', '*')
        url = 'rest/nfsShareClient?path=/manila_fakeid/manila_fakeid&client=*'
        mock_call.assert_called_once_with(url, None, self.delete)

    def test__delete_cifs_access_rest(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._delete_cifs_access_rest(
            '/manila_fakeid/manila_fakeid', 'fake_user', '0')
        url = 'rest/cifsShareClient?path=/manila_fakeid/manila_fakeid' \
              '&ugName=fake_user&ugType=0'
        mock_call.assert_called_once_with(url, None, self.delete)

    def test__get_nfs_service_status(self):
        fake_result = {
            'code': 0,
            'message': 'success',
            'data': {
                'serviceStatus': constants.NFS_ENABLED,
                'nfs3Status': constants.NFS_SUPPORTED,
                'nfs4Status': constants.NFS_SUPPORTED
            }
        }
        mock_call = self.mock_object(self.resthelper,
                                     'call',
                                     mock.Mock(return_value=fake_result))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_nfs_service_status()
        expect = {
            'serviceStatus': constants.NFS_ENABLED,
            'nfs3Status': constants.NFS_SUPPORTED,
            'nfs4Status': constants.NFS_SUPPORTED
        }
        self.assertEqual(expect, result)
        url = 'rest/nfsService'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__start_nfs_service(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._start_nfs_service()
        url = 'rest/nfsService'
        data = {
            "openStatus": "1",
        }
        mock_call.assert_called_once_with(url, data, self.put)

    def test__config_nfs_service(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._config_nfs_service()
        url = 'rest/nfsConfig'
        data = {
            'configNfs3': "yes",
            'configNfs4': "yes",
        }
        mock_call.assert_called_once_with(url, data, self.put)

    def test__get_cifs_service_status(self):
        mock_call = self.mock_object(
            self.resthelper,
            'call',
            mock.Mock(return_value=self.result_success_return_1))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_cifs_service_status()
        self.assertEqual('1', result)
        url = 'rest/cifsService'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__start_cifs_service(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._start_cifs_service()
        url = 'rest/cifsService'
        data = {
            'openStatus': '1',
        }
        mock_call.assert_called_once_with(url, data, self.put)

    def test__config_cifs_service(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._config_cifs_service()
        url = 'rest/cifsConfig'
        data = {
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
        mock_call.assert_called_once_with(url, data, self.put)

    def test__get_all_pool(self):
        mock_call = self.mock_object(
            self.resthelper,
            'call',
            mock.Mock(return_value=self.result_success_storage_pools))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._get_all_pool()
        self.assertEqual(self.result_success_storage_pools, result)
        url = 'rest/storagepool'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__query_user(self):
        mock_call = self.mock_object(
            self.resthelper,
            'call',
            mock.Mock(return_value=self.result_success_return_0))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._query_user('fake_user')
        self.assertEqual('0', result)
        url = 'rest/user/fake_user'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__add_localuser(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._add_localuser('fake_user',
                                       'fake_passwd', 'fake_group')
        url = 'rest/localUser'
        data = {
            'userName': 'fake_user',
            'mgGroup': 'fake_group',
            'userPasswd': 'fake_passwd',
            'unusedGroup': []}
        mock_call.assert_called_once_with(url, data, self.post)

    def test__query_group(self):
        mock_call = self.mock_object(
            self.resthelper,
            'call',
            mock.Mock(return_value=self.result_success_return_0))
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        result = self.resthelper._query_group('fake_group')
        self.assertEqual('0', result)
        url = 'rest/group/fake_group'
        mock_call.assert_called_once_with(url, None, self.get)

    def test__add_localgroup(self):
        mock_call = self.mock_object(self.resthelper,
                                     'call')
        self.mock_object(self.resthelper,
                         '_assert_result_code')
        self.resthelper._add_localgroup('fake_group')
        url = 'rest/localGroup'
        data = {'groupName': 'fake_group'}
        mock_call.assert_called_once_with(url, data, self.post)
