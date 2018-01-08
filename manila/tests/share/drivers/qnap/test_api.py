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

import base64

import ddt
import mock
import six
from six.moves import urllib
import time

from manila import exception
from manila.share.drivers.qnap import qnap
from manila import test
from manila.tests import fake_share
from manila.tests.share.drivers.qnap import fakes


def create_configuration(management_url, qnap_share_ip, qnap_nas_login,
                         qnap_nas_password, qnap_poolname):
    """Create configuration."""
    configuration = mock.Mock()
    configuration.qnap_management_url = management_url
    configuration.qnap_share_ip = qnap_share_ip
    configuration.qnap_nas_login = qnap_nas_login
    configuration.qnap_nas_password = qnap_nas_password
    configuration.qnap_poolname = qnap_poolname
    configuration.safe_get.return_value = False
    return configuration


class QnapShareDriverBaseTestCase(test.TestCase):
    """Base Class for the QnapShareDriver Tests."""

    def setUp(self):
        """Setup the Qnap Driver Base TestCase."""
        super(QnapShareDriverBaseTestCase, self).setUp()
        self.driver = None
        self.share_api = None

    def _do_setup(self, management_url, share_ip, nas_login,
                  nas_password, poolname, **kwargs):
        """Config do setup configurations."""
        self.driver = qnap.QnapShareDriver(
            configuration=create_configuration(
                management_url,
                share_ip,
                nas_login,
                nas_password,
                poolname),
            private_storage=kwargs.get('private_storage'))
        self.driver.do_setup('context')


@ddt.ddt
class QnapAPITestCase(QnapShareDriverBaseTestCase):
    """Tests QNAP api functions."""

    login_url = ('/cgi-bin/authLogin.cgi?')
    get_basic_info_url = ('/cgi-bin/authLogin.cgi')
    fake_password = 'qnapadmin'

    def setUp(self):
        """Setup the Qnap API TestCase."""
        super(QnapAPITestCase, self).setUp()
        fake_parms = {}
        fake_parms['user'] = 'admin'
        fake_parms['pwd'] = base64.b64encode(
            self.fake_password.encode("utf-8"))
        fake_parms['serviceKey'] = 1
        sanitized_params = self._sanitize_params(fake_parms)
        self.login_url = ('/cgi-bin/authLogin.cgi?%s' % sanitized_params)
        self.mock_object(six.moves.http_client, 'HTTPConnection')
        self.share = fake_share.fake_share(
            share_proto='NFS',
            id='shareId',
            display_name='fakeDisplayName',
            export_locations=[{'path': '1.2.3.4:/share/fakeShareName'}],
            host='QnapShareDriver',
            size=10)

    def _sanitize_params(self, params, doseq=False):
        sanitized_params = {}
        for key in params:
            value = params[key]
            if value is not None:
                if isinstance(value, list):
                    sanitized_params[key] = [six.text_type(v) for v in value]
                else:
                    sanitized_params[key] = six.text_type(value)

        sanitized_params = urllib.parse.urlencode(sanitized_params, doseq)
        return sanitized_params

    @ddt.data('fake_share_name', 'fakeLabel')
    def test_create_share_api(self, fake_name):
        """Test create share api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeCreateShareResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.create_share(
            self.share,
            'Storage Pool 1',
            fake_name,
            'NFS',
            qnap_deduplication=False,
            qnap_compression=True,
            qnap_thin_provision=True,
            qnap_ssd_cache=False)

        fake_params = {
            'wiz_func': 'share_create',
            'action': 'add_share',
            'vol_name': fake_name,
            'vol_size': '10' + 'GB',
            'threshold': '80',
            'dedup': 'off',
            'compression': '1',
            'thin_pro': '1',
            'cache': '0',
            'cifs_enable': '0',
            'nfs_enable': '1',
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
            'pool_name': 'Storage Pool 1',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = ('/cgi-bin/wizReq.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_api_delete_share(self):
        """Test delete share api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeDeleteShareResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.delete_share(
            'fakeId')

        fake_params = {
            'func': 'volume_mgmt',
            'vol_remove': '1',
            'volumeID': 'fakeId',
            'stop_service': 'no',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            '/cgi-bin/disk/disk_manage.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_get_specific_poolinfo(self):
        """Test get specific poolinfo api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeSpecificPoolInfoResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.get_specific_poolinfo(
            'fakePoolId')

        fake_params = {
            'store': 'poolInfo',
            'func': 'extra_get',
            'poolID': 'fakePoolId',
            'Pool_Info': '1',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            '/cgi-bin/disk/disk_manage.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    @ddt.data({'pool_id': "Storage Pool 1"},
              {'pool_id': "Storage Pool 1", 'vol_no': 'fakeNo'},
              {'pool_id': "Storage Pool 1", 'vol_label': 'fakeShareName'})
    def test_get_share_info(self, dict_parm):
        """Test get share info api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeShareInfoResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.get_share_info(**dict_parm)

        fake_params = {
            'store': 'poolVolumeList',
            'poolID': 'Storage Pool 1',
            'func': 'extra_get',
            'Pool_Vol_Info': '1',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            '/cgi-bin/disk/disk_manage.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_get_specific_volinfo(self):
        """Test get specific volume info api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeSpecificVolInfoResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.get_specific_volinfo(
            'fakeNo')

        fake_params = {
            'store': 'volumeInfo',
            'volumeID': 'fakeNo',
            'func': 'extra_get',
            'Volume_Info': '1',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            '/cgi-bin/disk/disk_manage.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_get_snapshot_info_es(self):
        """Test get snapsho info api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeSnapshotInfoResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.get_snapshot_info(
            volID='volId', snapshot_name='fakeSnapshotName')

        fake_params = {
            'func': 'extra_get',
            'volumeID': 'volId',
            'snapshot_list': '1',
            'snap_start': '0',
            'snap_count': '100',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            '/cgi-bin/disk/snapshot.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_create_snapshot_api(self):
        """Test create snapshot api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeCreateSnapshotResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.create_snapshot_api(
            'fakeVolumeId',
            'fakeSnapshotName')

        fake_params = {
            'func': 'create_snapshot',
            'volumeID': 'fakeVolumeId',
            'snapshot_name': 'fakeSnapshotName',
            'expire_min': '0',
            'vital': '1',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            '/cgi-bin/disk/snapshot.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    @ddt.data(fakes.FakeDeleteSnapshotResponse(),
              fakes.FakeDeleteSnapshotResponseSnapshotNotExist(),
              fakes.FakeDeleteSnapshotResponseShareNotExist())
    def test_delete_snapshot_api(self, fakeDeleteSnapshotResponse):
        """Test delete snapshot api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakeDeleteSnapshotResponse]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.delete_snapshot_api(
            'fakeSnapshotId')

        fake_params = {
            'func': 'del_snapshots',
            'snapshotID': 'fakeSnapshotId',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            '/cgi-bin/disk/snapshot.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_clone_snapshot_api(self):
        """Test clone snapshot api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeDeleteSnapshotResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.clone_snapshot(
            'fakeSnapshotId',
            'fakeNewShareName')

        fake_params = {
            'func': 'clone_qsnapshot',
            'by_vol': '1',
            'snapshotID': 'fakeSnapshotId',
            'new_name': 'fakeNewShareName',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            '/cgi-bin/disk/snapshot.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_edit_share_api(self):
        """Test edit share api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseTs_4_3_0(),
            fakes.FakeLoginResponse(),
            fakes.FakeCreateSnapshotResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        expect_share_dict = {
            "sharename": 'fakeVolId',
            "old_sharename": 'fakeVolId',
            "new_size": 100,
            "deduplication": False,
            "compression": True,
            "thin_provision": True,
            "ssd_cache": False,
            "share_proto": "NFS"
        }
        self.driver.api_executor.edit_share(
            expect_share_dict)

        fake_params = {
            'wiz_func': 'share_property',
            'action': 'share_property',
            'sharename': 'fakeVolId',
            'old_sharename': 'fakeVolId',
            'vol_size': '100GB',
            'dedup': 'off',
            'compression': '1',
            'thin_pro': '1',
            'cache': '0',
            'cifs_enable': '0',
            'nfs_enable': '1',
            'afp_enable': '0',
            'ftp_enable': '0',
            'hidden': '0',
            'oplocks': '1',
            'sync': 'always',
            'recycle_bin': '1',
            'recycle_bin_administrators_only': '0',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            '/cgi-bin/priv/privWizard.cgi?%s' % sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    @ddt.data(fakes.FakeGetHostListResponse(),
              fakes.FakeGetNoHostListResponse())
    def test_get_host_list(self, fakeGetHostListResponse):
        """Test get host list api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakeGetHostListResponse]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.get_host_list()

        fake_params = {
            'module': 'hosts',
            'func': 'get_hostlist',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            ('/cgi-bin/accessrights/accessrightsRequest.cgi?%s') %
            sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_add_host(self):
        """Test add host api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeGetHostListResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.add_host(
            'fakeHostName', 'fakeIpV4')

        fake_params = {
            'module': 'hosts',
            'func': 'apply_addhost',
            'name': 'fakeHostName',
            'ipaddr_v4': 'fakeIpV4',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            ('/cgi-bin/accessrights/accessrightsRequest.cgi?%s') %
            sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_edit_host(self):
        """Test edit host api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeGetHostListResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.edit_host(
            'fakeHostName', ['fakeIpV4'])

        fake_params = {
            'module': 'hosts',
            'func': 'apply_sethost',
            'name': 'fakeHostName',
            'ipaddr_v4': ['fakeIpV4'],
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params, doseq=True)
        fake_url = (
            ('/cgi-bin/accessrights/accessrightsRequest.cgi?%s') %
            sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_delete_host(self):
        """Test delete host api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakes.FakeGetHostListResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.delete_host('fakeHostName')

        fake_params = {
            'module': 'hosts',
            'func': 'apply_delhost',
            'host_name': 'fakeHostName',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            ('/cgi-bin/accessrights/accessrightsRequest.cgi?%s') %
            sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    @ddt.data(fakes.FakeGetHostListResponse())
    def test_set_nfs_access(self, fakeGetHostListResponse):
        """Test get host list api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fakeGetHostListResponse]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.set_nfs_access(
            'fakeShareName', 'fakeAccess', 'fakeHostName')

        fake_params = {
            'wiz_func': 'share_nfs_control',
            'action': 'share_nfs_control',
            'sharename': 'fakeShareName',
            'access': 'fakeAccess',
            'host_name': 'fakeHostName',
            'sid': 'fakeSid',
        }
        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            ('/cgi-bin/priv/privWizard.cgi?%s') %
            sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    def test_get_snapshot_info_ts_api(self):
        """Test get snapshot info api."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseTs_4_3_0(),
            fakes.FakeLoginResponse(),
            fakes.FakeSnapshotInfoResponse()]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.driver.api_executor.get_snapshot_info(
            snapshot_name='fakeSnapshotName',
            lun_index='fakeLunIndex')

        fake_params = {
            'func': 'extra_get',
            'LUNIndex': 'fakeLunIndex',
            'smb_snapshot_list': '1',
            'smb_snapshot': '1',
            'snapshot_list': '1',
            'sid': 'fakeSid'}

        sanitized_params = self._sanitize_params(fake_params)
        fake_url = (
            ('/cgi-bin/disk/snapshot.cgi?%s') %
            sanitized_params)

        expected_call_list = [
            mock.call('GET', self.login_url),
            mock.call('GET', self.get_basic_info_url),
            mock.call('GET', self.login_url),
            mock.call('GET', fake_url)]
        self.assertEqual(
            expected_call_list,
            mock_http_connection.return_value.request.call_args_list)

    @ddt.data(fakes.FakeAuthPassFailResponse(),
              fakes.FakeEsResCodeNegativeResponse())
    def test_api_create_share_with_fail_response(self, fake_fail_response):
        """Test create share api with fail response."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fakes.FakeGetBasicInfoResponseEs_1_1_3(),
            fakes.FakeLoginResponse(),
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response]

        self.mock_object(time, 'sleep')
        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.api_executor.create_share,
            share=self.share,
            pool_name='Storage Pool 1',
            create_share_name='fake_share_name',
            share_proto='NFS',
            qnap_deduplication=False,
            qnap_compression=True,
            qnap_thin_provision=True,
            qnap_ssd_cache=False)

    @ddt.unpack
    @ddt.data(['self.driver.api_executor.get_share_info',
              {'pool_id': 'fakeId'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.get_specific_volinfo',
              {'vol_id': 'fakeId'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.create_snapshot_api',
              {'volumeID': 'fakeVolumeId',
               'snapshot_name': 'fakeSnapshotName'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.create_snapshot_api',
              {'volumeID': 'fakeVolumeId',
               'snapshot_name': 'fakeSnapshotName'},
              fakes.FakeEsResCodeNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.get_snapshot_info',
              {'volID': 'volId'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.get_snapshot_info',
              {'volID': 'volId'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.get_specific_poolinfo',
              {'pool_id': 'Storage Pool 1'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.get_specific_poolinfo',
              {'pool_id': 'Storage Pool 1'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.delete_share',
              {'vol_id': 'fakeId'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.delete_share',
              {'vol_id': 'fakeId'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.delete_snapshot_api',
              {'snapshot_id': 'fakeSnapshotId'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.delete_snapshot_api',
              {'snapshot_id': 'fakeSnapshotId'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.clone_snapshot',
              {'snapshot_id': 'fakeSnapshotId',
               'new_sharename': 'fakeNewShareName'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.clone_snapshot',
              {'snapshot_id': 'fakeSnapshotId',
               'new_sharename': 'fakeNewShareName'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.edit_share',
              {'share_dict': {"sharename": 'fakeVolId',
                              "old_sharename": 'fakeVolId',
                              "new_size": 100,
                              "deduplication": False,
                              "compression": True,
                              "thin_provision": False,
                              "ssd_cache": False,
                              "share_proto": "NFS"}},
              fakes.FakeEsResCodeNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.edit_share',
              {'share_dict': {"sharename": 'fakeVolId',
                              "old_sharename": 'fakeVolId',
                              "new_size": 100,
                              "deduplication": False,
                              "compression": True,
                              "thin_provision": False,
                              "ssd_cache": False,
                              "share_proto": "NFS"}},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.add_host',
              {'hostname': 'fakeHostName',
               'ipv4': 'fakeIpV4'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.add_host',
              {'hostname': 'fakeHostName',
               'ipv4': 'fakeIpV4'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.edit_host',
              {'hostname': 'fakeHostName',
               'ipv4_list': 'fakeIpV4List'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.edit_host',
              {'hostname': 'fakeHostName',
               'ipv4_list': 'fakeIpV4List'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.delete_host',
              {'hostname': 'fakeHostName'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.delete_host',
              {'hostname': 'fakeHostName'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.get_host_list',
              {},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.get_host_list',
              {},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.set_nfs_access',
              {'sharename': 'fakeShareName',
               'access': 'fakeAccess',
               'host_name': 'fakeHostName'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.set_nfs_access',
              {'sharename': 'fakeShareName',
               'access': 'fakeAccess',
               'host_name': 'fakeHostName'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseEs_1_1_3()],
              ['self.driver.api_executor.get_snapshot_info',
              {'snapshot_name': 'fakeSnapshoName',
               'lun_index': 'fakeLunIndex'},
              fakes.FakeAuthPassFailResponse(),
              fakes.FakeGetBasicInfoResponseTs_4_3_0()],
              ['self.driver.api_executor.get_snapshot_info',
              {'snapshot_name': 'fakeSnapshoName',
               'lun_index': 'fakeLunIndex'},
              fakes.FakeResultNegativeResponse(),
              fakes.FakeGetBasicInfoResponseTs_4_3_0()])
    def test_get_snapshot_info_ts_with_fail_response(
            self, api, dict_parm,
            fake_fail_response, fake_basic_info):
        """Test get snapshot info api with fail response."""
        mock_http_connection = six.moves.http_client.HTTPConnection
        mock_http_connection.return_value.getresponse.side_effect = [
            fakes.FakeLoginResponse(),
            fake_basic_info,
            fakes.FakeLoginResponse(),
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response,
            fake_fail_response]

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.mock_object(time, 'sleep')
        self.assertRaises(
            exception.ShareBackendException,
            eval(api),
            **dict_parm)
