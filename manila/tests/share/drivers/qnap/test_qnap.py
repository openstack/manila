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


try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

import ddt
import mock
from oslo_config import cfg
import six
import time

from eventlet import greenthread
from manila import exception
from manila.share.drivers.qnap import api
from manila.share.drivers.qnap import qnap
from manila.share import share_types
from manila import test
from manila.tests import fake_share
from manila.tests.share.drivers.qnap import fakes


CONF = cfg.CONF


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
class QnapShareDriverLoginTestCase(QnapShareDriverBaseTestCase):
    """Tests do_setup api."""

    def setUp(self):
        """Setup the Qnap Share Driver login TestCase."""
        super(QnapShareDriverLoginTestCase, self).setUp()
        self.mock_object(six.moves.http_client, 'HTTPConnection')
        self.mock_object(six.moves.http_client, 'HTTPSConnection')

    @ddt.unpack
    @ddt.data({'mng_url': 'http://1.2.3.4:8080', 'port': '8080', 'ssl': False},
              {'mng_url': 'https://1.2.3.4:443', 'port': '443', 'ssl': True})
    def test_do_setup_positive(self, mng_url, port, ssl):
        """Test do_setup with http://1.2.3.4:8080."""
        fake_login_response = fakes.FakeLoginResponse()
        fake_get_basic_info_response_es = (
            fakes.FakeGetBasicInfoResponseEs_1_1_3())
        if ssl:
            mock_connection = six.moves.http_client.HTTPSConnection
        else:
            mock_connection = six.moves.http_client.HTTPConnection
        mock_connection.return_value.getresponse.side_effect = [
            fake_login_response,
            fake_get_basic_info_response_es,
            fake_login_response]

        self._do_setup(mng_url, '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')

        self.assertEqual(
            mng_url,
            self.driver.configuration.qnap_management_url)
        self.assertEqual(
            '1.2.3.4', self.driver.configuration.qnap_share_ip)
        self.assertEqual(
            'admin', self.driver.configuration.qnap_nas_login)
        self.assertEqual(
            'qnapadmin', self.driver.configuration.qnap_nas_password)
        self.assertEqual(
            'Storage Pool 1', self.driver.configuration.qnap_poolname)
        self.assertEqual('fakeSid', self.driver.api_executor.sid)
        self.assertEqual('admin', self.driver.api_executor.username)
        self.assertEqual('qnapadmin', self.driver.api_executor.password)
        self.assertEqual('1.2.3.4', self.driver.api_executor.ip)
        self.assertEqual(port, self.driver.api_executor.port)
        self.assertEqual(ssl, self.driver.api_executor.ssl)

    @ddt.data(fakes.FakeGetBasicInfoResponseTs_4_3_0(),
              fakes.FakeGetBasicInfoResponseTesTs_4_3_0(),
              fakes.FakeGetBasicInfoResponseTesEs_1_1_3())
    def test_do_setup_positive_with_diff_nas(self, fake_basic_info):
        """Test do_setup with different NAS model."""
        fake_login_response = fakes.FakeLoginResponse()
        mock_connection = six.moves.http_client.HTTPSConnection
        mock_connection.return_value.getresponse.side_effect = [
            fake_login_response,
            fake_basic_info,
            fake_login_response]

        self._do_setup('https://1.2.3.4:443', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')

        self.assertEqual('fakeSid', self.driver.api_executor.sid)
        self.assertEqual('admin', self.driver.api_executor.username)
        self.assertEqual('qnapadmin', self.driver.api_executor.password)
        self.assertEqual('1.2.3.4', self.driver.api_executor.ip)
        self.assertEqual('443', self.driver.api_executor.port)
        self.assertTrue(self.driver.api_executor.ssl)

    @ddt.data({
        'fake_basic_info': fakes.FakeGetBasicInfoResponseTs_4_3_0(),
        'expect_result': api.QnapAPIExecutorTS
    }, {
        'fake_basic_info': fakes.FakeGetBasicInfoResponseTesTs_4_3_0(),
        'expect_result': api.QnapAPIExecutorTS
    }, {
        'fake_basic_info': fakes.FakeGetBasicInfoResponseTesEs_1_1_3(),
        'expect_result': api.QnapAPIExecutor
    }, {
        'fake_basic_info': fakes.FakeGetBasicInfoResponseEs_1_1_3(),
        'expect_result': api.QnapAPIExecutor
    })
    @ddt.unpack
    def test_create_api_executor(self, fake_basic_info, expect_result):
        """Test do_setup with different NAS model."""
        fake_login_response = fakes.FakeLoginResponse()
        mock_connection = six.moves.http_client.HTTPSConnection
        mock_connection.return_value.getresponse.side_effect = [
            fake_login_response,
            fake_basic_info,
            fake_login_response]
        self._do_setup('https://1.2.3.4:443', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1')
        self.assertIsInstance(self.driver.api_executor, expect_result)

    @ddt.data({
        'fake_basic_info': fakes.FakeGetBasicInfoResponseTs_4_0_0(),
        'expect_result': exception.ShareBackendException
    }, {
        'fake_basic_info': fakes.FakeGetBasicInfoResponseTesTs_4_0_0(),
        'expect_result': exception.ShareBackendException
    }, {
        'fake_basic_info': fakes.FakeGetBasicInfoResponseTesEs_1_1_1(),
        'expect_result': exception.ShareBackendException
    }, {
        'fake_basic_info': fakes.FakeGetBasicInfoResponseEs_1_1_1(),
        'expect_result': exception.ShareBackendException
    })
    @ddt.unpack
    def test_create_api_executor_negative(self,
                                          fake_basic_info, expect_result):
        """Test do_setup with different NAS model."""
        fake_login_response = fakes.FakeLoginResponse()
        mock_connection = six.moves.http_client.HTTPSConnection
        mock_connection.return_value.getresponse.side_effect = [
            fake_login_response,
            fake_basic_info,
            fake_login_response]
        self.assertRaises(
            exception.ShareBackendException,
            self._do_setup,
            'https://1.2.3.4:443',
            '1.2.3.4',
            'admin',
            'qnapadmin',
            'Storage Pool 1')

    def test_do_setup_with_exception(self):
        """Test do_setup with exception."""
        fake_login_response = fakes.FakeLoginResponse()
        fake_get_basic_info_response_error = (
            fakes.FakeGetBasicInfoResponseError())
        mock_connection = six.moves.http_client.HTTPSConnection
        mock_connection.return_value.getresponse.side_effect = [
            fake_login_response,
            fake_get_basic_info_response_error,
            fake_login_response]

        self.driver = qnap.QnapShareDriver(
            configuration=create_configuration(
                'https://1.2.3.4:443', '1.2.3.4', 'admin',
                'qnapadmin', 'Pool1'))
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.do_setup,
            context='context')

    def test_check_for_setup_error(self):
        """Test do_setup with exception."""
        self.driver = qnap.QnapShareDriver(
            configuration=create_configuration(
                'https://1.2.3.4:443', '1.2.3.4', 'admin',
                'qnapadmin', 'Pool1'))
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.check_for_setup_error)


@ddt.ddt
class QnapShareDriverTestCase(QnapShareDriverBaseTestCase):
    """Tests share driver functions."""

    def setUp(self):
        """Setup the Qnap Driver Base TestCase."""
        super(QnapShareDriverTestCase, self).setUp()
        self.mock_object(qnap.QnapShareDriver, '_create_api_executor')
        self.share = fake_share.fake_share(
            share_proto='NFS',
            id='shareId',
            display_name='fakeDisplayName',
            export_locations=[{'path': '1.2.3.4:/share/fakeShareName'}],
            host='QnapShareDriver',
            size=10)

    def get_share_info_return_value(self):
        """Return the share info form get_share_info method."""
        root = ET.fromstring(fakes.FAKE_RES_DETAIL_DATA_SHARE_INFO)

        share_list = root.find('Volume_Info')
        share_info_tree = share_list.findall('row')
        for share in share_info_tree:
            return share

    def get_snapshot_info_return_value(self):
        """Return the snapshot info form get_snapshot_info method."""
        root = ET.fromstring(fakes.FAKE_RES_DETAIL_DATA_SNAPSHOT)

        snapshot_list = root.find('SnapshotList')
        snapshot_info_tree = snapshot_list.findall('row')
        for snapshot in snapshot_info_tree:
            return snapshot

    def get_specific_volinfo_return_value(self):
        """Return the volume info form get_specific_volinfo method."""
        root = ET.fromstring(fakes.FAKE_RES_DETAIL_DATA_VOLUME_INFO)

        volume_list = root.find('Volume_Info')
        volume_info_tree = volume_list.findall('row')
        for volume in volume_info_tree:
            return volume

    def get_specific_poolinfo_return_value(self):
        """Get specific pool info."""
        root = ET.fromstring(fakes.FAKE_RES_DETAIL_DATA_SPECIFIC_POOL_INFO)

        pool_list = root.find('Pool_Index')
        pool_info_tree = pool_list.findall('row')
        for pool in pool_info_tree:
            return pool

    def get_host_list_return_value(self):
        """Get host list."""
        root = ET.fromstring(fakes.FAKE_RES_DETAIL_DATA_GET_HOST_LIST)

        hosts = []
        host_list = root.find('host_list')
        host_tree = host_list.findall('host')
        for host in host_tree:
            hosts.append(host)

        return hosts

    @ddt.data({
        'fake_extra_spec': {},
        'expect_extra_spec': {
            'qnap_thin_provision': True,
            'qnap_compression': True,
            'qnap_deduplication': False,
            'qnap_ssd_cache': False
        }
    }, {
        'fake_extra_spec': {
            'thin_provisioning': u'true',
            'compression': u'true',
            'qnap_ssd_cache': u'true'
        },
        'expect_extra_spec': {
            'qnap_thin_provision': True,
            'qnap_compression': True,
            'qnap_deduplication': False,
            'qnap_ssd_cache': True
        }
    }, {
        'fake_extra_spec': {
            'thin_provisioning': u'<is> False',
            'compression': u'<is> True',
            'qnap_ssd_cache': u'<is> True'
        },
        'expect_extra_spec': {
            'qnap_thin_provision': False,
            'qnap_compression': True,
            'qnap_deduplication': False,
            'qnap_ssd_cache': True
        }
    }, {
        'fake_extra_spec': {
            'thin_provisioning': u'true',
            'dedupe': u'<is> True',
            'qnap_ssd_cache': u'False'
        },
        'expect_extra_spec': {
            'qnap_thin_provision': True,
            'qnap_compression': True,
            'qnap_deduplication': True,
            'qnap_ssd_cache': False
        }
    }, {
        'fake_extra_spec': {
            'thin_provisioning': u'<is> False',
            'compression': u'false',
            'dedupe': u'<is> False',
            'qnap_ssd_cache': u'<is> False'
        },
        'expect_extra_spec': {
            'qnap_thin_provision': False,
            'qnap_compression': False,
            'qnap_deduplication': False,
            'qnap_ssd_cache': False
        }
    })
    @ddt.unpack
    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    @mock.patch.object(qnap.QnapShareDriver, '_gen_random_name')
    def test_create_share_positive(
            self,
            mock_gen_random_name,
            mock_get_location_path,
            fake_extra_spec, expect_extra_spec):
        """Test create share."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.side_effect = [
            None, self.get_share_info_return_value()]
        mock_gen_random_name.return_value = 'fakeShareName'
        mock_api_executor.return_value.create_share.return_value = (
            'fakeCreateShareId')
        mock_get_location_path.return_value = None
        mock_private_storage = mock.Mock()
        self.mock_object(greenthread, 'sleep')
        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value=fake_extra_spec))
        self.driver.create_share('context', self.share)

        mock_api_return = mock_api_executor.return_value
        expected_call_list = [
            mock.call('Storage Pool 1', vol_label='fakeShareName'),
            mock.call('Storage Pool 1', vol_label='fakeShareName')]
        self.assertEqual(
            expected_call_list,
            mock_api_return.get_share_info.call_args_list)
        mock_api_executor.return_value.create_share.assert_called_once_with(
            self.share,
            self.driver.configuration.qnap_poolname,
            'fakeShareName',
            'NFS',
            **expect_extra_spec)
        mock_get_location_path.assert_called_once_with(
            'fakeShareName', 'NFS', '1.2.3.4', 'fakeNo')

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    @mock.patch.object(qnap.QnapShareDriver, '_gen_random_name')
    def test_create_share_negative_share_exist(
            self,
            mock_gen_random_name,
            mock_get_location_path):
        """Test create share."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_gen_random_name.return_value = 'fakeShareName'
        mock_get_location_path.return_value = None
        mock_private_storage = mock.Mock()
        self.mock_object(time, 'sleep')
        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={}))

        self.assertRaises(
            exception.ShareBackendException,
            self.driver.create_share,
            context='context',
            share=self.share)

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    @mock.patch.object(qnap.QnapShareDriver, '_gen_random_name')
    def test_create_share_negative_create_fail(
            self,
            mock_gen_random_name,
            mock_get_location_path):
        """Test create share."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = None
        mock_gen_random_name.return_value = 'fakeShareName'
        mock_get_location_path.return_value = None
        mock_private_storage = mock.Mock()
        self.mock_object(time, 'sleep')
        self.mock_object(greenthread, 'sleep')
        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={}))

        self.assertRaises(
            exception.ShareBackendException,
            self.driver.create_share,
            context='context',
            share=self.share)

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    @mock.patch.object(qnap.QnapShareDriver, '_gen_random_name')
    def test_create_share_negative_configutarion(
            self,
            mock_gen_random_name,
            mock_get_location_path):
        """Test create share."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.side_effect = [
            None, self.get_share_info_return_value()]
        mock_gen_random_name.return_value = 'fakeShareName'
        mock_get_location_path.return_value = None
        mock_private_storage = mock.Mock()

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={
                                   'dedupe': 'true',
                                   'thin_provisioning': 'false'}))

        self.assertRaises(
            exception.InvalidExtraSpec,
            self.driver.create_share,
            context='context',
            share=self.share)

    def test_delete_share_positive(self):
        """Test delete share with fake_share."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_api_executor.return_value.delete_share.return_value = (
            'fakeCreateShareId')
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolNo'

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.delete_share('context', self.share, share_server=None)

        mock_api_executor.return_value.get_share_info.assert_called_once_with(
            'Storage Pool 1', vol_no='fakeVolNo')
        mock_api_executor.return_value.delete_share.assert_called_once_with(
            'fakeNo')

    def test_delete_share_no_volid(self):
        """Test delete share with fake_share and no volID."""
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.delete_share('context', self.share, share_server=None)

        mock_private_storage.get.assert_called_once_with(
            'shareId', 'volID')

    def test_delete_share_no_delete_share(self):
        """Test delete share with fake_share."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = None
        mock_api_executor.return_value.delete_share.return_value = (
            'fakeCreateShareId')
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolNo'

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.delete_share('context', self.share, share_server=None)

        mock_api_executor.return_value.get_share_info.assert_called_once_with(
            'Storage Pool 1', vol_no='fakeVolNo')

    def test_extend_share(self):
        """Test extend share with fake_share."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_api_executor.return_value.edit_share.return_value = None
        mock_private_storage = mock.Mock()
        mock_private_storage.get.side_effect = [
            'fakeVolName',
            'True',
            'True',
            'False',
            'False']

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.extend_share(self.share, 100, share_server=None)

        expect_share_dict = {
            'sharename': 'fakeVolName',
            'old_sharename': 'fakeVolName',
            'new_size': 100,
            'thin_provision': True,
            'compression': True,
            'deduplication': False,
            'ssd_cache': False,
            'share_proto': 'NFS'
        }
        mock_api_executor.return_value.edit_share.assert_called_once_with(
            expect_share_dict)

    def test_extend_share_without_share_name(self):
        """Test extend share without share name."""
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.ShareResourceNotFound,
            self.driver.extend_share,
            share=self.share,
            new_size=100,
            share_server=None)

    @mock.patch.object(qnap.QnapShareDriver, '_gen_random_name')
    def test_create_snapshot(
            self,
            mock_gen_random_name):
        """Test create snapshot with fake_snapshot."""
        fake_snapshot = fakes.SnapshotClass(
            10, 'fakeShareName@fakeSnapshotName')

        mock_gen_random_name.return_value = 'fakeSnapshotName'
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_snapshot_info.side_effect = [
            None, self.get_snapshot_info_return_value()]
        mock_api_executor.return_value.create_snapshot_api.return_value = (
            'fakeCreateShareId')
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolId'

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.create_snapshot(
            'context', fake_snapshot, share_server=None)

        mock_api_return = mock_api_executor.return_value
        expected_call_list = [
            mock.call(volID='fakeVolId', snapshot_name='fakeSnapshotName'),
            mock.call(volID='fakeVolId', snapshot_name='fakeSnapshotName')]
        self.assertEqual(
            expected_call_list,
            mock_api_return.get_snapshot_info.call_args_list)

        mock_api_return.create_snapshot_api.assert_called_once_with(
            'fakeVolId', 'fakeSnapshotName')

    def test_create_snapshot_without_volid(self):
        """Test create snapshot with fake_snapshot."""
        fake_snapshot = fakes.SnapshotClass(10, None)

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.ShareResourceNotFound,
            self.driver.create_snapshot,
            context='context',
            snapshot=fake_snapshot,
            share_server=None)

    def test_delete_snapshot(self):
        """Test delete snapshot with fakeSnapshot."""
        fake_snapshot = fakes.SnapshotClass(
            10, 'fakeShareName@fakeSnapshotName')

        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.delete_snapshot_api.return_value = (
            'fakeCreateShareId')
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeSnapshotId'

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.delete_snapshot(
            'context', fake_snapshot, share_server=None)

        mock_api_return = mock_api_executor.return_value
        mock_api_return.delete_snapshot_api.assert_called_once_with(
            'fakeShareName@fakeSnapshotName')

    def test_delete_snapshot_without_snapshot_id(self):
        """Test delete snapshot with fakeSnapshot and no snapshot id."""
        fake_snapshot = fakes.SnapshotClass(10, None)

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.delete_snapshot(
            'context', fake_snapshot, share_server=None)

        mock_private_storage.get.assert_called_once_with(
            'fakeSnapshotId', 'snapshot_id')

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    @mock.patch('manila.share.API')
    @mock.patch.object(qnap.QnapShareDriver, '_gen_random_name')
    def test_create_share_from_snapshot(
            self,
            mock_gen_random_name,
            mock_share_api,
            mock_get_location_path):
        """Test create share from snapshot."""
        fake_snapshot = fakes.SnapshotClass(
            10, 'fakeShareName@fakeSnapshotName')

        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_gen_random_name.return_value = 'fakeShareName'
        mock_api_executor.return_value.get_share_info.side_effect = [
            None, self.get_share_info_return_value()]
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeSnapshotId'
        mock_share_api.return_value.get.return_value = {'size': 10}

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.create_share_from_snapshot(
            'context', self.share, fake_snapshot, share_server=None)

        mock_gen_random_name.assert_called_once_with(
            'share')
        mock_api_return = mock_api_executor.return_value
        expected_call_list = [
            mock.call('Storage Pool 1', vol_label='fakeShareName'),
            mock.call('Storage Pool 1', vol_label='fakeShareName')]
        self.assertEqual(
            expected_call_list,
            mock_api_return.get_share_info.call_args_list)
        mock_api_return.clone_snapshot.assert_called_once_with(
            'fakeShareName@fakeSnapshotName', 'fakeShareName')

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    @mock.patch('manila.share.API')
    @mock.patch.object(qnap.QnapShareDriver, '_gen_random_name')
    def test_create_share_from_snapshot_diff_size(
            self,
            mock_gen_random_name,
            mock_share_api,
            mock_get_location_path):
        """Test create share from snapshot."""
        fake_snapshot = fakes.SnapshotClass(
            10, 'fakeShareName@fakeSnapshotName')

        mock_gen_random_name.return_value = 'fakeShareName'
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.side_effect = [
            None, self.get_share_info_return_value()]
        mock_private_storage = mock.Mock()
        mock_private_storage.get.side_effect = [
            'True',
            'True',
            'False',
            'False',
            'fakeVolName']
        mock_share_api.return_value.get.return_value = {'size': 5}
        mock_api_executor.return_value.edit_share.return_value = (
            None)

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.create_share_from_snapshot(
            'context', self.share, fake_snapshot, share_server=None)

        mock_gen_random_name.assert_called_once_with(
            'share')
        mock_api_return = mock_api_executor.return_value
        expected_call_list = [
            mock.call('Storage Pool 1', vol_label='fakeShareName'),
            mock.call('Storage Pool 1', vol_label='fakeShareName')]
        self.assertEqual(
            expected_call_list,
            mock_api_return.get_share_info.call_args_list)
        mock_api_return.clone_snapshot.assert_called_once_with(
            'fakeShareName@fakeSnapshotName', 'fakeShareName')
        expect_share_dict = {
            'sharename': 'fakeShareName',
            'old_sharename': 'fakeShareName',
            'new_size': 10,
            'thin_provision': True,
            'compression': True,
            'deduplication': False,
            'ssd_cache': False,
            'share_proto': 'NFS'
        }
        mock_api_return.edit_share.assert_called_once_with(
            expect_share_dict)

    def test_create_share_from_snapshot_without_snapshot_id(self):
        """Test create share from snapshot."""
        fake_snapshot = fakes.SnapshotClass(10, None)

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.SnapshotResourceNotFound,
            self.driver.create_share_from_snapshot,
            context='context',
            share=self.share,
            snapshot=fake_snapshot,
            share_server=None)

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    @mock.patch('manila.share.API')
    @mock.patch.object(qnap.QnapShareDriver, '_gen_random_name')
    def test_create_share_from_snapshot_negative_name_exist(
            self,
            mock_gen_random_name,
            mock_share_api,
            mock_get_location_path):
        """Test create share from snapshot."""
        fake_snapshot = fakes.SnapshotClass(
            10, 'fakeShareName@fakeSnapshotName')

        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_gen_random_name.return_value = 'fakeShareName'
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeSnapshotId'
        mock_share_api.return_value.get.return_value = {'size': 10}
        self.mock_object(time, 'sleep')
        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.create_share_from_snapshot,
            context='context',
            share=self.share,
            snapshot=fake_snapshot,
            share_server=None)

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    @mock.patch('manila.share.API')
    @mock.patch.object(qnap.QnapShareDriver, '_gen_random_name')
    def test_create_share_from_snapshot_negative_clone_fail(
            self,
            mock_gen_random_name,
            mock_share_api,
            mock_get_location_path):
        """Test create share from snapshot."""
        fake_snapshot = fakes.SnapshotClass(
            10, 'fakeShareName@fakeSnapshotName')

        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_gen_random_name.return_value = 'fakeShareName'
        mock_api_executor.return_value.get_share_info.return_value = None
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeSnapshotId'
        mock_share_api.return_value.get.return_value = {'size': 10}
        self.mock_object(time, 'sleep')
        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.create_share_from_snapshot,
            context='context',
            share=self.share,
            snapshot=fake_snapshot,
            share_server=None)

    @mock.patch.object(qnap.QnapShareDriver, '_get_timestamp_from_vol_name')
    @mock.patch.object(qnap.QnapShareDriver, '_allow_access')
    @ddt.data('fakeHostName', 'fakeHostNameNotMatch')
    def test_update_access_allow_access(
            self, fakeHostName, mock_allow_access,
            mock_get_timestamp_from_vol_name):
        """Test update access with allow access rules."""
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolName'
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_host_list.return_value = (
            self.get_host_list_return_value())
        mock_api_executor.return_value.set_nfs_access.return_value = None
        mock_api_executor.return_value.delete_host.return_value = None
        mock_allow_access.return_value = None
        mock_get_timestamp_from_vol_name.return_value = fakeHostName

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.update_access(
            'context', self.share, 'access_rules',
            None, None, share_server=None)

        mock_api_executor.return_value.set_nfs_access.assert_called_once_with(
            'fakeVolName', 2, 'all')

    @mock.patch.object(qnap.QnapShareDriver, '_allow_access')
    @mock.patch.object(qnap.QnapShareDriver, '_deny_access')
    def test_update_access_deny_and_allow_access(
            self,
            mock_deny_access,
            mock_allow_access):
        """Test update access with deny and allow access rules."""
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolName'
        mock_deny_access.return_value = None
        mock_allow_access.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        delete_rules = []
        delete_rules.append('access1')
        add_rules = []
        add_rules.append('access1')
        self.driver.update_access(
            'context', self.share, None,
            add_rules, delete_rules, share_server=None)

        mock_deny_access.assert_called_once_with(
            'context', self.share, 'access1', None)
        mock_allow_access.assert_called_once_with(
            'context', self.share, 'access1', None)

    def test_update_access_without_volname(self):
        """Test update access without volName."""
        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.ShareResourceNotFound,
            self.driver.update_access,
            context='context',
            share=self.share,
            access_rules='access_rules',
            add_rules=None,
            delete_rules=None,
            share_server=None)

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    def test_manage_existing_nfs(
            self,
            mock_get_location_path):
        """Test manage existing."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_private_storage = mock.Mock()
        mock_private_storage.update.return_value = None
        mock_private_storage.get.side_effect = [
            'fakeVolId',
            'fakeVolName']
        mock_api_executor.return_value.get_specific_volinfo.return_value = (
            self.get_specific_volinfo_return_value())
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_get_location_path.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={}))
        self.driver.manage_existing(self.share, 'driver_options')

        mock_api_return = mock_api_executor.return_value
        mock_api_return.get_share_info.assert_called_once_with(
            'Storage Pool 1', vol_label='fakeShareName')
        mock_api_return.get_specific_volinfo.assert_called_once_with(
            'fakeNo')
        mock_get_location_path.assert_called_once_with(
            'fakeShareName', 'NFS', '1.2.3.4', 'fakeNo')

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    def test_manage_existing_nfs_negative_configutarion(
            self,
            mock_get_location_path):
        """Test manage existing."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_private_storage = mock.Mock()
        mock_private_storage.update.return_value = None
        mock_private_storage.get.side_effect = [
            'fakeVolId',
            'fakeVolName']
        mock_api_executor.return_value.get_specific_volinfo.return_value = (
            self.get_specific_volinfo_return_value())
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_get_location_path.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.mock_object(share_types, 'get_extra_specs_from_share',
                         mock.Mock(return_value={
                                   'dedupe': 'true',
                                   'thin_provisioning': 'false'}))

        self.assertRaises(
            exception.InvalidExtraSpec,
            self.driver.manage_existing,
            share=self.share,
            driver_options='driver_options')

    def test_manage_invalid_protocol(self):
        """Test manage existing."""
        share = fake_share.fake_share(
            share_proto='fakeProtocol',
            id='fakeId',
            display_name='fakeDisplayName',
            export_locations=[{'path': ''}],
            host='QnapShareDriver',
            size=10)

        mock_private_storage = mock.Mock()

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.InvalidInput,
            self.driver.manage_existing,
            share=share,
            driver_options='driver_options')

    def test_manage_existing_nfs_without_export_locations(self):
        share = fake_share.fake_share(
            share_proto='NFS',
            id='fakeId',
            display_name='fakeDisplayName',
            export_locations=[{'path': ''}],
            host='QnapShareDriver',
            size=10)

        mock_private_storage = mock.Mock()

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.manage_existing,
            share=share,
            driver_options='driver_options')

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    def test_manage_existing_nfs_ip_not_equel_share_ip(
            self,
            mock_get_location_path):
        """Test manage existing with nfs ip not equel to share ip."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_private_storage = mock.Mock()
        mock_private_storage.update.return_value = None
        mock_private_storage.get.side_effect = [
            'fakeVolId',
            'fakeVolName']
        mock_api_executor.return_value.get_specific_volinfo.return_value = (
            self.get_specific_volinfo_return_value())
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_get_location_path.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.1.1.1', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.ShareBackendException,
            self.driver.manage_existing,
            share=self.share,
            driver_options='driver_options')

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    def test_manage_existing_nfs_without_existing_share(
            self,
            mock_get_location_path):
        """Test manage existing nfs without existing share."""
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_private_storage = mock.Mock()
        mock_private_storage.update.return_value = None
        mock_private_storage.get.side_effect = [
            'fakeVolId',
            'fakeVolName']
        mock_api_executor.return_value.get_specific_volinfo.return_value = (
            self.get_specific_volinfo_return_value())
        mock_api_executor.return_value.get_share_info.return_value = (
            None)
        mock_get_location_path.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.ManageInvalidShare,
            self.driver.manage_existing,
            share=self.share,
            driver_options='driver_options')

    def test_unmanage(self):
        """Test unmanage."""
        mock_private_storage = mock.Mock()
        mock_private_storage.delete.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.unmanage(self.share)

        mock_private_storage.delete.assert_called_once_with(
            'shareId')

    @mock.patch.object(qnap.QnapShareDriver, '_get_location_path')
    def test_manage_existing_snapshot(
            self,
            mock_get_location_path):
        """Test manage existing snapshot snapshot."""
        fake_snapshot = fakes.SnapshotClass(
            10, 'fakeShareName@fakeSnapshotName')

        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_private_storage = mock.Mock()
        mock_private_storage.update.return_value = None
        mock_private_storage.get.side_effect = [
            'fakeVolId', 'fakeVolName']

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.manage_existing_snapshot(fake_snapshot, 'driver_options')

        mock_api_return = mock_api_executor.return_value
        mock_api_return.get_share_info.assert_called_once_with(
            'Storage Pool 1', vol_no='fakeVolId')
        fake_metadata = {
            'snapshot_id': 'fakeShareName@fakeSnapshotName'}
        mock_private_storage.update.assert_called_once_with(
            'fakeSnapshotId', fake_metadata)

    def test_unmanage_snapshot(self):
        """Test unmanage snapshot."""
        fake_snapshot = fakes.SnapshotClass(
            10, 'fakeShareName@fakeSnapshotName')

        mock_private_storage = mock.Mock()
        mock_private_storage.delete.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver.unmanage_snapshot(fake_snapshot)

        mock_private_storage.delete.assert_called_once_with(
            'fakeSnapshotId')

    @ddt.data(
        {'expect_result': 'manila-shr-fake_time', 'test_string': 'share'},
        {'expect_result': 'manila-snp-fake_time', 'test_string': 'snapshot'},
        {'expect_result': 'manila-hst-fake_time', 'test_string': 'host'},
        {'expect_result': 'manila-fake_time', 'test_string': ''})
    @ddt.unpack
    @mock.patch('oslo_utils.timeutils.utcnow')
    def test_gen_random_name(
            self, mock_utcnow, expect_result, test_string):
        """Test gen random name."""
        mock_private_storage = mock.Mock()
        mock_utcnow.return_value.strftime.return_value = 'fake_time'

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)

        self.assertEqual(
            expect_result, self.driver._gen_random_name(test_string))

    def test_get_location_path(self):
        """Test get location path name."""
        mock_private_storage = mock.Mock()
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_api_executor.return_value.get_specific_volinfo.return_value = (
            self.get_specific_volinfo_return_value())

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)

        location = 'fakeIp:fakeMountPath'
        expect_result = {
            'path': location,
            'is_admin_only': False,
        }
        self.assertEqual(
            expect_result, self.driver._get_location_path(
                'fakeShareName', 'NFS', 'fakeIp', 'fakeVolId'))

        self.assertRaises(
            exception.InvalidInput,
            self.driver._get_location_path,
            share_name='fakeShareName',
            share_proto='fakeProto',
            ip='fakeIp',
            vol_id='fakeVolId')

    def test_update_share_stats(self):
        """Test update share stats."""
        mock_private_storage = mock.Mock()
        mock_api_return = (
            qnap.QnapShareDriver._create_api_executor.return_value)
        mock_api_return.get_specific_poolinfo.return_value = (
            self.get_specific_poolinfo_return_value())
        mock_api_return.get_share_info.return_value = (
            self.get_share_info_return_value())
        mock_api_return.get_specific_volinfo.return_value = (
            self.get_specific_volinfo_return_value())

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver._update_share_stats()

        mock_api_return.get_specific_poolinfo.assert_called_once_with(
            self.driver.configuration.qnap_poolname)

    def test_get_vol_host(self):
        """Test get manila host IPV4s."""
        mock_private_storage = mock.Mock()

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)

        expect_host_dict_ips = []
        host_list = self.get_host_list_return_value()
        for host in host_list:
            host_dict = {
                'index': host.find('index').text,
                'hostid': host.find('hostid').text,
                'name': host.find('name').text,
                'ipv4': [host.find('netaddrs').find('ipv4').text]
            }
            expect_host_dict_ips.append(host_dict)

        self.assertEqual(
            expect_host_dict_ips, self.driver._get_vol_host(
                host_list, 'fakeHostName'))

    @mock.patch.object(qnap.QnapShareDriver, '_gen_host_name')
    @mock.patch.object(qnap.QnapShareDriver, '_get_timestamp_from_vol_name')
    @mock.patch.object(qnap.QnapShareDriver, '_check_share_access')
    def test_allow_access_ro(
            self,
            mock_check_share_access,
            mock_get_timestamp_from_vol_name,
            mock_gen_host_name):
        """Test allow_access with access type ro."""
        fake_access = fakes.AccessClass('fakeAccessType', 'ro', 'fakeIp')

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolName'
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_host_list.return_value = []
        mock_get_timestamp_from_vol_name.return_value = 'fakeHostName'
        mock_gen_host_name.return_value = 'manila-fakeHostName-ro'
        mock_api_executor.return_value.add_host.return_value = None
        mock_api_executor.return_value.set_nfs_access.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver._allow_access(
            'context', self.share, fake_access, share_server=None)

        mock_check_share_access.assert_called_once_with(
            'NFS', 'fakeAccessType')
        mock_api_executor.return_value.add_host.assert_called_once_with(
            'manila-fakeHostName-ro', 'fakeIp')

    @mock.patch.object(qnap.QnapShareDriver, '_gen_host_name')
    @mock.patch.object(qnap.QnapShareDriver, '_get_timestamp_from_vol_name')
    @mock.patch.object(qnap.QnapShareDriver, '_check_share_access')
    def test_allow_access_ro_with_hostlist(
            self,
            mock_check_share_access,
            mock_get_timestamp_from_vol_name,
            mock_gen_host_name):
        """Test allow_access_ro_with_hostlist."""
        host_dict_ips = []
        for host in self.get_host_list_return_value():
            if host.find('netaddrs/ipv4').text is not None:
                host_dict = {
                    'index': host.find('index').text,
                    'hostid': host.find('hostid').text,
                    'name': host.find('name').text,
                    'ipv4': [host.find('netaddrs').find('ipv4').text]}
                host_dict_ips.append(host_dict)

        for host in host_dict_ips:
            fake_access_to = host['ipv4']
        fake_access = fakes.AccessClass(
            'fakeAccessType', 'ro', fake_access_to)

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolName'
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_host_list.return_value = (
            self.get_host_list_return_value())
        mock_get_timestamp_from_vol_name.return_value = 'fakeHostName'
        mock_gen_host_name.return_value = 'manila-fakeHostName'
        mock_api_executor.return_value.set_nfs_access.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver._allow_access(
            'context', self.share, fake_access, share_server=None)

        mock_check_share_access.assert_called_once_with(
            'NFS', 'fakeAccessType')

    @mock.patch.object(qnap.QnapShareDriver, '_gen_host_name')
    @mock.patch.object(qnap.QnapShareDriver, '_get_timestamp_from_vol_name')
    @mock.patch.object(qnap.QnapShareDriver, '_check_share_access')
    def test_allow_access_rw_with_hostlist_invalid_access(
            self,
            mock_check_share_access,
            mock_get_timestamp_from_vol_name,
            mock_gen_host_name):
        """Test allow_access_rw_invalid_access."""
        host_dict_ips = []
        for host in self.get_host_list_return_value():
            if host.find('netaddrs/ipv4').text is not None:
                host_dict = {
                    'index': host.find('index').text,
                    'hostid': host.find('hostid').text,
                    'name': host.find('name').text,
                    'ipv4': [host.find('netaddrs').find('ipv4').text]}
                host_dict_ips.append(host_dict)

        for host in host_dict_ips:
            fake_access_to = host['ipv4']
        fake_access = fakes.AccessClass(
            'fakeAccessType', 'rw', fake_access_to)

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolName'
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_host_list.return_value = (
            self.get_host_list_return_value())
        mock_get_timestamp_from_vol_name.return_value = 'fakeHostName'
        mock_gen_host_name.return_value = 'manila-fakeHostName-rw'

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)

        self.assertRaises(
            exception.InvalidShareAccess,
            self.driver._allow_access,
            context='context',
            share=self.share,
            access=fake_access,
            share_server=None)

    @mock.patch.object(qnap.QnapShareDriver, '_get_timestamp_from_vol_name')
    @mock.patch.object(qnap.QnapShareDriver, '_check_share_access')
    def test_allow_access_rw(
            self,
            mock_check_share_access,
            mock_get_timestamp_from_vol_name):
        """Test allow_access with access type rw."""
        fake_access = fakes.AccessClass('fakeAccessType', 'rw', 'fakeIp')

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolName'
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_host_list.return_value = []
        mock_get_timestamp_from_vol_name.return_value = 'fakeHostName'
        mock_api_executor.return_value.add_host.return_value = None
        mock_api_executor.return_value.set_nfs_access.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver._allow_access(
            'context', self.share, fake_access, share_server=None)

        mock_check_share_access.assert_called_once_with(
            'NFS', 'fakeAccessType')
        mock_api_executor.return_value.add_host.assert_called_once_with(
            'manila-fakeHostName-rw', 'fakeIp')

    @mock.patch.object(qnap.QnapShareDriver, '_gen_host_name')
    @mock.patch.object(qnap.QnapShareDriver, '_check_share_access')
    def test_allow_access_ro_without_hostlist(
            self,
            mock_check_share_access,
            mock_gen_host_name):
        """Test allow access without host list."""
        fake_access = fakes.AccessClass('fakeAccessType', 'ro', 'fakeIp')

        mock_private_storage = mock.Mock()

        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_host_list.return_value = None
        mock_gen_host_name.return_value = 'fakeHostName'
        mock_api_executor.return_value.add_host.return_value = None
        mock_api_executor.return_value.set_nfs_access.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        share_name = self.driver._gen_random_name('share')
        mock_private_storage.get.return_value = share_name
        self.driver._allow_access(
            'context', self.share, fake_access, share_server=None)

        mock_check_share_access.assert_called_once_with(
            'NFS', 'fakeAccessType')
        mock_api_executor.return_value.add_host.assert_called_once_with(
            'fakeHostName', 'fakeIp')

    @mock.patch.object(qnap.QnapShareDriver, '_get_vol_host')
    @mock.patch.object(qnap.QnapShareDriver, '_gen_host_name')
    @mock.patch.object(qnap.QnapShareDriver, '_get_timestamp_from_vol_name')
    @mock.patch.object(qnap.QnapShareDriver, '_check_share_access')
    def test_deny_access_with_hostlist(
            self,
            mock_check_share_access,
            mock_get_timestamp_from_vol_name,
            mock_gen_host_name,
            mock_get_vol_host):

        """Test deny access."""
        host_dict_ips = []
        for host in self.get_host_list_return_value():
            if host.find('netaddrs/ipv4').text is not None:
                host_dict = {
                    'index': host.find('index').text,
                    'hostid': host.find('hostid').text,
                    'name': host.find('name').text,
                    'ipv4': [host.find('netaddrs').find('ipv4').text]}
                host_dict_ips.append(host_dict)

        for host in host_dict_ips:
            fake_access_to = host['ipv4'][0]
        fake_access = fakes.AccessClass('fakeAccessType', 'ro', fake_access_to)

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'vol_name'

        mock_api_return = (
            qnap.QnapShareDriver._create_api_executor.return_value)
        mock_api_return.get_host_list.return_value = (
            self.get_host_list_return_value())
        mock_get_timestamp_from_vol_name.return_value = 'fakeTimeStamp'
        mock_gen_host_name.return_value = 'manila-fakeHostName'
        mock_get_vol_host.return_value = host_dict_ips
        mock_api_return.add_host.return_value = None
        mock_api_return.set_nfs_access.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver._deny_access(
            'context', self.share, fake_access, share_server=None)

        mock_check_share_access.assert_called_once_with(
            'NFS', 'fakeAccessType')

    @mock.patch.object(qnap.QnapShareDriver, '_get_timestamp_from_vol_name')
    @mock.patch.object(qnap.QnapShareDriver, '_check_share_access')
    def test_deny_access_with_hostlist_not_equel_access_to(
            self,
            mock_check_share_access,
            mock_get_timestamp_from_vol_name):
        """Test deny access."""
        fake_access = fakes.AccessClass('fakeAccessType', 'ro', 'fakeIp')

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'vol_name'
        mock_api_return = (
            qnap.QnapShareDriver._create_api_executor.return_value)
        mock_api_return.get_host_list.return_value = (
            self.get_host_list_return_value())
        mock_api_return.add_host.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver._deny_access(
            'context', self.share, fake_access, share_server=None)

        mock_check_share_access.assert_called_once_with(
            'NFS', 'fakeAccessType')

    @mock.patch.object(qnap.QnapShareDriver, '_get_timestamp_from_vol_name')
    @mock.patch.object(qnap.QnapShareDriver, '_check_share_access')
    def test_deny_access_without_hostlist(
            self,
            mock_check_share_access,
            mock_get_timestamp_from_vol_name):
        """Test deny access without hostlist."""
        fake_access = fakes.AccessClass('fakeAccessType', 'ro', 'fakeIp')

        mock_private_storage = mock.Mock()
        mock_private_storage.get.return_value = 'fakeVolName'
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_host_list.return_value = None
        mock_get_timestamp_from_vol_name.return_value = 'fakeHostName'
        mock_api_executor.return_value.add_host.return_value = None
        mock_api_executor.return_value.set_nfs_access.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.driver._deny_access(
            'context', self.share, fake_access, share_server=None)

        mock_check_share_access.assert_called_once_with(
            'NFS', 'fakeAccessType')

    @ddt.data('NFS', 'CIFS', 'proto')
    def test_check_share_access(self, test_proto):
        """Test check_share_access."""
        mock_private_storage = mock.Mock()
        mock_api_executor = qnap.QnapShareDriver._create_api_executor
        mock_api_executor.return_value.get_host_list.return_value = None
        mock_api_executor.return_value.add_host.return_value = None
        mock_api_executor.return_value.set_nfs_access.return_value = None

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', 'Storage Pool 1',
                       private_storage=mock_private_storage)
        self.assertRaises(
            exception.InvalidShareAccess,
            self.driver._check_share_access,
            share_proto=test_proto,
            access_type='notser')

    def test_get_ts_model_pool_id(self):
        """Test get ts model pool id."""
        mock_private_storage = mock.Mock()

        self._do_setup('http://1.2.3.4:8080', '1.2.3.4', 'admin',
                       'qnapadmin', '1',
                       private_storage=mock_private_storage)
        self.assertEqual('1', self.driver._get_ts_model_pool_id('1'))
