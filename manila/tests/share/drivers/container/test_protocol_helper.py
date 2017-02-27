# Copyright 2016 Mirantis, Inc.
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
"""Unit tests for the Protocol helper module."""

import ddt
import functools
import mock

from manila.common import constants as const
from manila import exception
from manila.share.drivers.container import protocol_helper
from manila import test
from manila.tests.share.drivers.container.fakes import fake_share


@ddt.ddt
class DockerCIFSHelperTestCase(test.TestCase):
    """Tests ContainerShareDriver"""

    def setUp(self):
        super(DockerCIFSHelperTestCase, self).setUp()
        self._helper = mock.Mock()
        self.fake_conf = mock.Mock()
        self.fake_conf.container_cifs_guest_ok = "yes"
        self.DockerCIFSHelper = protocol_helper.DockerCIFSHelper(
            self._helper, share=fake_share(), config=self.fake_conf)

    def fake_exec_sync(self, *args, **kwargs):
        kwargs["execute_arguments"].append(args)
        try:
            ret_val = kwargs["ret_val"]
        except KeyError:
            ret_val = None
        return [ret_val]

    def test_create_share_guest_ok(self):
        expected_arguments = [
            ("fakeserver", ["net", "conf", "addshare", "fakeshareid",
             "/shares/fakeshareid", "writeable=y", "guest_ok=y"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "browseable", "yes"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "hosts allow", "127.0.0.1"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "read only", "no"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "hosts deny", "0.0.0.0/0"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "create mask", "0755"])]
        actual_arguments = []
        self._helper.execute = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val=" fake 192.0.2.2/24 more fake \n" * 20)
        self.DockerCIFSHelper.share = fake_share()

        self.DockerCIFSHelper.create_share("fakeserver")

        self.assertEqual(expected_arguments.sort(), actual_arguments.sort())

    def test_create_share_guest_not_ok(self):
        self.DockerCIFSHelper.conf = mock.Mock()
        self.DockerCIFSHelper.conf.container_cifs_guest_ok = False
        expected_arguments = [
            ("fakeserver", ["net", "conf", "addshare", "fakeshareid",
             "/shares/fakeshareid", "writeable=y", "guest_ok=n"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "browseable", "yes"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "hosts allow", "192.0.2.2"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "read only", "no"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "hosts deny", "0.0.0.0/0"]),
            ("fakeserver", ["net", "conf", "setparm", "fakeshareid",
             "create mask", "0755"])]
        actual_arguments = []
        self._helper.execute = functools.partial(
            self.fake_exec_sync, execute_arguments=actual_arguments,
            ret_val=" fake 192.0.2.2/24 more fake \n" * 20)
        self.DockerCIFSHelper.share = fake_share()

        self.DockerCIFSHelper.create_share("fakeserver")

        self.assertEqual(expected_arguments.sort(), actual_arguments.sort())

    def test_delete_share(self):
        self.DockerCIFSHelper.share = fake_share()

        self.DockerCIFSHelper.delete_share("fakeserver")

        self.DockerCIFSHelper.container.execute.assert_called_with(
            "fakeserver",
            ["net", "conf", "delshare", "fakeshareid"])

    def test__get_access_group_ro(self):
        result = self.DockerCIFSHelper._get_access_group(const.ACCESS_LEVEL_RO)

        self.assertEqual("read list", result)

    def test__get_access_group_rw(self):
        result = self.DockerCIFSHelper._get_access_group(const.ACCESS_LEVEL_RW)

        self.assertEqual("valid users", result)

    def test__get_access_group_other(self):
        self.assertRaises(exception.InvalidShareAccessLevel,
                          self.DockerCIFSHelper._get_access_group,
                          "fake_level")

    def test__get_existing_users(self):
        self.DockerCIFSHelper.container.execute = mock.Mock(
            return_value=("fake_user", ""))

        result = self.DockerCIFSHelper._get_existing_users("fake_server_id",
                                                           "fake_share",
                                                           "fake_access")

        self.assertEqual("fake_user", result)
        self.DockerCIFSHelper.container.execute.assert_called_once_with(
            "fake_server_id",
            ["net", "conf", "getparm", "fake_share", "fake_access"])

    def test__set_users(self):
        self.DockerCIFSHelper.container.execute = mock.Mock()

        self.DockerCIFSHelper._set_users("fake_server_id", "fake_share",
                                         "fake_access", "fake_user")

        self.DockerCIFSHelper.container.execute.assert_called_once_with(
            "fake_server_id",
            ["net", "conf", "setparm", "fake_share", "fake_access",
             "fake_user"])

    def test__allow_access_ok(self):
        self.DockerCIFSHelper._get_access_group = mock.Mock(
            return_value="valid users")
        self.DockerCIFSHelper._get_existing_users = mock.Mock(
            return_value="fake_user")
        self.DockerCIFSHelper._set_users = mock.Mock()

        self.DockerCIFSHelper._allow_access("fake_share", "fake_server_id",
                                            "fake_user2", "rw")

        self.DockerCIFSHelper._get_access_group.assert_called_once_with("rw")
        self.DockerCIFSHelper._get_existing_users.assert_called_once_with(
            "fake_server_id", "fake_share", "valid users")
        self.DockerCIFSHelper._set_users.assert_called_once_with(
            "fake_server_id", "fake_share", "valid users",
            "fake_user fake_user2")

    def test__allow_access_not_ok(self):
        self.DockerCIFSHelper._get_access_group = mock.Mock(
            return_value="valid users")
        self.DockerCIFSHelper._get_existing_users = mock.Mock()
        self.DockerCIFSHelper._get_existing_users.side_effect = TypeError
        self.DockerCIFSHelper._set_users = mock.Mock()

        self.DockerCIFSHelper._allow_access("fake_share", "fake_server_id",
                                            "fake_user2", "rw")

        self.DockerCIFSHelper._get_access_group.assert_called_once_with("rw")
        self.DockerCIFSHelper._get_existing_users.assert_called_once_with(
            "fake_server_id", "fake_share", "valid users")
        self.DockerCIFSHelper._set_users.assert_called_once_with(
            "fake_server_id", "fake_share", "valid users",
            "fake_user2")

    def test__deny_access_ok(self):
        self.DockerCIFSHelper._get_access_group = mock.Mock(
            return_value="valid users")
        self.DockerCIFSHelper._get_existing_users = mock.Mock(
            return_value="fake_user fake_user2")
        self.DockerCIFSHelper._set_users = mock.Mock()

        self.DockerCIFSHelper._deny_access("fake_share", "fake_server_id",
                                           "fake_user2", "rw")

        self.DockerCIFSHelper._get_access_group.assert_called_once_with("rw")
        self.DockerCIFSHelper._get_existing_users.assert_called_once_with(
            "fake_server_id", "fake_share", "valid users")
        self.DockerCIFSHelper._set_users.assert_called_once_with(
            "fake_server_id", "fake_share", "valid users",
            "fake_user")

    def test__deny_access_ok_so_many_users(self):
        self.DockerCIFSHelper._get_access_group = mock.Mock(
            return_value="valid users")
        self.DockerCIFSHelper._get_existing_users = mock.Mock(
            return_value="joost jaap huub dirk")
        self.DockerCIFSHelper._set_users = mock.Mock()

        # Sorry, Jaap.
        self.DockerCIFSHelper._deny_access("fake_share", "fake_server_id",
                                           "jaap", "rw")

        self.DockerCIFSHelper._get_access_group.assert_called_once_with("rw")
        self.DockerCIFSHelper._get_existing_users.assert_called_once_with(
            "fake_server_id", "fake_share", "valid users")
        self.DockerCIFSHelper._set_users.assert_called_once_with(
            "fake_server_id", "fake_share", "valid users",
            "dirk huub joost")

    def test__deny_access_not_ok(self):
        self.DockerCIFSHelper._get_access_group = mock.Mock(
            return_value="valid users")
        self.DockerCIFSHelper._get_existing_users = mock.Mock()
        self.DockerCIFSHelper._get_existing_users.side_effect = TypeError
        self.DockerCIFSHelper._set_users = mock.Mock()
        self.mock_object(protocol_helper.LOG, "warning")

        self.DockerCIFSHelper._deny_access("fake_share", "fake_server_id",
                                           "fake_user2", "rw")

        self.DockerCIFSHelper._get_access_group.assert_called_once_with("rw")
        self.DockerCIFSHelper._get_existing_users.assert_called_once_with(
            "fake_server_id", "fake_share", "valid users")
        self.assertFalse(self.DockerCIFSHelper._set_users.called)
        self.assertTrue(protocol_helper.LOG.warning.called)

    def test_update_access_access_rules_wrong_type(self):
        allow_rules = [{
            "access_to": "192.0.2.2",
            "access_level": "ro",
            "access_type": "fake"
        }]
        self.mock_object(self.DockerCIFSHelper, "_allow_access")

        self.assertRaises(exception.InvalidShareAccess,
                          self.DockerCIFSHelper.update_access,
                          "fakeserver", allow_rules, [], [])

    def test_update_access_access_rules_ok(self):
        access_rules = [{
            "access_to": "fakeuser",
            "access_level": "ro",
            "access_type": "user"
        }]
        self.mock_object(self.DockerCIFSHelper, "_allow_access")
        self.DockerCIFSHelper.container.execute = mock.Mock()

        self.DockerCIFSHelper.update_access("fakeserver",
                                            access_rules, [], [])

        self.DockerCIFSHelper._allow_access.assert_called_once_with(
            "fakeshareid",
            "fakeserver",
            "fakeuser",
            "ro")
        self.DockerCIFSHelper.container.execute.assert_called_once_with(
            "fakeserver",
            ["net", "conf", "setparm", "fakeshareid", "valid users", ""])

    def test_update_access_add_rules(self):
        add_rules = [{
            "access_to": "fakeuser",
            "access_level": "ro",
            "access_type": "user"
        }]
        self.mock_object(self.DockerCIFSHelper, "_allow_access")

        self.DockerCIFSHelper.update_access("fakeserver", [],
                                            add_rules, [])

        self.DockerCIFSHelper._allow_access.assert_called_once_with(
            "fakeshareid",
            "fakeserver",
            "fakeuser",
            "ro")

    def test_update_access_delete_rules(self):
        delete_rules = [{
            "access_to": "fakeuser",
            "access_level": "ro",
            "access_type": "user"
        }]
        self.mock_object(self.DockerCIFSHelper, "_deny_access")

        self.DockerCIFSHelper.update_access("fakeserver", [],
                                            [], delete_rules)

        self.DockerCIFSHelper._deny_access.assert_called_once_with(
            "fakeshareid",
            "fakeserver",
            "fakeuser",
            "ro")

    @ddt.data(('inet',
               "192.168.0.254",
               ["5: br0 inet 192.168.0.254/24 brd 192.168.0.255 "
                "scope global br0 valid_lft forever preferred_lft forever"]),
              ("inet6",
               "2001:470:8:c82:6600:6aff:fe84:8dda",
               ["5: br0 inet6 2001:470:8:c82:6600:6aff:fe84:8dda/64 "
                "scope global valid_lft forever preferred_lft forever"]),
              )
    @ddt.unpack
    def test__fetch_container_address(self, address_family, expected_address,
                                      return_value):
        self.DockerCIFSHelper.container.execute = mock.Mock(
            return_value=return_value)
        address = self.DockerCIFSHelper._fetch_container_address(
            "fakeserver",
            address_family)
        self.assertEqual(expected_address, address)
