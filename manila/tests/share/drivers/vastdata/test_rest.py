# Copyright 2024 VAST Data Inc.
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
import io
import unittest
from unittest import mock

import ddt
import requests

from manila import exception as manila_exception
from manila.share.drivers.vastdata import driver_util
from manila.share.drivers.vastdata import rest as vast_rest


fake_metrics = driver_util.Bunch.from_dict(
    {
        "object_ids": [1],
        "prop_list": [
            "timestamp",
            "object_id",
            "Capacity,drr",
            "Capacity,physical_space_in_use",
            "Capacity,physical_space",
            "Capacity,logical_space",
            "Capacity,logical_space_in_use",
        ],
        "data": [
            [
                "2024-04-13T14:47:48Z",
                1,
                1.2,
                30635076602.0,
                711246584217.0,
                505850953728.0,
                22370924820.0,
            ],
            [
                "2024-04-13T14:47:38Z",
                1,
                1.2,
                30635109399.0,
                711246584217.0,
                505850134528.0,
                22370810131.0,
            ],
            [
                "2024-04-13T14:47:28Z",
                1,
                1.2,
                30635142195.0,
                711246584217.0,
                505849217024.0,
                22370720020.0,
            ],
            [
                "2024-04-13T14:47:18Z",
                1,
                1.2,
                30635174991.0,
                711246584217.0,
                505848365056.0,
                22370654484.0,
            ],
            [
                "2024-04-13T14:47:08Z",
                1,
                1.2,
                30635207787.0,
                711246584217.0,
                505847447552.0,
                22420396308.0,
            ],
            [
                "2024-04-13T14:46:58Z",
                1,
                1.2,
                30635248783.0,
                711246584217.0,
                505846398976.0,
                22420306196.0,
            ],
        ],
        "granularity": None,
    }
)


class TestSession(unittest.TestCase):

    def setUp(self):
        self.session = vast_rest.Session(
            "host", "username",
            "password", False, "1.0"
        )

    @mock.patch("requests.Session.request")
    def test_refresh_auth_token_success(self, mock_request):
        mock_request.return_value.json.return_value = {"access": "test_token"}
        self.session.refresh_auth_token()
        self.assertEqual(
            self.session.headers["authorization"],
            "Bearer test_token"
        )

    @mock.patch("requests.Session.request")
    def test_refresh_auth_token_failure(self, mock_request):
        mock_request.side_effect = ConnectionError()
        with self.assertRaises(manila_exception.VastApiException):
            self.session.refresh_auth_token()

    @mock.patch("requests.Session.request")
    def test_request_success(self, mock_request):
        mock_request.return_value.status_code = 200
        self.session.request(
            "GET", "test_method",
            log_result=False, params={"foo": "bar"}
        )
        mock_request.assert_called_once_with(
            "GET", "https://host/api/test_method/",
            verify=False, params={"foo": "bar"}
        )

    @mock.patch("requests.Session.request")
    def test_request_failure_400(self, mock_request):
        mock_request.return_value.status_code = 400
        mock_request.return_value.text = "foo/bar"
        with self.assertRaises(manila_exception.VastApiException):
            self.session.request(
                "POST", "test_method",
                data={"data": {"foo": "bar"}}
            )

    def test_request_failure_500(self):

        resp = requests.Response()
        resp.status_code = 500
        resp.raw = io.BytesIO(b"Server error")

        with mock.patch(
                "requests.Session.request", new=lambda *a, **k: resp
        ):
            with self.assertRaises(manila_exception.VastApiException) as exc:
                self.session.request("GET", "test_method", log_result=False)
            self.assertIn("Server Error", str(exc.exception))

    def test_request_no_return_content(self):
        resp = requests.Response()
        resp.status_code = 200
        resp.raw = io.BytesIO(b"")

        with mock.patch(
                "requests.Session.request", new=lambda *a, **k: resp
        ):
            res = self.session.request("GET", "test_method")
        self.assertFalse(res)

    @mock.patch(
        "manila.share.drivers.vastdata.rest.Session.refresh_auth_token",
        mock.MagicMock()
    )
    def test_refresh_token_retries(self):
        resp = requests.Response()
        resp.status_code = 403
        resp.raw = io.BytesIO(b"Token is invalid")

        with mock.patch("requests.Session.request", new=lambda *a, **k: resp):
            with self.assertRaises(manila_exception.VastApiRetry):
                self.session.request("POST", "test_method", foo="bar")

    def test_getattr_with_underscore(self):
        with self.assertRaises(AttributeError):
            self.session.__getattr__("_private")

    @mock.patch.object(vast_rest.Session, "request")
    def test_getattr_without_underscore(self, mock_request):
        attr = "public"
        params = {"key": "value"}
        self.session.__getattr__(attr)(**params)
        mock_request.assert_called_once_with("get", attr, params=params)


class TestVastResource(unittest.TestCase):
    def setUp(self):
        self.mock_rest = mock.MagicMock()
        self.vast_resource = vast_rest.VastResource(self.mock_rest)

    def test_list_with_filtering_params(self):
        self.vast_resource.list(name="test")
        self.mock_rest.session.get.assert_called_with(
            self.vast_resource.resource_name, params={"name": "test"}
        )

    def test_create_with_provided_params(self):
        self.vast_resource.create(name="test", size=10)
        self.mock_rest.session.post.assert_called_with(
            self.vast_resource.resource_name, data={"name": "test", "size": 10}
        )

    def test_update_with_provided_params(self):
        self.vast_resource.update("1", name="test", size=10)
        self.mock_rest.session.patch.assert_called_with(
            f"{self.vast_resource.resource_name}/1",
            data={"name": "test", "size": 10}
        )

    def test_delete_when_entry_not_found(self):
        self.vast_resource.one = mock.MagicMock(return_value=None)
        self.vast_resource.delete("test")
        self.mock_rest.session.delete.assert_not_called()

    def test_delete_when_entry_found(self):
        mock_entry = mock.MagicMock()
        mock_entry.id = "1"
        self.vast_resource.one = mock.MagicMock(return_value=mock_entry)
        self.vast_resource.delete("test")
        self.mock_rest.session.delete.assert_called_with(
            f"{self.vast_resource.resource_name}/{mock_entry.id}"
        )

    def test_one_when_no_entries_found(self):
        self.vast_resource.list = mock.MagicMock(return_value=[])
        result = self.vast_resource.one("test")
        self.assertIsNone(result)

    def test_one_when_multiple_entries_found(self):
        self.vast_resource.list = mock.MagicMock(
            return_value=[mock.MagicMock(), mock.MagicMock()]
        )
        with self.assertRaises(manila_exception.VastDriverException):
            self.vast_resource.one("test")

    def test_one_when_single_entry_found(self):
        mock_entry = mock.MagicMock()
        self.vast_resource.list = mock.MagicMock(return_value=[mock_entry])
        result = self.vast_resource.one("test")
        self.assertEqual(result, mock_entry)

    def test_ensure_when_entry_not_found(self):
        self.vast_resource.one = mock.MagicMock(return_value=None)
        mock_entry = mock.MagicMock()
        self.vast_resource.create = mock.MagicMock(return_value=mock_entry)
        result = self.vast_resource.ensure("test", size=10)
        self.assertEqual(result, mock_entry)

    def test_ensure_when_entry_found(self):
        mock_entry = mock.MagicMock()
        self.vast_resource.one = mock.MagicMock(return_value=mock_entry)
        result = self.vast_resource.ensure("test", size=10)
        self.assertEqual(result, mock_entry)


class ViewTest(unittest.TestCase):
    @mock.patch(
        "manila.share.drivers.vastdata.rest.Session.refresh_auth_token",
        mock.MagicMock()
    )
    def test_view_create(self):
        with mock.patch(
                "manila.share.drivers.vastdata.rest.Session.post"
        ) as mock_session:
            rest_api = vast_rest.RestApi(
                "host",
                "username",
                "password",
                True,
                "1.0"
            )
            rest_api.views.create("test-view", "/test", 1)

        self.assertEqual(("views",), mock_session.call_args.args)
        self.assertDictEqual(
            {
                "data": {
                    "name": "test-view",
                    "path": "/test",
                    "policy_id": 1,
                    "create_dir": True,
                    "protocols": ["NFS"],
                }
            },
            mock_session.call_args.kwargs,
        )


@mock.patch(
    "manila.share.drivers.vastdata.rest.Session.refresh_auth_token",
    mock.MagicMock()
)
@mock.patch(
    "manila.share.drivers.vastdata.rest.Session.get",
    mock.MagicMock(return_value=fake_metrics),
)
class TestCapacityMetrics(unittest.TestCase):

    def test_capacity_metrics(self):
        metrics_list = [
            "Capacity,drr",
            "Capacity,logical_space",
            "Capacity,logical_space_in_use",
            "Capacity,physical_space",
            "Capacity,physical_space_in_use",
        ]
        expected = {
            "": 1,
            "drr": 1.2,
            "physical_space_in_use": 30635248783.0,
            "physical_space": 711246584217.0,
            "logical_space": 505846398976.0,
            "logical_space_in_use": 22420306196.0,
        }
        rest_api = vast_rest.RestApi(
            "host",
            "username",
            "password",
            True,
            "1.0"
        )
        metrics = rest_api.capacity_metrics.get(metrics_list)
        self.assertDictEqual(expected, metrics)


@mock.patch(
    "manila.share.drivers.vastdata.rest.Session.refresh_auth_token",
    mock.MagicMock()
)
@ddt.ddt
class TestFolders(unittest.TestCase):

    @mock.patch(
        "manila.share.drivers.vastdata.rest.Session.refresh_auth_token",
        mock.MagicMock()
    )
    def setUp(self):
        self.rest_api = vast_rest.RestApi(
            "host", "username", "password", True, "1.0"
        )

    @ddt.data(
        "4.3.9",
        "4.0.11.12",
        "3.4.6.123.1",
        "4.5.6-1",
        "4.6.0",
        "4.6.0-1",
        "4.6.0-1.1",
        "4.6.9",
    )
    def test_requisite_decorator(self, cluster_version):
        """Test `requisite` decorator produces exception

         when cluster version doesn't met requirements
         """
        with mock.patch(
            "manila.share.drivers.vastdata.rest.RestApi.get_sw_version",
            new=lambda s: cluster_version,
        ):
            self.assertRaises(
                manila_exception.VastDriverException,
                lambda: self.rest_api.folders.delete("/abc")
            )

    def test_trash_api_disabled(self):
        def raise_http_err(*args, **kwargs):
            resp = requests.Response()
            resp.status_code = 400
            resp.raw = io.BytesIO(b"trash folder disabled")
            raise manila_exception.VastApiException(message=resp.text)

        with (
            mock.patch(
                "manila.share.drivers.vastdata.rest.Session.delete",
                side_effect=raise_http_err,
            ),
            mock.patch(
                "manila.share.drivers.vastdata.rest.RestApi.get_sw_version",
                new=lambda s: "5.0.0",
            ),
        ):
            with self.assertRaises(
                    manila_exception.VastDriverException
            ) as exc:
                self.rest_api.folders.delete("/abc")
        self.assertIn("Trash Folder Access is disabled", str(exc.exception))

    def test_trash_api_unpredictable_error(self):
        def raise_http_err(*args, **kwargs):
            raise RuntimeError()

        with (
            mock.patch(
                "manila.share.drivers.vastdata.rest.Session.delete",
                side_effect=raise_http_err,
            ),
            mock.patch(
                "manila.share.drivers.vastdata.rest.RestApi.get_sw_version",
                new=lambda s: "5.0.0",
            ),
        ):
            with self.assertRaises(RuntimeError):
                self.rest_api.folders.delete("/abc")

    def test_double_deletion(self):
        def raise_http_err(*args, **kwargs):
            resp = requests.Response()
            resp.status_code = 400
            resp.raw = io.BytesIO(b"no such directory")
            raise manila_exception.VastApiException(message=resp.text)

        with (
            mock.patch(
                "manila.share.drivers.vastdata.rest.Session.delete",
                side_effect=raise_http_err,
            ),
            mock.patch(
                "manila.share.drivers.vastdata.rest.RestApi.get_sw_version",
                new=lambda s: "5.0.0",
            ),
        ):
            with self.assertLogs(level="DEBUG") as cm:
                self.rest_api.folders.delete("/abc")
            self.assertIn(
                "remote directory might have been removed earlier",
                str(cm.output)
            )


class VipPoolTest(unittest.TestCase):
    @mock.patch(
        "manila.share.drivers.vastdata.rest.Session.refresh_auth_token",
        mock.MagicMock()
    )
    def setUp(self):
        self.rest_api = vast_rest.RestApi(
            "host",
            "username",
            "password",
            True,
            "1.0"
        )

    def test_no_vipool(self):
        with mock.patch(
                "manila.share.drivers.vastdata.rest.Session.get",
                return_value=[]
        ):
            with self.assertRaises(
                    manila_exception.VastDriverException
            ) as exc:
                self.rest_api.vip_pools.vips("test-vip")
        self.assertIn("No vip pool found", str(exc.exception))

    def test_no_vips(self):
        vippool = driver_util.Bunch(ip_ranges=[])
        with mock.patch(
            "manila.share.drivers.vastdata.rest.Session.get",
                return_value=[vippool]
        ):
            with self.assertRaises(
                    manila_exception.VastDriverException
            ) as exc:
                self.rest_api.vip_pools.vips("test-vip")
        self.assertIn(
            "Pool test-vip has no available vips",
            str(exc.exception)
        )

    def test_vips_ok(self):
        vippool = driver_util.Bunch(
            ip_ranges=[["15.0.0.1", "15.0.0.4"], ["10.0.0.27", "10.0.0.30"]]
        )
        expected = [
            "15.0.0.1",
            "15.0.0.2",
            "15.0.0.3",
            "15.0.0.4",
            "10.0.0.27",
            "10.0.0.28",
            "10.0.0.29",
            "10.0.0.30",
        ]
        with mock.patch(
            "manila.share.drivers.vastdata.rest.Session.get",
                return_value=[vippool]
        ):
            vips = self.rest_api.vip_pools.vips("test-vip")
        self.assertListEqual(vips, expected)


class TestRestApi(unittest.TestCase):

    @mock.patch("manila.share.drivers.vastdata.rest.Session")
    def test_get_sw_version(self, mock_session):
        mock_session.return_value.versions.return_value = [
            mock.MagicMock(sys_version="1.0")
        ]
        rest_api = vast_rest.RestApi(
            "host", "username", "password", True, "1.0"
        )
        version = rest_api.get_sw_version()
        self.assertEqual(version, "1.0")
