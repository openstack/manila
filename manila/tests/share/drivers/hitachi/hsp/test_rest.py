# Copyright (c) 2016 Hitachi Data Systems, Inc.
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

import ddt
import json
import mock
import requests
import time

from manila import exception
from manila.share.drivers.hitachi.hsp import rest
from manila import test
from manila.tests.share.drivers.hitachi.hsp import fakes


class FakeRequests(object):
    status_code = 0
    headers = {}
    content = ""

    def __init__(self, status_code, content='null'):
        self.status_code = status_code
        self.headers = {'location': 'fake_location'}
        self.content = content

    def json(self):
        return {'messages': [{'message': 'fake_msg'}]}


@ddt.ddt
class HitachiHSPRestTestCase(test.TestCase):
    def setUp(self):
        super(HitachiHSPRestTestCase, self).setUp()
        self.hitachi_hsp_host = '172.24.47.190'
        self.hitachi_hsp_username = 'hds_hnas_user'
        self.hitachi_hsp_password = 'hds_hnas_password'

        self._driver = rest.HSPRestBackend(self.hitachi_hsp_host,
                                           self.hitachi_hsp_username,
                                           self.hitachi_hsp_password)

    @ddt.data(202, 500)
    def test__send_post(self, code):
        self.mock_object(requests, "post", mock.Mock(
            return_value=FakeRequests(code)))

        if code == 202:
            self.mock_object(rest.HSPRestBackend, "_wait_job_status",
                             mock.Mock())
            self._driver._send_post('fake_url')

            rest.HSPRestBackend._wait_job_status.assert_called_once_with(
                'fake_location', 'COMPLETE')
        else:
            self.assertRaises(exception.HSPBackendException,
                              self._driver._send_post, 'fake_url')

    @ddt.data({'code': 200, 'content': 'null'},
              {'code': 200, 'content': 'fake_content'},
              {'code': 500, 'content': 'null'})
    @ddt.unpack
    def test__send_get(self, code, content):
        self.mock_object(requests, "get", mock.Mock(
            return_value=FakeRequests(code, content)))

        if code == 200:
            result = self._driver._send_get('fake_url')
            if content == 'null':
                self.assertIsNone(result)
            else:
                self.assertEqual(FakeRequests(code, content).json(), result)
        else:
            self.assertRaises(exception.HSPBackendException,
                              self._driver._send_get, 'fake_url')

    @ddt.data(202, 500)
    def test__send_delete(self, code):
        self.mock_object(requests, "delete", mock.Mock(
            return_value=FakeRequests(code)))

        if code == 202:
            self.mock_object(rest.HSPRestBackend, "_wait_job_status",
                             mock.Mock())
            self._driver._send_delete('fake_url')

            rest.HSPRestBackend._wait_job_status.assert_called_once_with(
                'fake_location', 'COMPLETE')
        else:
            self.assertRaises(exception.HSPBackendException,
                              self._driver._send_delete, 'fake_url')

    def test_add_file_system(self):
        url = "https://172.24.47.190/hspapi/file-systems/"

        payload = {
            'quota': fakes.file_system['properties']['quota'],
            'auto-access': False,
            'enabled': True,
            'description': '',
            'record-access-time': True,
            'tags': '',
            'space-hwm': 90,
            'space-lwm': 70,
            'name': fakes.file_system['properties']['name'],
        }

        self.mock_object(rest.HSPRestBackend, "_send_post", mock.Mock())
        self._driver.add_file_system(fakes.file_system['properties']['name'],
                                     fakes.file_system['properties']['quota'])

        rest.HSPRestBackend._send_post.assert_called_once_with(
            url, payload=json.dumps(payload))

    def test_get_file_system(self):
        url = ("https://172.24.47.190/hspapi/file-systems/list?name=%s" %
               fakes.file_system['properties']['name'])

        self.mock_object(rest.HSPRestBackend, "_send_get", mock.Mock(
            return_value={'list': [fakes.file_system]}))

        result = self._driver.get_file_system(
            fakes.file_system['properties']['name'])

        self.assertEqual(fakes.file_system, result)

        rest.HSPRestBackend._send_get.assert_called_once_with(url)

    def test_get_file_system_exception(self):
        url = ("https://172.24.47.190/hspapi/file-systems/list?name=%s" %
               fakes.file_system['properties']['name'])

        self.mock_object(rest.HSPRestBackend, "_send_get",
                         mock.Mock(return_value=None))

        self.assertRaises(exception.HSPItemNotFoundException,
                          self._driver.get_file_system,
                          fakes.file_system['properties']['name'])

        rest.HSPRestBackend._send_get.assert_called_once_with(url)

    def test_delete_file_system(self):
        url = ("https://172.24.47.190/hspapi/file-systems/%s" %
               fakes.file_system['id'])

        self.mock_object(rest.HSPRestBackend, "_send_delete", mock.Mock())
        self._driver.delete_file_system(fakes.file_system['id'])

        rest.HSPRestBackend._send_delete.assert_called_once_with(url)

    def test_resize_file_system(self):
        url = ("https://172.24.47.190/hspapi/file-systems/%s" %
               fakes.file_system['id'])
        new_size = 53687091200
        payload = {'quota': new_size}

        self.mock_object(rest.HSPRestBackend, "_send_post", mock.Mock())
        self._driver.resize_file_system(fakes.file_system['id'], new_size)

        rest.HSPRestBackend._send_post.assert_called_once_with(
            url, payload=json.dumps(payload))

    def test_rename_file_system(self):
        url = ("https://172.24.47.190/hspapi/file-systems/%s" %
               fakes.file_system['id'])
        new_name = "fs_rename"
        payload = {'name': new_name}

        self.mock_object(rest.HSPRestBackend, "_send_post", mock.Mock())

        self._driver.rename_file_system(fakes.file_system['id'], new_name)

        rest.HSPRestBackend._send_post.assert_called_once_with(
            url, payload=json.dumps(payload))

    def test_add_share(self):
        url = "https://172.24.47.190/hspapi/shares/"
        payload = {
            'description': '',
            'type': 'NFS',
            'enabled': True,
            'tags': '',
            'name': fakes.share['name'],
            'file-system-id': fakes.share['properties']['file-system-id'],
        }

        self.mock_object(rest.HSPRestBackend, "_send_post", mock.Mock())

        self._driver.add_share(fakes.share['name'],
                               fakes.share['properties']['file-system-id'])

        rest.HSPRestBackend._send_post.assert_called_once_with(
            url, payload=json.dumps(payload))

    @ddt.data({'fs_id': None,
               'name': fakes.share['name'],
               'url': 'https://172.24.47.190/hspapi/shares/list?'
                      'name=aa4a7710-f326-41fb-ad18-b4ad587fc87a'},
              {'fs_id': fakes.share['properties']['file-system-id'],
               'name': None,
               'url': 'https://172.24.47.190/hspapi/shares/list?'
                      'file-system-id=33689245-1806-45d0-8507-0700b5f89750'})
    @ddt.unpack
    def test_get_share(self, fs_id, name, url):
        self.mock_object(rest.HSPRestBackend, "_send_get",
                         mock.Mock(return_value={'list': [fakes.share]}))

        result = self._driver.get_share(fs_id, name)

        self.assertEqual(fakes.share, result)

        rest.HSPRestBackend._send_get.assert_called_once_with(url)

    def test_get_share_exception(self):
        url = ("https://172.24.47.190/hspapi/shares/list?"
               "name=aa4a7710-f326-41fb-ad18-b4ad587fc87a")

        self.mock_object(rest.HSPRestBackend, "_send_get", mock.Mock(
            return_value=None))

        self.assertRaises(exception.HSPItemNotFoundException,
                          self._driver.get_share, None, fakes.share['name'])

        rest.HSPRestBackend._send_get.assert_called_once_with(url)

    def test_delete_share(self):
        url = "https://172.24.47.190/hspapi/shares/%s" % fakes.share['id']

        self.mock_object(rest.HSPRestBackend, "_send_delete")

        self._driver.delete_share(fakes.share['id'])

        rest.HSPRestBackend._send_delete.assert_called_once_with(url)

    def test_add_access_rule(self):
        url = "https://172.24.47.190/hspapi/shares/%s/" % fakes.share['id']
        payload = {
            "action": "add-access-rule",
            "name": fakes.share['id'] + fakes.access_rule['access_to'],
            "host-specification": fakes.access_rule['access_to'],
            "read-write": fakes.access_rule['access_level'],
        }

        self.mock_object(rest.HSPRestBackend, "_send_post", mock.Mock())

        self._driver.add_access_rule(fakes.share['id'],
                                     fakes.access_rule['access_to'],
                                     fakes.access_rule['access_level'])

        rest.HSPRestBackend._send_post.assert_called_once_with(
            url, payload=json.dumps(payload))

    def test_delete_access_rule(self):
        url = "https://172.24.47.190/hspapi/shares/%s/" % fakes.share['id']
        payload = {
            "action": "delete-access-rule",
            "name": fakes.hsp_rules[0]['name'],
        }
        self.mock_object(rest.HSPRestBackend, "_send_post", mock.Mock())

        self._driver.delete_access_rule(fakes.share['id'],
                                        fakes.hsp_rules[0]['name'])

        rest.HSPRestBackend._send_post.assert_called_once_with(
            url, payload=json.dumps(payload))

    @ddt.data({'value': {'list': fakes.hsp_rules}, 'res': fakes.hsp_rules},
              {'value': None, 'res': []})
    @ddt.unpack
    def test_get_access_rules(self, value, res):
        url = ("https://172.24.47.190/hspapi/shares/%s/access-rules" %
               fakes.share['id'])

        self.mock_object(rest.HSPRestBackend, "_send_get", mock.Mock(
            return_value=value))

        result = self._driver.get_access_rules(fakes.share['id'])

        self.assertEqual(res, result)

        rest.HSPRestBackend._send_get.assert_called_once_with(url)

    @ddt.data({'list': [fakes.hsp_cluster]}, None)
    def test_get_clusters(self, value):
        url = "https://172.24.47.190/hspapi/clusters/list"

        self.mock_object(rest.HSPRestBackend, "_send_get", mock.Mock(
            return_value=value))

        if value:
            result = self._driver.get_cluster()

            self.assertEqual(fakes.hsp_cluster, result)
        else:
            self.assertRaises(exception.HSPBackendException,
                              self._driver.get_cluster)

        rest.HSPRestBackend._send_get.assert_called_once_with(url)

    @ddt.data('COMPLETE', 'ERROR', 'RUNNING')
    def test__wait_job_status(self, stat):
        url = "fake_job_url"
        json = {
            'id': 'fake_id',
            'properties': {
                'completion-details': 'Duplicate NFS access rule exists',
                'completion-status': stat,
            },
            'messages': [{
                'id': 'fake_id',
                'message': 'fake_msg',
            }]
        }

        self.mock_object(rest.HSPRestBackend, "_send_get", mock.Mock(
            return_value=json))
        self.mock_object(time, "sleep")

        if stat == 'COMPLETE':
            self._driver._wait_job_status(url, 'COMPLETE')

            rest.HSPRestBackend._send_get.assert_called_once_with(url)
        elif stat == 'ERROR':
            self.assertRaises(exception.HSPBackendException,
                              self._driver._wait_job_status, url, 'COMPLETE')

            rest.HSPRestBackend._send_get.assert_called_once_with(url)
        else:
            self.assertRaises(exception.HSPTimeoutException,
                              self._driver._wait_job_status, url, 'COMPLETE')

            rest.HSPRestBackend._send_get.assert_has_calls([
                mock.call(url), mock.call(url), mock.call(url), mock.call(url),
                mock.call(url),
            ])
