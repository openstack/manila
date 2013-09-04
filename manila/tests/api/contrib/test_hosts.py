# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2011 OpenStack, LLC.
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

import datetime

from lxml import etree
import webob.exc

from manila.api.contrib import hosts as os_hosts
from manila import context
from manila import db
from manila import flags
from manila.openstack.common import log as logging
from manila.openstack.common import timeutils
from manila import test


FLAGS = flags.FLAGS
LOG = logging.getLogger(__name__)
created_time = datetime.datetime(2012, 11, 14, 1, 20, 41, 95099)
curr_time = timeutils.utcnow()

SERVICE_LIST = [
    {'created_at': created_time, 'updated_at': curr_time,
     'host': 'test.host.1', 'topic': 'manila-volume', 'disabled': 0,
     'availability_zone': 'manila'},
    {'created_at': created_time, 'updated_at': curr_time,
     'host': 'test.host.1', 'topic': 'manila-volume', 'disabled': 0,
     'availability_zone': 'manila'},
    {'created_at': created_time, 'updated_at': curr_time,
     'host': 'test.host.1', 'topic': 'manila-volume', 'disabled': 0,
     'availability_zone': 'manila'},
    {'created_at': created_time, 'updated_at': curr_time,
     'host': 'test.host.1', 'topic': 'manila-volume', 'disabled': 0,
     'availability_zone': 'manila'}]

LIST_RESPONSE = [{'service-status': 'available', 'service': 'manila-volume',
                  'zone': 'manila', 'service-state': 'enabled',
                  'host_name': 'test.host.1', 'last-update': curr_time},
                 {'service-status': 'available', 'service': 'manila-volume',
                  'zone': 'manila', 'service-state': 'enabled',
                  'host_name': 'test.host.1', 'last-update': curr_time},
                 {'service-status': 'available', 'service': 'manila-volume',
                  'zone': 'manila', 'service-state': 'enabled',
                  'host_name': 'test.host.1', 'last-update': curr_time},
                 {'service-status': 'available', 'service': 'manila-volume',
                  'zone': 'manila', 'service-state': 'enabled',
                  'host_name': 'test.host.1', 'last-update': curr_time}]


def stub_service_get_all(self, req):
    return SERVICE_LIST


class FakeRequest(object):
    environ = {'manila.context': context.get_admin_context()}
    GET = {}


class FakeRequestWithmanilaZone(object):
    environ = {'manila.context': context.get_admin_context()}
    GET = {'zone': 'manila'}


class HostTestCase(test.TestCase):
    """Test Case for hosts."""

    def setUp(self):
        super(HostTestCase, self).setUp()
        self.controller = os_hosts.HostController()
        self.req = FakeRequest()
        self.stubs.Set(db, 'service_get_all',
                       stub_service_get_all)

    def _test_host_update(self, host, key, val, expected_value):
        body = {key: val}
        result = self.controller.update(self.req, host, body=body)
        self.assertEqual(result[key], expected_value)

    def test_list_hosts(self):
        """Verify that the volume hosts are returned."""
        hosts = os_hosts._list_hosts(self.req)
        self.assertEqual(hosts, LIST_RESPONSE)

        manila_hosts = os_hosts._list_hosts(self.req, 'manila-volume')
        expected = [host for host in LIST_RESPONSE
                    if host['service'] == 'manila-volume']
        self.assertEqual(manila_hosts, expected)

    def test_list_hosts_with_zone(self):
        req = FakeRequestWithmanilaZone()
        hosts = os_hosts._list_hosts(req)
        self.assertEqual(hosts, LIST_RESPONSE)

    def test_bad_status_value(self):
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          self.req, 'test.host.1', body={'status': 'bad'})
        self.assertRaises(webob.exc.HTTPBadRequest,
                          self.controller.update,
                          self.req,
                          'test.host.1',
                          body={'status': 'disablabc'})

    def test_bad_update_key(self):
        bad_body = {'crazy': 'bad'}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          self.req, 'test.host.1', body=bad_body)

    def test_bad_update_key_and_correct_udpate_key(self):
        bad_body = {'status': 'disable', 'crazy': 'bad'}
        self.assertRaises(webob.exc.HTTPBadRequest, self.controller.update,
                          self.req, 'test.host.1', body=bad_body)

    def test_good_udpate_keys(self):
        body = {'status': 'disable'}
        self.assertRaises(NotImplementedError, self.controller.update,
                          self.req, 'test.host.1', body=body)

    def test_bad_host(self):
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.update,
                          self.req,
                          'bogus_host_name',
                          body={'disabled': 0})

    def test_show_forbidden(self):
        self.req.environ['manila.context'].is_admin = False
        dest = 'dummydest'
        self.assertRaises(webob.exc.HTTPForbidden,
                          self.controller.show,
                          self.req, dest)
        self.req.environ['manila.context'].is_admin = True

    def test_show_host_not_exist(self):
        """A host given as an argument does not exists."""
        self.req.environ['manila.context'].is_admin = True
        dest = 'dummydest'
        self.assertRaises(webob.exc.HTTPNotFound,
                          self.controller.show,
                          self.req, dest)


class HostSerializerTest(test.TestCase):
    def setUp(self):
        super(HostSerializerTest, self).setUp()
        self.deserializer = os_hosts.HostDeserializer()

    def test_index_serializer(self):
        serializer = os_hosts.HostIndexTemplate()
        text = serializer.serialize({"hosts": LIST_RESPONSE})

        tree = etree.fromstring(text)

        self.assertEqual('hosts', tree.tag)
        self.assertEqual(len(LIST_RESPONSE), len(tree))
        for i in range(len(LIST_RESPONSE)):
            self.assertEqual('host', tree[i].tag)
            self.assertEqual(LIST_RESPONSE[i]['service-status'],
                             tree[i].get('service-status'))
            self.assertEqual(LIST_RESPONSE[i]['service'],
                             tree[i].get('service'))
            self.assertEqual(LIST_RESPONSE[i]['zone'],
                             tree[i].get('zone'))
            self.assertEqual(LIST_RESPONSE[i]['service-state'],
                             tree[i].get('service-state'))
            self.assertEqual(LIST_RESPONSE[i]['host_name'],
                             tree[i].get('host_name'))
            self.assertEqual(str(LIST_RESPONSE[i]['last-update']),
                             tree[i].get('last-update'))

    def test_update_serializer_with_status(self):
        exemplar = dict(host='test.host.1', status='enabled')
        serializer = os_hosts.HostUpdateTemplate()
        text = serializer.serialize(exemplar)

        tree = etree.fromstring(text)

        self.assertEqual('host', tree.tag)
        for key, value in exemplar.items():
            self.assertEqual(value, tree.get(key))

    def test_update_deserializer(self):
        exemplar = dict(status='enabled', foo='bar')
        intext = ("<?xml version='1.0' encoding='UTF-8'?>\n"
                  '<updates><status>enabled</status><foo>bar</foo></updates>')
        result = self.deserializer.deserialize(intext)

        self.assertEqual(dict(body=exemplar), result)
