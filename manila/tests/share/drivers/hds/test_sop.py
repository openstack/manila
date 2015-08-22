# Copyright (c) 2015 Hitachi Data Systems.
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

"""Unit tests for the Hitachi Data Systems Scale-out Platform manila driver."""

import time

import httplib2
import mock
from oslo_config import cfg
from oslo_serialization import jsonutils as json
from oslo_utils import units
from six import moves

from manila import context
from manila import exception
from manila.share import configuration as config
from manila.share.drivers.hds import sop
from manila import test
from manila.tests import fake_share


CONF = cfg.CONF

fake_authorization = {'Authorization': u'Basic ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk'}


class SopShareDriverTestCase(test.TestCase):
    """Tests SopShareDriver."""

    def setUp(self):
        super(SopShareDriverTestCase, self).setUp()
        self._context = context.get_admin_context()
        self.server = {
            'instance_id': 'fake_instance_id',
            'ip': 'fake_ip',
            'username': 'fake_username',
            'password': 'fake_password',
            'pk_path': 'fake_pk_path',
            'backend_details': {
                'ip': '1.2.3.4',
                'instance_id': 'fake',
            },
        }
        CONF.set_default('hdssop_target', 'https://1.2.3.4')
        CONF.set_default('hdssop_adminuser', 'fakeuser')
        CONF.set_default('hdssop_adminpassword', 'fakepassword')
        CONF.set_default('driver_handles_share_servers', False)

        self.fake_conf = config.Configuration(None)
        self._driver = sop.SopShareDriver(configuration=self.fake_conf)
        self.share = fake_share.fake_share(share_proto='NFS')
        self._driver.share_backend_name = 'HDS_SOP'
        self.mock_object(time, 'sleep')

    def test_add_file_system_sopapi(self):
        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)

        httpretval = ({'status': '202',
                       'content-length': '0',
                       'x-sopapi-version': '1.0.0',
                       'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;Secure',
                       'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                       'server': 'Jetty(8.1.3.v20120416)',
                       'location': 'https://1.2.3.4/sopapi/jobs/fakeuuid',
                       'date': 'Tue, 20 Jan 2015 22:41:29 GMT'}, '')

        self.mock_object(httpclient, 'request',
                         mock.Mock(return_value=httpretval))
        self.mock_object(self._driver, '_wait_for_job_completion', mock.Mock())

        fakepayload1 = {
            'quota': 145 * units.Gi,
            'enabled': True,
            'description': '',
            'record-access-time': True,
            'tags': '',
            'space-hwm': 90,
            'space-lwm': 70,
            'name': 'fakeid',
        }

        fsadd = self._driver._add_file_system_sopapi(httpclient, fakepayload1)
        self.assertIsNone(fsadd)
        httpclient.request.assert_called_once_with(
            'https://' +
            self.server['backend_details']['ip'] +
            '/sopapi/file-systems/',
            'POST',
            body=json.dumps(fakepayload1),
            headers=fake_authorization)
        self._driver._wait_for_job_completion.assert_called_once_with(
            httpclient,
            'https://1.2.3.4/sopapi/jobs/fakeuuid')

    def test_add_file_system_sopapi_belowminsize(self):
        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)

        httpretval = ({'status': '400',
                       'content-type': 'application/jsson',
                       'transfer-encoding': 'chunked',
                       'x-sopapi-version': '1.0.0',
                       'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;Secure',
                       'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                       'server': 'Jetty(8.1.3.v20120416)',
                       'location': 'https://1.2.3.4/sopapi/jobs/fakeuuid',
                       'date': 'Tue, 20 Jan 2015 22:41:29 GMT'},
                      {'messages': [{'category': 1,
                                     'message': '''"Property 'quota' is inv'''
                                     'alid. Specify a value from 137438953472 '
                                     'to 6755399441055744."',
                                     'code': 'schema_number_min_constraint',
                                     'type': 'error'},
                                    ]})
        self.mock_object(httpclient, 'request',
                         mock.Mock(return_value=httpretval))
        self.mock_object(self._driver, '_wait_for_job_completion', mock.Mock())

        fakepayload = {
            'quota': 3 * units.Gi,
            'enabled': True,
            'description': '',
            'record-access-time': True,
            'tags': '',
            'space-hwm': 90,
            'space-lwm': 70,
            'name': 'fakeid',
        }
        self.assertRaises(exception.SopAPIError,
                          self._driver._add_file_system_sopapi,
                          httpclient, fakepayload)
        httpclient.request.assert_called_once_with(
            'https://' +
            self.server['backend_details']['ip'] +
            '/sopapi/file-systems/',
            'POST',
            body=json.dumps(fakepayload),
            headers=fake_authorization)
        self.assertEqual(False, self._driver._wait_for_job_completion.called)

    def test_wait_for_job_completion_simple(self):
        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)

        httpreturn = [
            ({'status': '200',
              'content-location': 'https://1.2.3.4/sopapi/jobs/fakeuuid',
              'transfer-encoding': 'chunked',
              'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;Secure',
              'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
              'server': 'Jetty(8.1.3.v20120416)',
              'x-sopapi-version': '1.0.0',
              'date': 'Wed, 21 Jan 2015 04:49:51 GMT',
              'content-type': 'application/json'},
             '{"id":"fakeuuid","properties":{"'
             'resource-name":"","resource-type":"share","creation-timestam'
             'p":1421815791,"completion-status":"PROCESSING","completion-d'
             'etails":"Saving changes","completion-substatus":"RUNNING","r'
             'esource-action":"ADD","percent-complete":75,"resource-id":"b'
             'fakeuuid","target-node-name":"Node005","target-node-id":"fak'
             'euuid","spawned-jobs":false,"spawned-jobs-list-uri":""}}'),
            ({'status': '200',
              'content-location': 'https://1.2.3.4/sopapi/jobs/fakeuuid',
              'transfer-encoding': 'chunked',
              'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;Secure',
              'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
              'server': 'Jetty(8.1.3.v20120416)',
              'x-sopapi-version': '1.0.0',
              'date': 'Wed, 21 Jan 2015 04:49:51 GMT',
              'content-type': 'application/json'},
             '{"id":"fakeuuid","properties":{"'
             'resource-name":"fakeuuid","resou'
             'rce-type":"share","creation-timestamp":1421815791,"completio'
             'n-status":"COMPLETE","completion-details":"Adding share comp'
             'leted","completion-substatus":"OK","resource-action":"ADD","'
             'percent-complete":100,"resource-id":"fakeuuid'
             '","target-node-name":"Node005","target-node-id"'
             ':"fakeuuid","spawned-jobs":false'
             ',"spawned-jobs-list-uri":""}}'),
        ]

        self.mock_object(httpclient, 'request',
                         mock.Mock(side_effect=httpreturn))

        fsadd = self._driver._wait_for_job_completion(httpclient, 'fakeuri')

        expectedresult = {
            u'id': u'fakeuuid',
            u'properties': {
                u'completion-details':
                u'Adding share completed',
                u'completion-status': u'COMPLETE',
                u'completion-substatus': u'OK',
                u'creation-timestamp': 1421815791,
                u'percent-complete': 100,
                u'resource-action': u'ADD',
                u'resource-id': u'fakeuuid',
                u'resource-name': u'fakeuuid',
                u'resource-type': u'share',
                u'spawned-jobs': False,
                u'spawned-jobs-list-uri': u'',
                u'target-node-id': u'fakeuuid',
                u'target-node-name': u'Node005',
            },
        }
        self.assertEqual(expectedresult, fsadd)
        httpcalls = [
            mock.call('fakeuri', 'GET', body='', headers=fake_authorization)
            for x in moves.range(2)]
        self.assertEqual(httpcalls, httpclient.request.call_args_list)

    def test_wait_for_job_completion_notimeout(self):
        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)

        httpreturn = [({'status': '200',
                        'content-location':
                            'https://1.2.3.4/sopapi/jobs/fakeuuid',
                        'transfer-encoding': 'chunked',
                        'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;Secure',
                        'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                        'server': 'Jetty(8.1.3.v20120416)',
                        'x-sopapi-version': '1.0.0',
                        'date': 'Wed, 21 Jan 2015 04:49:51 GMT',
                        'content-type': 'application/json'},
                       '{"id":"fakeuuid","properties":{"resource-name":"","re'
                       'source-type":"share","creation-timestamp":1421815791,'
                       '"completion-status":"PROCESSING","completion-details"'
                       ':"Saving changes","completion-substatus":"RUNNING","r'
                       'esource-action":"ADD","percent-complete":75,"resource'
                       '-id":"fakeuuid","target-node-name":"Node005","target-'
                       'node-id":"fakeuuid","spawned-jobs":false,"spawned-job'
                       's-list-uri":""}}') for x in moves.range(200)
                      ]

        httpreturn.append(({'status': '200',
                            'content-location':
                                'https://1.2.3.4/sopapi/jobs/fakeuuid',
                            'transfer-encoding': 'chunked',
                            'set-cookie':
                                'JSESSIONID=abcdef;Path=/sopapi;Secure',
                            'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                            'server': 'Jetty(8.1.3.v20120416)',
                            'x-sopapi-version': '1.0.0',
                            'date': 'Wed, 21 Jan 2015 04:49:51 GMT',
                            'content-type': 'application/json'},
                           '{"id":"fakeuuid","properties":{"resource-name":"fa'
                           'keuuid","resource-type":"share","creation-timestam'
                           'p":1421816291,"completion-status":"COMPLETE","comp'
                           'letion-details":"Adding share completed","completi'
                           'on-substatus":"OK","resource-action":"ADD","percen'
                           't-complete":100,"resource-id":"fakeuuid","target-n'
                           'ode-name":"Node005","target-node-id":"fakeuuid","s'
                           'pawned-jobs":false,"spawned-jobs-list-uri":""}}'))

        self.mock_object(httpclient, 'request',
                         mock.Mock(side_effect=httpreturn))
        self.mock_object(time, 'sleep', mock.Mock())

        fsadd = self._driver._wait_for_job_completion(httpclient, 'fakeuri')

        expectedresult = {
            u'id': u'fakeuuid',
            u'properties': {
                u'completion-details':
                u'Adding share completed',
                u'completion-status': u'COMPLETE',
                u'completion-substatus': u'OK',
                u'creation-timestamp': 1421816291,
                u'percent-complete': 100,
                u'resource-action': u'ADD',
                u'resource-id': u'fakeuuid',
                u'resource-name': u'fakeuuid',
                u'resource-type': u'share',
                u'spawned-jobs': False,
                u'spawned-jobs-list-uri': u'',
                u'target-node-id': u'fakeuuid',
                u'target-node-name': u'Node005',
            },
        }
        self.assertEqual(expectedresult, fsadd)
        httpcalls = [mock.call('fakeuri',
                               'GET',
                               body='',
                               headers=fake_authorization)
                     for x in moves.range(201)]
        self.assertEqual(httpcalls, httpclient.request.call_args_list)
        timecalls = [mock.call(1) for x in moves.range(200)]
        self.assertEqual(timecalls, time.sleep.call_args_list)

    def test_wait_for_job_completion_timeout(self):
        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)

        httpret = [({'status': '200',
                     'content-location': 'https://1.2.3.4/sopapi/jobs/'
                     'fakeuuid',
                     'transfer-encoding': 'chunked',
                     'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;Secure',
                     'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                     'server': 'Jetty(8.1.3.v20120416)',
                     'x-sopapi-version': '1.0.0',
                     'date': 'Wed, 21 Jan 2015 04:49:51 GMT',
                     'content-type': 'application/json'},
                    '{"id":"fakeuuid","properties'
                    '":{"resource-name":"","resource-type":"share","creation-'
                    'timestamp":1421815791,"completion-status":"PROCESSING","'
                    'completion-details":"Saving changes","completion-substat'
                    'us":"RUNNING","resource-action":"ADD","percent-complete"'
                    ':75,"resource-id":"fakeuuid"'
                    ',"target-node-name":"Node005","target-node-id":"fakeuuid'
                    '","spawned-jobs":false,"spawned-jobs-list-uri":""}}')
                   for x in moves.range(301)]

        httpret.append(({'status': '200',
                         'content-location':
                         'https://1.2.3.4/sopapi/jobs/fakeuuid',
                         'transfer-encoding': 'chunked',
                         'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;Secure',
                         'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                         'server': 'Jetty(8.1.3.v20120416)',
                         'x-sopapi-version': '1.0.0',
                         'date': 'Wed, 21 Jan 2015 04:49:51 GMT',
                         'content-type': 'application/json'},
                        '{"id":"fakeuuid","propert'
                        'ies":{"resource-name":"fakeuuid","resource-type":"sha'
                        're","creation-timestamp":1421815791,"completion-statu'
                        's":"COMPLETE","completion-details":"Adding share comp'
                        'leted","completion-substatus":"OK","resource-action"'
                        ':"ADD","percent-complete": 100,"resource-id":"fakeuui'
                        'd","target-node-name":"Node005","target-node-id":"fa'
                        'keuuid","spawned-jobs":false,"spawned-jobs-list-uri"'
                        ':""}}'))

        self.mock_object(httpclient, 'request', mock.Mock(side_effect=httpret))
        self.mock_object(time, 'sleep', mock.Mock())

        self.assertRaises(exception.SopAPIError,
                          self._driver._wait_for_job_completion,
                          httpclient, 'fakeuri')
        httpcalls = [mock.call('fakeuri',
                               'GET',
                               body='',
                               headers=fake_authorization)
                     for x in moves.range(301)]
        self.assertEqual(httpcalls, httpclient.request.call_args_list)
        timecalls = [mock.call(1) for x in moves.range(301)]
        self.assertEqual(timecalls, time.sleep.call_args_list)

    def test_add_share_sopapi(self):
        httpclient = httplib2.Http(disable_ssl_certificate_validation=True,
                                   timeout=None)

        httpret = ({'status': '202',
                    'content-length': '0',
                    'x-sopapi-version': '1.0.0',
                    'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;Secure',
                    'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                    'server': 'Jetty(8.1.3.v20120416)',
                    'location': 'https://1.2.3.4/sopapi/jobs/fakeuuid',
                    'date': 'Wed, 21 Jan 2015 05:29:35 GMT'}, '')
        self.mock_object(httpclient, 'request',
                         mock.Mock(return_value=httpret))

        waitforret = json.loads('{"id":"fakeuuid'
                                '","properties":{"resource-name":"fakeuuid'
                                '","resource-type":"share",'
                                '"creation-timestamp":1421815791,"c'
                                'ompletion-status":"COMPLETE","completion-de'
                                'tails":"Adding share completed","completion'
                                '-substatus":"OK","resource-action":"ADD","p'
                                'ercent-complete":100,"resource-id":"fakeuui'
                                'd","target-node-name":"Node005","target-nod'
                                'e-id":"fakeuuid1","spawned-jobs":false,"spaw'
                                'ned-jobs-list-uri":""}}')
        self.mock_object(self._driver, '_wait_for_job_completion',
                         mock.Mock(return_value=waitforret))

        fakepayload = {
            'description': '',
            'type': 'NFS',
            'enabled': True,
            'tags': '',
            'name': 'fakeuuid',
            'file-system-id': 'fakeuuid',
        }
        fsadd = self._driver._add_share_sopapi(httpclient, fakepayload)
        self.assertEqual('fakeuuid', fsadd)
        httpcalls = [mock.call('https://' +
                               self.server['backend_details']['ip'] +
                               '/sopapi/shares/',
                               'POST',
                               body=json.dumps(fakepayload),
                               headers=fake_authorization)]
        self.assertEqual(httpcalls, httpclient.request.call_args_list)
        self._driver._wait_for_job_completion.assert_called_once_with(
            httpclient, 'https://' +
            self.server['backend_details']['ip'] +
            '/sopapi/jobs/fakeuuid')

    def test_create_share_success(self):

        self.mock_object(self._driver, '_add_file_system_sopapi', mock.Mock())
        self.mock_object(self._driver, '_get_file_system_id_by_name',
                         mock.Mock(return_value='fakeuuid'))
        self.mock_object(self._driver, '_add_share_sopapi',
                         mock.Mock(return_value='fakeuuid'))

        result = self._driver.create_share(
            self._context, self.share, share_server=self.server)

        self.assertEqual('https://1.2.3.4:/fakeuuid', result)

        fakepayload = {
            'quota': 1073741824,
            'enabled': True,
            'description': '',
            'record-access-time': True,
            'tags': '',
            'space-hwm': 90,
            'space-lwm': 70,
            'name': 'fakeid',
        }

        fakepayload1 = {
            'description': '',
            'type': 'NFS',
            'enabled': True,
            'tags': '',
            'name': 'fakeid',
            'file-system-id': 'fakeuuid',
        }
        self._driver._add_file_system_sopapi.assert_called_once_with(
            mock.ANY, fakepayload)
        self._driver._get_file_system_id_by_name.assert_called_once_with(
            mock.ANY, 'fakeid')
        self._driver._add_share_sopapi.assert_called_once_with(
            mock.ANY, fakepayload1)

    def test_get_share_stats_refresh_false(self):
        self._driver._stats = {'fake_key': 'fake_value'}

        result = self._driver.get_share_stats(False)
        self.assertEqual(result, self._driver._stats)

    def test_get_share_stats_refresh_true(self):
        test_data = {
            'driver_handles_share_servers': False,
            'share_backend_name': 'HDS_SOP',
            'vendor_name': 'Hitach Data Systems',
            'driver_version': '1.0',
            'storage_protocol': 'NFS',
            'reserved_percentage': 0,
            'QoS_support': False,
            'total_capacity_gb': 1234,
            'free_capacity_gb': 2345,
            'pools': None,
            'snapshot_support': True,
        }
        self.mock_object(self._driver, '_get_sop_filesystem_stats',
                         mock.Mock(return_value=(1234, 2345)))
        self._driver._update_share_stats()
        self.assertEqual(test_data, self._driver._stats)
        self._driver._get_sop_filesystem_stats.assert_called_once_with()

    def test_allow_access_rw(self):
        payload = {
            'action': 'add-access-rule',
            'all-squash': True,
            'anongid': 65534,
            'anonuid': 65534,
            'host-specification': '1.2.3.4',
            'description': '',
            'read-write': True,
            'root-squash': False,
            'tags': 'nfs',
            'name': 'fakeid-1.2.3.4'
        }

        self.mock_object(self._driver, '_get_share_id_by_name',
                         mock.Mock(return_value='fakeuuid'))
        self.mock_object(self._driver, '_wait_for_job_completion', mock.Mock())
        self.mock_object(httplib2.Http, 'request', mock.Mock(
            return_value=({'status': '202',
                           'content-length': '0',
                           'x-sopapi-version': '1.0.0',
                           'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;S'
                           'ecure',
                           'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                           'server': 'Jetty(8.1.3.v20120416)',
                           'location': 'https://1.2.3.4/sopapi/jobs/fakeuu'
                           'id',
                           'date': 'Wed, 21 Jan 2015 05:29:35 GMT'}, '')))

        access = {
            'access_type': 'ip',
            'access_to': '1.2.3.4',
            'access_level': 'rw',
        }
        self._driver.allow_access(
            self._context, self.share, access, share_server=self.server)

        headers = dict(Authorization=self._driver.get_sop_auth_header())

        httplib2.Http.request.assert_called_once_with(
            'https://1.2.3.4/sopapi/shares/fakeuuid', 'POST',
            body=json.dumps(payload),
            headers=headers)
        self._driver._get_share_id_by_name.assert_called_once_with(
            mock.ANY, 'fakeid')
        self._driver._wait_for_job_completion.assert_called_once_with(
            mock.ANY, 'https://' +
            self.server['backend_details']['ip'] +
            '/sopapi/jobs/fakeuuid')

    def test_allow_access_ro(self):
        payload = {
            'action': 'add-access-rule',
            'all-squash': True,
            'anongid': 65534,
            'anonuid': 65534,
            'host-specification': '1.2.3.4',
            'description': '',
            'read-write': False,
            'root-squash': False,
            'tags': 'nfs',
            'name': 'fakeid-1.2.3.4'
        }

        self.mock_object(self._driver, '_get_share_id_by_name',
                         mock.Mock(return_value='fakeuuid'))
        self.mock_object(self._driver, '_wait_for_job_completion', mock.Mock())
        self.mock_object(httplib2.Http, 'request', mock.Mock(
            return_value=({'status': '202',
                           'content-length': '0',
                           'x-sopapi-version': '1.0.0',
                           'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;S'
                           'ecure',
                           'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                           'server': 'Jetty(8.1.3.v20120416)',
                           'location': 'https://1.2.3.4/sopapi/jobs/fakeuu'
                           'id',
                           'date': 'Wed, 21 Jan 2015 05:29:35 GMT'}, '')))

        access = {
            'access_type': 'ip',
            'access_to': '1.2.3.4',
            'access_level': 'ro',
        }
        self._driver.allow_access(
            self._context, self.share, access, share_server=self.server)

        headers = dict(Authorization=self._driver.get_sop_auth_header())

        httplib2.Http.request.assert_called_once_with(
            'https://1.2.3.4/sopapi/shares/fakeuuid', 'POST',
            body=json.dumps(payload),
            headers=headers)
        self._driver._get_share_id_by_name.assert_called_once_with(
            mock.ANY, 'fakeid')
        self._driver._wait_for_job_completion.assert_called_once_with(
            mock.ANY, 'https://' +
            self.server['backend_details']['ip'] +
            '/sopapi/jobs/fakeuuid')

    def test_deny_access(self):
        payload = {
            'action': 'delete-access-rule',
            'name': 'fakeid-1.2.3.4',
        }

        self.mock_object(self._driver, '_get_share_id_by_name',
                         mock.Mock(return_value='fakeuuid'))
        self.mock_object(self._driver, '_wait_for_job_completion', mock.Mock())
        self.mock_object(httplib2.Http, 'request', mock.Mock(
            return_value=({'status': '202', 'content-length': '0',
                           'x-sopapi-version': '1.0.0',
                           'set-cookie': 'JSESSIONID=abcdef;Path=/sopapi;S'
                           'ecure',
                           'expires': 'Thu, 01 Jan 1970 00:00:00 GMT',
                           'server': 'Jetty(8.1.3.v20120416)',
                           'location': 'https://1.2.3.4/sopapi/jobs/fakeuuid',
                           'date': 'Wed, 21 Jan 2015 05:29:35 GMT'}, '')))

        access = {
            'access_type': 'ip',
            'access_to': '1.2.3.4',
            'access_level': 'rw',
        }
        self._driver.deny_access(
            self._context, self.share, access, share_server=self.server)

        headers = dict(Authorization=self._driver.get_sop_auth_header())

        httplib2.Http.request.assert_called_once_with(
            'https://1.2.3.4/sopapi/shares/fakeuuid', 'POST',
            body=json.dumps(payload),
            headers=headers)
        self._driver._get_share_id_by_name.assert_called_once_with(
            mock.ANY, 'fakeid')
        self._driver._wait_for_job_completion.assert_called_once_with(
            mock.ANY, 'https://' +
            self.server['backend_details']['ip'] +
            '/sopapi/jobs/fakeuuid')
