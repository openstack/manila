# Copyright 2016 Nexenta Systems, Inc.
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
:mod:`nexenta.jsonrpc` -- Nexenta-specific JSON RPC client
=====================================================================

.. automodule:: nexenta.jsonrpc
"""

import base64
import json
import requests
from requests.packages.urllib3 import exceptions
import time

from oslo_log import log
from oslo_serialization import jsonutils

from manila import exception
from manila.i18n import _

LOG = log.getLogger(__name__)
requests.packages.urllib3.disable_warnings(exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(
    exceptions.InsecurePlatformWarning)
session = requests.Session()


class NexentaJSONProxy(object):
    def __init__(self, scheme, host, port, user,
                 password, method='get'):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.method = method

    @property
    def url(self):
        return '%s://%s:%s/' % (self.scheme, self.host, self.port)

    def __getattr__(self, method='get'):
        if method:
            return NexentaJSONProxy(
                self.scheme, self.host, self.port,
                self.user, self.password, method)

    def __hash__(self):
        return self.url.__hash__()

    def __repr__(self):
        return 'NEF proxy: %s' % self.url

    def __call__(self, path, data=None):
        auth = base64.b64encode(
            ('%s:%s' % (self.user, self.password)).encode('utf-8'))
        url = self.url + path

        if data:
            data = jsonutils.dumps(data)

        LOG.debug('Sending JSON to url: %s, data: %s, method: %s',
                  path, data, self.method)
        session.headers.update({'Content-Type': 'application/json'})

        response = getattr(session, self.method)(
            url, data=data, verify=False)
        if response.status_code in (401, 403):
            LOG.debug('Login requested by NexentaStor')
            if self.scheme == 'http':
                session.headers.update({'Authorization': 'Basic %s' % auth})
            else:
                session.headers.update(
                    {'Authorization': 'Bearer %s' % self.https_auth()})
            LOG.debug('Re-sending JSON to url: %s, data: %s, method: %s',
                      path, data, self.method)
            response = getattr(session, self.method)(
                url, data=data, verify=False)
        self.check_error(response)
        content = json.loads(response.content) if response.content else None
        LOG.debug("Got response: %(code)s %(reason)s %(content)s", {
            'code': response.status_code,
            'reason': response.reason,
            'content': content})
        response.close()

        if response.status_code == 202 and content:
            url = self.url + content['links'][0]['href']
            keep_going = True
            while keep_going:
                time.sleep(1)
                response = session.get(url, verify=False)
                self.check_error(response)
                LOG.debug("Got response: %(code)s %(reason)s", {
                    'code': response.status_code,
                    'reason': response.reason})
                content = json.loads(
                    response.content) if response.content else None
                keep_going = response.status_code == 202
                response.close()
        return content

    def https_auth(self):
        url = self.url + 'auth/login'
        data = jsonutils.dumps(
            {'username': self.user, 'password': self.password})
        response = session.post(
            url, data=data, verify=False)
        content = json.loads(response.content) if response.content else None
        LOG.debug("Got response: %(code)s %(reason)s %(content)s", {
            'code': response.status_code,
            'reason': response.reason,
            'content': content})
        response.close()
        return content['token']

    def check_error(self, response):
        code = response.status_code
        if code not in (200, 201, 202):
            reason = response.reason
            content = json.loads(
                response.content) if response.content else None
            response.close()
            if content and 'code' in content:
                message = content.get(
                    'message', 'Message is not specified by Nexenta REST')
                raise exception.NexentaException(
                    reason=message, code=content['code'])
            raise exception.NexentaException(
                reason=_(
                    'Got bad response: %(code)s %(reason)s %(content)s') % {
                        'code': code, 'reason': reason, 'content': content})
