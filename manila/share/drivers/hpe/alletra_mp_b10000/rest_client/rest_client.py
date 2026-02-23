# Copyright (c) 2025 Hewlett Packard Enterprise Development LP
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

import json
import requests

from oslo_log import log as logging
from oslo_utils import strutils

from manila import exception
from manila.i18n import _

LOG = logging.getLogger(__name__)


class HpeAlletraRestClient(object):

    def __init__(
            self,
            api_url,
            user,
            password,
            debug=False,
            secure=False,
            timeout=None,
            suppress_ssl_warnings=False):

        if suppress_ssl_warnings:
            requests.packages.urllib3.disable_warnings()

        self.api_url = api_url.rstrip('/')
        self.user = user
        self.password = password
        self.session_key = None
        self.debug = debug
        self.timeout = timeout
        self.secure = secure

    def authenticate(self, optional=None):
        self.session_key = None

        info = {'user': self.user, 'password': self.password}
        url = '/credentials'
        method = 'POST'
        resp, body = self.request(True, self.api_url + url, method, body=info)
        if body and 'key' in body:
            self.session_key = body['key']
            return True, resp.status
        return False, resp.status

    def _log_http_request(self, http_method, http_url, headers, payload):
        """Log HTTP request details when debug mode is enabled."""
        if self.debug:
            LOG.debug("HTTP Request - Method: %(method)s, URL: %(url)s, "
                      "Headers: %(headers)s, Payload: %(payload)s", {
                          'method': http_method,
                          'url': http_url,
                          'headers': headers,
                          'payload': strutils.mask_password(payload)})

    def _log_http_response(self, status, headers, body):
        """Log HTTP response details when debug mode is enabled."""
        if self.debug:
            LOG.debug("HTTP Response - Status: %(status)s, "
                      "Headers: %(headers)s, Body: %(body)s", {
                          'status': status,
                          'headers': dict(headers),
                          'body': strutils.mask_password(body)})

    def post(self, url, **kwargs):
        return self._api_request(False, url, 'POST', **kwargs)

    def delete(self, url, **kwargs):
        return self._api_request(False, url, 'DELETE', **kwargs)

    def get(self, url, **kwargs):
        return self._api_request(False, url, 'GET', **kwargs)

    def _api_request(self, auth_request, url, method, **kwargs):
        resp, body = self.request(auth_request, self.api_url + url, method,
                                  **kwargs)
        retry_count = 2
        while resp.status >= 400 and retry_count > 0:
            retry_count -= 1

            if resp.status == 401:
                # Reuthenticate if resp code indicates (401-Unauthorized)
                msg = _(
                    "Reauthenticating since backend request "
                    "%(method)s %(url)s failed with response "
                    "code %(status)s") % {
                    'method': method,
                    'url': url,
                    'status': resp.status}
                LOG.debug(msg)

                auth_success, auth_status = self.authenticate()
                if not auth_success:
                    break

                # Retry request
                resp, body = self.request(
                    auth_request, self.api_url + url, method, **kwargs)

        if resp.status >= 400:
            msg = _(
                "Backend request %(method)s %(url)s failed with response code "
                "%(status)s. Response body: %(body)s") % {
                'method': method,
                'url': url,
                'status': resp.status,
                'body': body}
            LOG.error(msg)
            raise exception.HPEAlletraB10000DriverException(reason=msg)

        return resp, body

    def request(self, auth_request, *args, **kwargs):

        # Include header for non-authentication requests
        kwargs.setdefault('headers', {})
        kwargs['headers']['Content-Type'] = 'application/json'
        if not auth_request:
            kwargs['headers']['Authorization'] = "Bearer " + self.session_key

        # Include payload as json str if required
        if 'body' in kwargs:
            kwargs['body'] = json.dumps(kwargs['body'])
            payload = kwargs['body']
        else:
            payload = None

        http_url = args[0]
        http_method = args[1]

        self._log_http_request(http_method, http_url, kwargs['headers'],
                               payload)

        # Make request
        if self.timeout:
            r = requests.request(http_method, http_url, data=payload,
                                 headers=kwargs['headers'],
                                 verify=self.secure,
                                 timeout=self.timeout)
        else:
            r = requests.request(http_method, http_url, data=payload,
                                 headers=kwargs['headers'],
                                 verify=self.secure)

        resp = r.headers
        resp['status'] = str(r.status_code)
        resp.status = r.status_code

        body = r.text
        if isinstance(body, bytes):
            body = body.decode('utf-8')

        r.close()
        if body:
            try:
                body = json.loads(body)
            except ValueError:
                pass
        else:
            body = None

        self._log_http_response(resp.status, resp, body)

        if resp.status >= 400:
            msg = _(
                "Backend request %(http_method)s %(http_url)s failed with "
                "response code %(status_code)s. Resp body %(resp_body)s") % {
                'http_method': http_method,
                'http_url': http_url,
                'status_code': resp.status,
                'resp_body': body}
            LOG.debug(msg)

        return resp, body
