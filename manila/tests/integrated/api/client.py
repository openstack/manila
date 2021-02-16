#    Copyright (c) 2011 Justin Santa Barbara
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

import netaddr
from urllib import parse

import requests

from oslo_log import log
from oslo_serialization import jsonutils

LOG = log.getLogger(__name__)


class OpenStackApiException(Exception):
    def __init__(self, message=None, response=None):
        self.response = response
        if not message:
            message = 'Unspecified error'

        if response:
            _status = response.status_code
            _body = response.text

            message = ('%(message)s\nStatus Code: %(_status)s\n'
                       'Body: %(_body)s') % {
                           "message": message,
                           "_status": _status,
                           "_body": _body
            }

        super(OpenStackApiException, self).__init__(message)


class OpenStackApiAuthenticationException(OpenStackApiException):
    def __init__(self, response=None, message=None):
        if not message:
            message = "Authentication error"
        super(OpenStackApiAuthenticationException, self).__init__(message,
                                                                  response)


class OpenStackApiAuthorizationException(OpenStackApiException):
    def __init__(self, response=None, message=None):
        if not message:
            message = "Authorization error"
        super(OpenStackApiAuthorizationException, self).__init__(message,
                                                                 response)


class OpenStackApiNotFoundException(OpenStackApiException):
    def __init__(self, response=None, message=None):
        if not message:
            message = "Item not found"
        super(OpenStackApiNotFoundException, self).__init__(message, response)


class TestOpenStackClient(object):
    """Simple OpenStack API Client.

    This is a really basic OpenStack API client that is under our control,
    so we can make changes / insert hooks for testing

    """

    def __init__(self, auth_user, auth_key, endpoint):
        super(TestOpenStackClient, self).__init__()
        self.auth_result = None
        self.auth_user = auth_user
        self.auth_key = auth_key
        self.endpoint = endpoint
        # default project_id
        self.project_id = 'openstack'

    def request(self, url, method='GET', body=None, headers=None,
                ssl_verify=True, stream=False):
        _headers = {'Content-Type': 'application/json'}
        _headers.update(headers or {})

        parsed_url = parse.urlparse(url)
        port = parsed_url.port or ''
        hostname = parsed_url.hostname
        if netaddr.valid_ipv6(hostname):
            hostname = "[%s]" % hostname
        scheme = parsed_url.scheme
        relative_url = parsed_url.path
        if parsed_url.query:
            relative_url = relative_url + "?" + parsed_url.query
        LOG.debug("Doing %(method)s on %(relative_url)s, body: %(body)s",
                  {"method": method, "relative_url": relative_url,
                   "body": body or {}})

        _url = "%s://%s:%s%s" % (scheme, hostname, port, relative_url)

        response = requests.request(method, _url, data=body, headers=_headers,
                                    verify=ssl_verify, stream=stream)
        return response

    def _authenticate(self):
        if self.auth_result:
            return self.auth_result

        headers = {'X-Auth-User': self.auth_user,
                   'X-Auth-Key': self.auth_key,
                   'X-Auth-Project-Id': self.project_id}
        response = self.request(self.endpoint,
                                headers=headers)

        http_status = response.status_code
        LOG.debug("%(endpoint)s => code %(http_status)s.",
                  {"endpoint": self.endpoint,
                   "http_status": http_status})

        if http_status == 401:
            raise OpenStackApiAuthenticationException(response=response)

        self.auth_result = response.headers
        return self.auth_result

    def api_request(self, relative_uri, check_response_status=None, **kwargs):
        auth_result = self._authenticate()

        base_uri = auth_result['x-server-management-url']

        full_uri = '%s/%s' % (base_uri, relative_uri)

        headers = kwargs.setdefault('headers', {})
        headers['X-Auth-Token'] = auth_result['x-auth-token']

        response = self.request(full_uri, **kwargs)

        http_status = response.status_code
        LOG.debug("%(relative_uri)s => code %(http_status)s.",
                  {"relative_uri": relative_uri, "http_status": http_status})

        if check_response_status:
            if http_status not in check_response_status:
                if http_status == 404:
                    raise OpenStackApiNotFoundException(response=response)
                elif http_status == 401:
                    raise OpenStackApiAuthorizationException(response=response)
                else:
                    raise OpenStackApiException(
                        message="Unexpected status code",
                        response=response)

        return response

    def _decode_json(self, response):
        body = response.text
        LOG.debug("Decoding JSON: %s.", (body))
        if body:
            return jsonutils.loads(body)
        else:
            return ""

    def api_options(self, relative_uri, **kwargs):
        kwargs['method'] = 'OPTIONS'
        kwargs.setdefault('check_response_status', [200])
        response = self.api_request(relative_uri, **kwargs)
        return self._decode_json(response)

    def api_get(self, relative_uri, **kwargs):
        kwargs.setdefault('check_response_status', [200])
        response = self.api_request(relative_uri, **kwargs)
        return self._decode_json(response)

    def api_post(self, relative_uri, body, **kwargs):
        kwargs['method'] = 'POST'
        if body:
            headers = kwargs.setdefault('headers', {})
            headers['Content-Type'] = 'application/json'
            kwargs['body'] = jsonutils.dumps(body)

        kwargs.setdefault('check_response_status', [200, 202])
        response = self.api_request(relative_uri, **kwargs)
        return self._decode_json(response)

    def api_put(self, relative_uri, body, **kwargs):
        kwargs['method'] = 'PUT'
        if body:
            headers = kwargs.setdefault('headers', {})
            headers['Content-Type'] = 'application/json'
            kwargs['body'] = jsonutils.dumps(body)

        kwargs.setdefault('check_response_status', [200, 202, 204])
        response = self.api_request(relative_uri, **kwargs)
        return self._decode_json(response)

    def api_delete(self, relative_uri, **kwargs):
        kwargs['method'] = 'DELETE'
        kwargs.setdefault('check_response_status', [200, 202, 204])
        return self.api_request(relative_uri, **kwargs)

    def get_shares(self, detail=True):
        rel_url = '/shares/detail' if detail else '/shares'
        return self.api_get(rel_url)['shares']
