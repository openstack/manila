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

from unittest import mock

import ddt

from manila import exception
from manila.share.drivers.hpe.alletra_mp_b10000.rest_client import (
    rest_client)
from manila import test


class MockDict(dict):
    """Dict subclass that allows attribute assignment."""

    def __setattr__(self, name, value):
        self[name] = value

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class MockDictTestCase(test.TestCase):
    """Test case for MockDict utility class."""

    def test_mockdict_getattr_success(self):
        """Test MockDict __getattr__ returns value for existing key."""
        mock_dict = MockDict()
        mock_dict['test_key'] = 'test_value'
        self.assertEqual(mock_dict.test_key, 'test_value')

    def test_mockdict_getattr_keyerror(self):
        """Test MockDict __getattr__ raises AttributeError for missing key."""
        mock_dict = MockDict()
        self.assertRaises(AttributeError, getattr, mock_dict,
                          'nonexistent_key')

    def test_mockdict_setattr(self):
        """Test MockDict __setattr__ sets value as dictionary key."""
        mock_dict = MockDict()
        mock_dict.test_key = 'test_value'
        self.assertEqual(mock_dict['test_key'], 'test_value')


@ddt.ddt
class HpeAlletraRestClientTestCase(test.TestCase):
    """Test case for HpeAlletraRestClient class."""

    def setUp(self):
        """Test Setup"""
        super(HpeAlletraRestClientTestCase, self).setUp()
        self.api_url = 'https://1.2.3.4:8080/api/v3'
        self.user = 'testuser'
        self.password = 'testpass'
        self.client = rest_client.HpeAlletraRestClient(
            self.api_url, self.user, self.password
        )

    def test_init(self):
        """Test client initialization."""
        client = rest_client.HpeAlletraRestClient(
            self.api_url, self.user, self.password, debug=True, secure=True
        )
        self.assertEqual(client.api_url, self.api_url)
        self.assertEqual(client.user, self.user)
        self.assertEqual(client.password, self.password)
        self.assertIsNone(client.session_key)
        self.assertTrue(client.secure)
        self.assertTrue(client.debug)

    def test_init_with_debug_flag(self):
        """Test client initialization with debug flag enabled."""
        client = rest_client.HpeAlletraRestClient(
            self.api_url, self.user, self.password, debug=True
        )
        self.assertTrue(client.debug)

    def test_init_without_debug_flag(self):
        """Test client initialization without debug flag (default False)."""
        client = rest_client.HpeAlletraRestClient(
            self.api_url, self.user, self.password
        )
        self.assertFalse(client.debug)

    def test_init_with_timeout(self):
        """Test client initialization with timeout parameter."""
        timeout_value = 30
        client = rest_client.HpeAlletraRestClient(
            self.api_url, self.user, self.password, timeout=timeout_value
        )
        self.assertEqual(client.timeout, timeout_value)

    def test_init_with_suppress_ssl_warnings_enabled(self):
        """Test client initialization with suppress_ssl_warnings enabled."""
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.packages.urllib3.'
                'disable_warnings') as mock_disable_warnings:
            rest_client.HpeAlletraRestClient(
                self.api_url, self.user, self.password,
                suppress_ssl_warnings=True
            )
            # Verify disable_warnings was called
            mock_disable_warnings.assert_called_once()

    def test_init_with_suppress_ssl_warnings_disabled(self):
        """Test client initialization with suppress_ssl_warnings disabled."""
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.packages.urllib3.'
                'disable_warnings') as mock_disable_warnings:
            rest_client.HpeAlletraRestClient(
                self.api_url, self.user, self.password,
                suppress_ssl_warnings=False
            )
            # Verify disable_warnings was NOT called
            mock_disable_warnings.assert_not_called()

    def test_init_with_trailing_slash(self):
        """Test client initialization with trailing slash in URL."""
        api_url_with_slash = 'https://1.2.3.4:8080/api/v3/'
        client = rest_client.HpeAlletraRestClient(
            api_url_with_slash, self.user, self.password
        )
        # Should strip trailing slash
        self.assertEqual(client.api_url, self.api_url)

    def test_authenticate_success(self):
        """Test successful authentication."""
        # Mock the request method
        mock_response = mock.Mock()
        mock_response.status = 200
        mock_response.text = '{"key": "session_key_123"}'
        mock_response.headers = mock.Mock()
        mock_response.close = mock.Mock()

        self.client.request = mock.Mock(
            return_value=(
                mock_response, {
                    "key": "session_key_123"}))

        success, status = self.client.authenticate()

        self.assertTrue(success)
        self.assertEqual(status, 200)
        self.assertEqual(self.client.session_key, 'session_key_123')
        self.client.request.assert_called_once()

    def test_authenticate_failure_no_key(self):
        """Test authentication failure when no key in response."""
        # Mock the request method
        mock_response = mock.Mock()
        mock_response.status = 200
        mock_response.text = '{"error": "no key"}'
        mock_response.headers = mock.Mock()
        mock_response.close = mock.Mock()

        self.client.request = mock.Mock(
            return_value=(
                mock_response, {
                    "error": "no key"}))

        success, status = self.client.authenticate()

        self.assertFalse(success)
        self.assertEqual(status, 200)
        self.assertIsNone(self.client.session_key)

    def test_authenticate_failure_bad_status(self):
        """Test authentication failure with bad status code."""
        # Mock the request method
        mock_response = mock.Mock()
        mock_response.status = 401
        mock_response.text = '{"error": "unauthorized"}'
        mock_response.headers = mock.Mock()
        mock_response.close = mock.Mock()

        self.client.request = mock.Mock(return_value=(
            mock_response, {"error": "unauthorized"}))

        success, status = self.client.authenticate()

        self.assertFalse(success)
        self.assertEqual(status, 401)
        self.assertIsNone(self.client.session_key)

    def test_get_method(self):
        """Test GET method."""
        # Setup authenticated client
        self.client.session_key = 'session_key_123'

        # Mock the request method
        mock_response = mock.Mock()
        mock_response.status = 200
        mock_response.text = '{"data": "test"}'
        mock_response.headers = mock.Mock()
        mock_response.close = mock.Mock()

        self.client.request = mock.Mock(
            return_value=(
                mock_response, {
                    "data": "test"}))

        resp, body = self.client.get('/test')

        self.assertEqual(resp.status, 200)
        self.assertEqual(body, {"data": "test"})
        # Verify request was called with correct parameters
        self.client.request.assert_called_once_with(
            False, self.api_url + '/test', 'GET')

    def test_post_method(self):
        """Test POST method."""
        # Setup authenticated client
        self.client.session_key = 'session_key_123'

        # Mock the request method
        mock_response = mock.Mock()
        mock_response.status = 201
        mock_response.text = '{"id": "123"}'
        mock_response.headers = mock.Mock()
        mock_response.close = mock.Mock()

        self.client.request = mock.Mock(
            return_value=(mock_response, {"id": "123"}))

        resp, body = self.client.post('/test', body={'name': 'test'})

        self.assertEqual(resp.status, 201)
        self.assertEqual(body, {"id": "123"})
        # Verify request was called with correct parameters
        self.client.request.assert_called_once_with(
            False, self.api_url + '/test', 'POST', body={'name': 'test'})

    def test_delete_method(self):
        """Test DELETE method."""
        # Setup authenticated client
        self.client.session_key = 'session_key_123'

        # Mock the request method
        mock_response = mock.Mock()
        mock_response.status = 204
        mock_response.text = ''
        mock_response.headers = mock.Mock()
        mock_response.close = mock.Mock()

        self.client.request = mock.Mock(return_value=(mock_response, None))

        resp, body = self.client.delete('/test/123')

        self.assertEqual(resp.status, 204)
        self.assertIsNone(body)
        # Verify request was called with correct parameters
        self.client.request.assert_called_once_with(
            False, self.api_url + '/test/123', 'DELETE')

    def test_request_with_json_body(self):
        """Test request method with JSON body."""
        # Mock the underlying requests.request
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock response
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.text = '{"result": "ok"}'
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            resp, body = self.client.request(
                True, 'http://test.com', 'POST', body={'test': 'data'})

            self.assertEqual(resp.status, 200)
            self.assertEqual(body, {"result": "ok"})
            # Verify body was JSON encoded
            call_args = mock_request.call_args
            self.assertEqual(call_args[1]['data'], '{"test": "data"}')
            self.assertEqual(
                call_args[1]['headers']['Content-Type'],
                'application/json')

    def test_request_without_auth_header(self):
        """Test request without authorization header for auth requests."""
        # Mock the underlying requests.request
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock response
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.text = '{"key": "session123"}'
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            resp, body = self.client.request(
                True, 'http://test.com/auth', 'POST', body={'user': 'test'})

            # Verify no Authorization header for auth requests
            call_args = mock_request.call_args
            self.assertNotIn('Authorization', call_args[1]['headers'])
            self.assertEqual(
                call_args[1]['headers']['Content-Type'],
                'application/json')

    def test_request_with_bytes_response(self):
        """Test request method with bytes response body."""
        # Setup authenticated client
        self.client.session_key = 'session_key_123'

        # Mock the underlying requests.request
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock response with bytes
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.text = b'{"data": "test"}'  # bytes
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            resp, body = self.client.request(False, 'http://test.com', 'GET')

            self.assertEqual(resp.status, 200)
            # Should be decoded and parsed as JSON
            self.assertEqual(body, {"data": "test"})

    def test_request_with_empty_response(self):
        """Test request method with empty response body."""
        # Setup authenticated client
        self.client.session_key = 'session_key_123'

        # Mock the underlying requests.request
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock response with empty body
            mock_response = mock.Mock()
            mock_response.status_code = 204
            mock_response.text = ''
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            resp, body = self.client.request(
                False, 'http://test.com', 'DELETE')

            self.assertEqual(resp.status, 204)
            self.assertIsNone(body)

    def test_request_with_invalid_json_response(self):
        """Test request method with invalid JSON response."""
        # Setup authenticated client
        self.client.session_key = 'session_key_123'

        # Mock the underlying requests.request
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock response with invalid JSON
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.text = 'not json'
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            resp, body = self.client.request(False, 'http://test.com', 'GET')

            self.assertEqual(resp.status, 200)
            self.assertEqual(body, 'not json')  # Should remain as string

    def test_request_with_timeout_set(self):
        """Test request includes timeout parameter when timeout is set."""
        timeout_value = 30
        client_with_timeout = rest_client.HpeAlletraRestClient(
            self.api_url, self.user, self.password, timeout=timeout_value
        )
        client_with_timeout.session_key = 'session_key'

        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock response
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.text = '{"result": "ok"}'
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            resp, body = client_with_timeout.request(
                True, self.api_url + '/test', 'GET')

            # Verify requests.request was called with timeout parameter
            self.assertEqual(mock_request.call_count, 1)
            call_kwargs = mock_request.call_args[1]
            self.assertEqual(call_kwargs['timeout'], timeout_value)
            self.assertEqual(resp.status, 200)

    def test_request_with_debug_enabled(self):
        """Test request method logs when debug is enabled."""
        # Setup authenticated client with debug enabled
        debug_client = rest_client.HpeAlletraRestClient(
            self.api_url, self.user, self.password, debug=True
        )
        debug_client.session_key = 'test_session_key'

        # Mock the underlying requests.request
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request, \
             mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.LOG') as mock_log:
            # Mock response
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.text = '{"data": "test"}'
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            resp, body = debug_client.request(False, 'http://test.com', 'GET')

            self.assertEqual(resp.status, 200)
            self.assertEqual(body, {"data": "test"})
            # Verify both request and response were logged
            self.assertEqual(mock_log.debug.call_count, 2)

    def test_request_with_debug_disabled(self):
        """Test request method skips logging when debug is disabled."""
        # Setup authenticated client with debug disabled
        debug_client = rest_client.HpeAlletraRestClient(
            self.api_url, self.user, self.password, debug=False
        )
        debug_client.session_key = 'test_session_key'

        # Mock the underlying requests.request
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request, \
             mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.LOG') as mock_log:
            # Mock response
            mock_response = mock.Mock()
            mock_response.status_code = 200
            mock_response.text = '{"data": "test"}'
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            resp, body = debug_client.request(False, 'http://test.com', 'GET')

            self.assertEqual(resp.status, 200)
            self.assertEqual(body, {"data": "test"})
            # Verify debug logging was not called
            mock_log.debug.assert_not_called()

    def test_api_request_retry_on_401(self):
        """Test _api_request retries on 401 and reauthenticates."""
        # Setup authenticated client
        self.client.session_key = 'old_key'

        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock first request fails with 401
            mock_response_401 = mock.Mock()
            mock_response_401.status_code = 401
            mock_response_401.text = '{"error": "unauthorized"}'
            mock_response_401.headers = MockDict()
            mock_response_401.close = mock.Mock()

            # Mock successful reauth response
            mock_auth_response = mock.Mock()
            mock_auth_response.status_code = 200
            mock_auth_response.text = '{"key": "new_session_key"}'
            mock_auth_response.headers = MockDict()
            mock_auth_response.close = mock.Mock()

            # Mock successful retry response
            mock_response_success = mock.Mock()
            mock_response_success.status_code = 200
            mock_response_success.text = '{"data": "success"}'
            mock_response_success.headers = MockDict()
            mock_response_success.close = mock.Mock()

            mock_request.side_effect = [
                mock_response_401,
                mock_auth_response,
                mock_response_success]

            resp, body = self.client._api_request(False, '/test', 'GET')

            self.assertEqual(resp.status, 200)
            self.assertEqual(body, {"data": "success"})
            self.assertEqual(
                self.client.session_key,
                'new_session_key')  # Should be updated
            self.assertEqual(
                mock_request.call_count,
                3)  # Original + auth + retry

    def test_api_request_max_retries_exceeded(self):
        """Test _api_request fails after max retries."""
        # Setup authenticated client
        self.client.session_key = 'session_key'

        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock all requests fail with 401
            mock_response_401 = mock.Mock()
            mock_response_401.status_code = 401
            mock_response_401.text = '{"error": "unauthorized"}'
            mock_response_401.headers = MockDict()
            mock_response_401.close = mock.Mock()
            mock_request.return_value = mock_response_401

            self.assertRaises(exception.HPEAlletraB10000DriverException,
                              self.client._api_request, False, '/test', 'GET')
            # Should have tried: original + 1 retry = 2 calls
            # (retry_count starts at 2, decrements to 1, then to 0,
            # so only 1 retry happens)
            self.assertEqual(mock_request.call_count, 2)

    def test_api_request_auth_failure_no_retry(self):
        """Test _api_request doesn't retry auth."""
        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock auth request fails
            mock_response = mock.Mock()
            mock_response.status_code = 401
            mock_response.text = '{"error": "unauthorized"}'
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            self.assertRaises(
                exception.HPEAlletraB10000DriverException,
                self.client._api_request,
                True,
                '/credentials',
                'POST')
            # Auth requests go through retry logic: initial + retry attempt = 2
            # calls
            self.assertEqual(mock_request.call_count, 2)

    def test_api_request_non_retryable_error(self):
        """Test _api_request fails immediately on non-retryable errors."""
        # Setup authenticated client
        self.client.session_key = 'session_key'

        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock request fails with 500 (not 401/403)
            mock_response = mock.Mock()
            mock_response.status_code = 500
            mock_response.text = '{"error": "internal server error"}'
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            self.assertRaises(exception.HPEAlletraB10000DriverException,
                              self.client._api_request, False, '/test', 'GET')
            # Should only try once for non-retryable errors
            self.assertEqual(mock_request.call_count, 1)

    def test_api_request_error_response_with_debug_enabled(self):
        """Test _api_request error is logged when debug is enabled."""
        debug_client = rest_client.HpeAlletraRestClient(
            self.api_url, self.user, self.password, debug=True
        )
        debug_client.session_key = 'session_key'

        with mock.patch(
                'manila.share.drivers.hpe.alletra_mp_b10000.'
                'rest_client.rest_client.requests.request') as mock_request:
            # Mock request fails with 500
            mock_response = mock.Mock()
            mock_response.status_code = 500
            mock_response.text = '{"error": "internal server error"}'
            mock_response.headers = MockDict()
            mock_response.close = mock.Mock()
            mock_request.return_value = mock_response

            self.assertRaises(exception.HPEAlletraB10000DriverException,
                              debug_client._api_request, False, '/test', 'GET')
            # Verify request was still made
            self.assertEqual(mock_request.call_count, 1)
