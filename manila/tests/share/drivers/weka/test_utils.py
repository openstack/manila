# Copyright 2026 Weka.IO Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Unit tests for manila.share.drivers.weka.utils."""

from unittest import mock

from manila.share.drivers.weka import exceptions as weka_exc
from manila.share.drivers.weka import utils
from manila import test


class TestUnitConversion(test.TestCase):

    def test_gb_to_bytes(self):
        self.assertEqual(1073741824, utils.gb_to_bytes(1))
        self.assertEqual(10737418240, utils.gb_to_bytes(10))
        self.assertEqual(0, utils.gb_to_bytes(0))

    def test_bytes_to_gb(self):
        self.assertEqual(1.0, utils.bytes_to_gb(1073741824))
        self.assertEqual(10.0, utils.bytes_to_gb(10737418240))
        self.assertEqual(0.0, utils.bytes_to_gb(0))

    def test_roundtrip(self):
        for size_gb in [1, 5, 100, 1024]:
            self.assertAlmostEqual(
                size_gb,
                utils.bytes_to_gb(utils.gb_to_bytes(size_gb)),
                places=2,
            )


class TestSanitizeLogParams(test.TestCase):

    def test_hides_password(self):
        params = {'username': 'admin', 'password': 'secret'}
        result = utils.sanitize_log_params(params)
        self.assertEqual('admin', result['username'])
        self.assertEqual('***', result['password'])

    def test_hides_token(self):
        params = {'access_token': 'abc123', 'data': 'ok'}
        result = utils.sanitize_log_params(params)
        self.assertEqual('***', result['access_token'])
        self.assertEqual('ok', result['data'])

    def test_hides_secret(self):
        params = {'secret_key': 'shh'}
        result = utils.sanitize_log_params(params)
        self.assertEqual('***', result['secret_key'])

    def test_non_dict_passthrough(self):
        self.assertEqual('hello', utils.sanitize_log_params('hello'))
        self.assertIsNone(utils.sanitize_log_params(None))

    def test_empty_dict(self):
        self.assertEqual({}, utils.sanitize_log_params({}))


class TestRetryOnTransient(test.TestCase):

    def test_succeeds_on_first_try(self):
        func = mock.Mock(return_value='ok')
        decorated = utils.retry_on_transient(max_retries=3)(func)
        result = decorated()
        self.assertEqual('ok', result)
        func.assert_called_once()

    def test_retries_on_429_then_succeeds(self):
        func = mock.Mock(side_effect=[
            weka_exc.WekaRateLimited(reason='slow down'),
            weka_exc.WekaRateLimited(reason='slow down'),
            'ok',
        ])
        decorated = utils.retry_on_transient(
            max_retries=3, initial_delay=0.01)(func)
        with mock.patch('time.sleep'):
            result = decorated()
        self.assertEqual('ok', result)
        self.assertEqual(3, func.call_count)

    def test_exhausted_raises_last_exception(self):
        exc = weka_exc.WekaRateLimited(reason='too slow')
        func = mock.Mock(side_effect=exc)
        decorated = utils.retry_on_transient(
            max_retries=2, initial_delay=0.01)(func)
        with mock.patch('time.sleep'):
            self.assertRaises(weka_exc.WekaRateLimited, decorated)
        self.assertEqual(3, func.call_count)  # 1 initial + 2 retries

    def test_non_transient_not_retried(self):
        exc = weka_exc.WekaNotFound(reason='gone')
        func = mock.Mock(side_effect=exc)
        decorated = utils.retry_on_transient(max_retries=3)(func)
        self.assertRaises(weka_exc.WekaNotFound, decorated)
        func.assert_called_once()

    def test_backoff_increases_delay(self):
        func = mock.Mock(side_effect=[
            weka_exc.WekaApiError(status_code=503, reason='down'),
            'ok',
        ])
        decorated = utils.retry_on_transient(
            max_retries=2, initial_delay=1.0, backoff=3.0)(func)
        with mock.patch('time.sleep') as sleep:
            decorated()
        sleep.assert_called_once_with(1.0)

    def test_preserves_function_name(self):
        def my_func():
            pass
        decorated = utils.retry_on_transient()(my_func)
        self.assertEqual('my_func', decorated.__name__)
