# Copyright (c) 2016 EMC Corporation.
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
import mock
import ssl

from manila.share.drivers.dell_emc.common.enas import utils
from manila import test


@ddt.ddt
class ENASUtilsTestCase(test.TestCase):

    @ddt.data({'full': ['cge-1-0', 'cge-1-1', 'cge-3-0',
                        'cge-3-1', 'cge-12-3'],
               'matchers': ['cge-?-0', 'cge-3*', 'foo'],
               'matched': set(['cge-1-0', 'cge-3-0',
                               'cge-3-1']),
               'unmatched': set(['cge-1-1', 'cge-12-3'])},
              {'full': ['cge-1-0', 'cge-1-1'],
               'matchers': ['cge-1-0'],
               'matched': set(['cge-1-0']),
               'unmatched': set(['cge-1-1'])},
              {'full': ['cge-1-0', 'cge-1-1'],
               'matchers': ['foo'],
               'matched': set([]),
               'unmatched': set(['cge-1-0', 'cge-1-1'])})
    @ddt.unpack
    def test_do_match_any(self, full, matchers, matched, unmatched):
        real_matched, real_unmatched = utils.do_match_any(
            full, matchers)
        self.assertEqual(matched, real_matched)
        self.assertEqual(unmatched, real_unmatched)


class SslContextTestCase(test.TestCase):

    def test_create_ssl_context(self):
        configuration = mock.Mock()
        configuration.emc_ssl_cert_verify = True
        configuration.emc_ssl_cert_path = "./cert_path/"
        self.mock_object(ssl, 'create_default_context')
        context = utils.create_ssl_context(configuration)
        self.assertIsNotNone(context)

    def test_create_ssl_context_no_verify(self):
        configuration = mock.Mock()
        configuration.emc_ssl_cert_verify = False
        self.mock_object(ssl, 'create_default_context')
        context = utils.create_ssl_context(configuration)
        self.assertFalse(context.check_hostname)

    def test_no_create_default_context(self):
        """Test scenario of running on python 2.7.8 or earlier."""
        configuration = mock.Mock()
        configuration.emc_ssl_cert_verify = False
        self.mock_object(ssl, 'create_default_context',
                         mock.Mock(side_effect=AttributeError))
        context = utils.create_ssl_context(configuration)
        self.assertIsNone(context)
