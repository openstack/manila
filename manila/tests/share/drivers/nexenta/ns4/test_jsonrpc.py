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

from mock import patch
from oslo_serialization import jsonutils
import requests

from manila import exception
from manila.share.drivers.nexenta.ns4 import jsonrpc
from manila import test


class TestNexentaJSONProxy(test.TestCase):

    @patch('requests.post')
    def test_call(self, post):
        nms_post = jsonrpc.NexentaJSONProxy(
            'http', '1.1.1.1', '8080', 'user', 'pass',
            'obj', auto=False, method='get')
        data = {'error': {'message': 'some_error'}}

        post.return_value = requests.Response()
        post.return_value.__setstate__({
            'status_code': 500, '_content': jsonutils.dumps(data)})

        self.assertRaises(exception.NexentaException, nms_post)
