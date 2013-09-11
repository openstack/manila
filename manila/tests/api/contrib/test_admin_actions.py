# vim: tabstop=4 shiftwidth=4 softtabstop=4

#   Copyright 2012 OpenStack LLC.
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import shutil
import tempfile
import webob

from manila import context
from manila import db
from manila import exception
from manila.openstack.common import jsonutils
from manila import test
from manila.tests.api import fakes
from manila.tests.api.v1 import stubs


def app():
    # no auth, just let environ['manila.context'] pass through
    api = fakes.router.APIRouter()
    mapper = fakes.urlmap.URLMap()
    mapper['/v2'] = api
    return mapper


class AdminActionsTest(test.TestCase):

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        super(AdminActionsTest, self).setUp()
        self.flags(rpc_backend='manila.openstack.common.rpc.impl_fake')
        self.flags(lock_path=self.tempdir)

    def tearDown(self):
        shutil.rmtree(self.tempdir)
