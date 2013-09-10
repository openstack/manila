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

