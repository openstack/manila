#   Copyright 2015 Mirantis inc.
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

from oslo_log import log
import six
import webob
from webob import exc

from manila.api.openstack import wsgi
from manila.common import constants
from manila import exception
from manila.i18n import _
from manila import share

LOG = log.getLogger(__name__)


class ShareUnmanageMixin(object):

    @wsgi.Controller.authorize("unmanage")
    def _unmanage(self, req, id, body=None):
        """Unmanage a share."""
        context = req.environ['manila.context']

        LOG.info("Unmanage share with id: %s", id, context=context)

        try:
            share = self.share_api.get(context, id)
            if share.get('has_replicas'):
                msg = _("Share %s has replicas. It cannot be unmanaged "
                        "until all replicas are removed.") % share['id']
                raise exc.HTTPConflict(explanation=msg)
            if share['instance'].get('share_server_id'):
                msg = _("Operation 'unmanage' is not supported for shares "
                        "that are created on top of share servers "
                        "(created with share-networks).")
                raise exc.HTTPForbidden(explanation=msg)
            elif share['status'] in constants.TRANSITIONAL_STATUSES:
                msg = _("Share with transitional state can not be unmanaged. "
                        "Share '%(s_id)s' is in '%(state)s' state.") % dict(
                            state=share['status'], s_id=share['id'])
                raise exc.HTTPForbidden(explanation=msg)
            snapshots = self.share_api.db.share_snapshot_get_all_for_share(
                context, id)
            if snapshots:
                msg = _("Share '%(s_id)s' can not be unmanaged because it has "
                        "'%(amount)s' dependent snapshot(s).") % {
                            's_id': id, 'amount': len(snapshots)}
                raise exc.HTTPForbidden(explanation=msg)
            self.share_api.unmanage(context, share)
        except exception.NotFound as e:
            raise exc.HTTPNotFound(explanation=six.text_type(e))
        except (exception.InvalidShare, exception.PolicyNotAuthorized) as e:
            raise exc.HTTPForbidden(explanation=six.text_type(e))

        return webob.Response(status_int=202)


class ShareUnmanageController(ShareUnmanageMixin, wsgi.Controller):
    """The Unmanage API controller for the OpenStack API."""

    resource_name = "share"

    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.share_api = share.API()

    @wsgi.Controller.api_version('1.0', '2.6')
    def unmanage(self, req, id):
        return self._unmanage(req, id)


def create_resource():
    return wsgi.Resource(ShareUnmanageController())
