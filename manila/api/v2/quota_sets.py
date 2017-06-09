# Copyright 2011 OpenStack LLC.
# Copyright (c) 2015 Mirantis inc.
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

from oslo_log import log
from oslo_utils import strutils
from six.moves.urllib import parse
import webob

from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.views import quota_sets as quota_sets_views
from manila import db
from manila import exception
from manila.i18n import _
from manila import quota

QUOTAS = quota.QUOTAS
LOG = log.getLogger(__name__)
NON_QUOTA_KEYS = ('tenant_id', 'id', 'force', 'share_type')


class QuotaSetsMixin(object):
    """The Quota Sets API controller common logic.

    Mixin class that should be inherited by Quota Sets API controllers,
    which are used for different API URLs and microversions.
    """

    resource_name = "quota_set"
    _view_builder_class = quota_sets_views.ViewBuilder

    @staticmethod
    def _validate_quota_limit(limit, minimum, maximum, force_update):
        # NOTE: -1 is a flag value for unlimited
        if limit < -1:
            msg = _("Quota limit must be -1 or greater.")
            raise webob.exc.HTTPBadRequest(explanation=msg)
        if ((limit < minimum and not force_update) and
           (maximum != -1 or (maximum == -1 and limit != -1))):
            msg = _("Quota limit must be greater than %s.") % minimum
            raise webob.exc.HTTPBadRequest(explanation=msg)
        if maximum != -1 and limit > maximum and not force_update:
            msg = _("Quota limit must be less than %s.") % maximum
            raise webob.exc.HTTPBadRequest(explanation=msg)

    @staticmethod
    def _validate_user_id_and_share_type_args(user_id, share_type):
        if user_id and share_type:
            msg = _("'user_id' and 'share_type' values are mutually exclusive")
            raise webob.exc.HTTPBadRequest(explanation=msg)

    @staticmethod
    def _get_share_type_id(context, share_type_name_or_id):
        if share_type_name_or_id:
            share_type = db.share_type_get_by_name_or_id(
                context, share_type_name_or_id)
            if share_type:
                return share_type['id']
            msg = _("Share type with name or id '%s' not found.") % (
                share_type_name_or_id)
            raise webob.exc.HTTPNotFound(explanation=msg)

    @staticmethod
    def _ensure_share_type_arg_is_absent(req):
        params = parse.parse_qs(req.environ.get('QUERY_STRING', ''))
        share_type = params.get('share_type', [None])[0]
        if share_type:
            msg = _("'share_type' key is not supported by this microversion. "
                    "Use 2.39 or greater microversion to be able "
                    "to use 'share_type' quotas.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

    @staticmethod
    def _ensure_share_group_related_args_are_absent(body):
        body = body.get('quota_set', body)
        for key in ('share_groups', 'share_group_snapshots'):
            if body.get(key):
                msg = _("'%(key)s' key is not supported by this microversion. "
                        "Use 2.40 or greater microversion to be able "
                        "to use '%(key)s' quotas.") % {"key": key}
                raise webob.exc.HTTPBadRequest(explanation=msg)

    def _get_quotas(self, context, project_id, user_id=None,
                    share_type_id=None, usages=False):
        self._validate_user_id_and_share_type_args(user_id, share_type_id)
        if user_id:
            values = QUOTAS.get_user_quotas(
                context, project_id, user_id, usages=usages)
        elif share_type_id:
            values = QUOTAS.get_share_type_quotas(
                context, project_id, share_type_id, usages=usages)
        else:
            values = QUOTAS.get_project_quotas(
                context, project_id, usages=usages)
        if usages:
            return values
        return {k: v['limit'] for k, v in values.items()}

    @wsgi.Controller.authorize("show")
    def _show(self, req, id, detail=False):
        context = req.environ['manila.context']
        params = parse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]
        share_type = params.get('share_type', [None])[0]
        try:
            db.authorize_project_context(context, id)
            # _get_quotas use 'usages' to indicate whether retrieve additional
            # attributes, so pass detail to the argument.
            share_type_id = self._get_share_type_id(context, share_type)
            quotas = self._get_quotas(
                context, id, user_id, share_type_id, usages=detail)
            return self._view_builder.detail_list(
                req, quotas, id, share_type_id)
        except exception.NotAuthorized:
            raise webob.exc.HTTPForbidden()

    @wsgi.Controller.authorize('show')
    def _defaults(self, req, id):
        context = req.environ['manila.context']
        return self._view_builder.detail_list(
            req, QUOTAS.get_defaults(context), id)

    @wsgi.Controller.authorize("update")
    def _update(self, req, id, body):
        context = req.environ['manila.context']
        project_id = id
        bad_keys = []
        force_update = False
        params = parse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]
        share_type = params.get('share_type', [None])[0]
        self._validate_user_id_and_share_type_args(user_id, share_type)
        share_type_id = self._get_share_type_id(context, share_type)
        body = body.get('quota_set', {})
        if share_type and body.get('share_groups',
                                   body.get('share_group_snapshots')):
            msg = _("Share type quotas handle only 'shares', 'gigabytes', "
                    "'snapshots' and 'snapshot_gigabytes' quotas.")
            raise webob.exc.HTTPBadRequest(explanation=msg)

        try:
            settable_quotas = QUOTAS.get_settable_quotas(
                context, project_id, user_id=user_id,
                share_type_id=share_type_id)
        except exception.NotAuthorized:
            raise webob.exc.HTTPForbidden()

        for key, value in body.items():
            if key == 'share_networks' and share_type_id:
                msg = _("'share_networks' quota cannot be set for share type. "
                        "It can be set only for project or user.")
                raise webob.exc.HTTPBadRequest(explanation=msg)
            elif (key not in QUOTAS and key not in NON_QUOTA_KEYS):
                bad_keys.append(key)
            elif key == 'force':
                force_update = strutils.bool_from_string(value)
            elif key not in NON_QUOTA_KEYS and value:
                try:
                    value = int(value)
                except (ValueError, TypeError):
                    msg = _("Quota '%(value)s' for %(key)s should be "
                            "integer.") % {'value': value, 'key': key}
                    LOG.warning(msg)
                    raise webob.exc.HTTPBadRequest(explanation=msg)

        LOG.debug("Force update quotas: %s.", force_update)

        if len(bad_keys) > 0:
            msg = _("Bad key(s) %s in quota_set.") % ",".join(bad_keys)
            raise webob.exc.HTTPBadRequest(explanation=msg)

        try:
            quotas = self._get_quotas(
                context, id, user_id=user_id, share_type_id=share_type_id,
                usages=True)
        except exception.NotAuthorized:
            raise webob.exc.HTTPForbidden()

        for key, value in body.items():
            if key in NON_QUOTA_KEYS or (not value and value != 0):
                continue
            # validate whether already used and reserved exceeds the new
            # quota, this check will be ignored if admin want to force
            # update
            try:
                value = int(value)
            except (ValueError, TypeError):
                msg = _("Quota '%(value)s' for %(key)s should be "
                        "integer.") % {'value': value, 'key': key}
                LOG.warning(msg)
                raise webob.exc.HTTPBadRequest(explanation=msg)

            if force_update is False and value >= 0:
                quota_value = quotas.get(key)
                if quota_value and quota_value['limit'] >= 0:
                    quota_used = (quota_value['in_use'] +
                                  quota_value['reserved'])
                    LOG.debug("Quota %(key)s used: %(quota_used)s, "
                              "value: %(value)s.",
                              {'key': key, 'quota_used': quota_used,
                               'value': value})
                    if quota_used > value:
                        msg = (_("Quota value %(value)s for %(key)s are "
                                 "greater than already used and reserved "
                                 "%(quota_used)s.") %
                               {'value': value, 'key': key,
                                'quota_used': quota_used})
                        raise webob.exc.HTTPBadRequest(explanation=msg)

            minimum = settable_quotas[key]['minimum']
            maximum = settable_quotas[key]['maximum']
            self._validate_quota_limit(value, minimum, maximum, force_update)
            try:
                db.quota_create(
                    context, project_id, key, value,
                    user_id=user_id, share_type_id=share_type_id)
            except exception.QuotaExists:
                db.quota_update(
                    context, project_id, key, value,
                    user_id=user_id, share_type_id=share_type_id)
            except exception.AdminRequired:
                raise webob.exc.HTTPForbidden()
        return self._view_builder.detail_list(
            req,
            self._get_quotas(
                context, id, user_id=user_id, share_type_id=share_type_id),
            share_type=share_type_id,
        )

    @wsgi.Controller.authorize("delete")
    def _delete(self, req, id):
        context = req.environ['manila.context']
        params = parse.parse_qs(req.environ.get('QUERY_STRING', ''))
        user_id = params.get('user_id', [None])[0]
        share_type = params.get('share_type', [None])[0]
        self._validate_user_id_and_share_type_args(user_id, share_type)
        try:
            db.authorize_project_context(context, id)
            if user_id:
                QUOTAS.destroy_all_by_project_and_user(context, id, user_id)
            elif share_type:
                share_type_id = self._get_share_type_id(context, share_type)
                QUOTAS.destroy_all_by_project_and_share_type(
                    context, id, share_type_id)
            else:
                QUOTAS.destroy_all_by_project(context, id)
            return webob.Response(status_int=202)
        except exception.NotAuthorized:
            raise webob.exc.HTTPForbidden()


class QuotaSetsControllerLegacy(QuotaSetsMixin, wsgi.Controller):
    """Deprecated Quota Sets API controller.

    Used by legacy API v1 and v2 microversions from 2.0 to 2.6.
    Registered under deprecated API URL 'os-quota-sets'.
    """

    @wsgi.Controller.api_version('1.0', '2.6')
    def show(self, req, id):
        self._ensure_share_type_arg_is_absent(req)
        return self._show(req, id)

    @wsgi.Controller.api_version('1.0', '2.6')
    def defaults(self, req, id):
        return self._defaults(req, id)

    @wsgi.Controller.api_version('1.0', '2.6')
    def update(self, req, id, body):
        self._ensure_share_type_arg_is_absent(req)
        self._ensure_share_group_related_args_are_absent(body)
        return self._update(req, id, body)

    @wsgi.Controller.api_version('1.0', '2.6')
    def delete(self, req, id):
        self._ensure_share_type_arg_is_absent(req)
        return self._delete(req, id)


class QuotaSetsController(QuotaSetsMixin, wsgi.Controller):
    """Quota Sets API controller.

    Used only by API v2 starting from microversion 2.7.
    Registered under API URL 'quota-sets'.
    """

    @wsgi.Controller.api_version('2.7')
    def show(self, req, id):
        if req.api_version_request < api_version.APIVersionRequest("2.39"):
            self._ensure_share_type_arg_is_absent(req)
        return self._show(req, id)

    @wsgi.Controller.api_version('2.25')
    def detail(self, req, id):
        if req.api_version_request < api_version.APIVersionRequest("2.39"):
            self._ensure_share_type_arg_is_absent(req)
        return self._show(req, id, True)

    @wsgi.Controller.api_version('2.7')
    def defaults(self, req, id):
        return self._defaults(req, id)

    @wsgi.Controller.api_version('2.7')
    def update(self, req, id, body):
        if req.api_version_request < api_version.APIVersionRequest("2.39"):
            self._ensure_share_type_arg_is_absent(req)
        elif req.api_version_request < api_version.APIVersionRequest("2.40"):
            self._ensure_share_group_related_args_are_absent(body)
        return self._update(req, id, body)

    @wsgi.Controller.api_version('2.7')
    def delete(self, req, id):
        if req.api_version_request < api_version.APIVersionRequest("2.39"):
            self._ensure_share_type_arg_is_absent(req)
        return self._delete(req, id)


def create_resource_legacy():
    return wsgi.Resource(QuotaSetsControllerLegacy())


def create_resource():
    return wsgi.Resource(QuotaSetsController())
