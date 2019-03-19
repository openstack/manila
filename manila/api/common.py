# Copyright 2010 OpenStack LLC.
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

import ipaddress
import os
import re
import six
import string

from oslo_config import cfg
from oslo_log import log
from oslo_utils import encodeutils
from six.moves.urllib import parse
import webob

from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import versioned_method
from manila.i18n import _

api_common_opts = [
    cfg.IntOpt(
        'osapi_max_limit',
        default=1000,
        help='The maximum number of items returned in a single response from '
             'a collection resource.'),
    cfg.StrOpt(
        'osapi_share_base_URL',
        help='Base URL to be presented to users in links to the Share API'),
]

CONF = cfg.CONF
CONF.register_opts(api_common_opts)
LOG = log.getLogger(__name__)


# Regex that matches alphanumeric characters, periods, hypens,
# colons and underscores:
# ^ assert position at start of the string
# [\w\.\-\:\_] match expression
# $ assert position at end of the string
VALID_KEY_NAME_REGEX = re.compile(r"^[\w\.\-\:\_]+$", re.UNICODE)


def validate_key_names(key_names_list):
    """Validate each item of the list to match key name regex."""
    for key_name in key_names_list:
        if not VALID_KEY_NAME_REGEX.match(key_name):
            return False
    return True


def get_pagination_params(request):
    """Return marker, limit tuple from request.

    :param request: `wsgi.Request` possibly containing 'marker' and 'limit'
                    GET variables. 'marker' is the id of the last element
                    the client has seen, and 'limit' is the maximum number
                    of items to return. If 'limit' is not specified, 0, or
                    > max_limit, we default to max_limit. Negative values
                    for either marker or limit will cause
                    exc.HTTPBadRequest() exceptions to be raised.

    """
    params = {}
    if 'limit' in request.GET:
        params['limit'] = _get_limit_param(request)
    if 'marker' in request.GET:
        params['marker'] = _get_marker_param(request)
    return params


def _get_limit_param(request):
    """Extract integer limit from request or fail."""
    try:
        limit = int(request.GET['limit'])
    except ValueError:
        msg = _('limit param must be an integer')
        raise webob.exc.HTTPBadRequest(explanation=msg)
    if limit < 0:
        msg = _('limit param must be positive')
        raise webob.exc.HTTPBadRequest(explanation=msg)
    return limit


def _get_marker_param(request):
    """Extract marker ID from request or fail."""
    return request.GET['marker']


def limited(items, request, max_limit=CONF.osapi_max_limit):
    """Return a slice of items according to requested offset and limit.

    :param items: A sliceable entity
    :param request: ``wsgi.Request`` possibly containing 'offset' and 'limit'
                    GET variables. 'offset' is where to start in the list,
                    and 'limit' is the maximum number of items to return. If
                    'limit' is not specified, 0, or > max_limit, we default
                    to max_limit. Negative values for either offset or limit
                    will cause exc.HTTPBadRequest() exceptions to be raised.
    :kwarg max_limit: The maximum number of items to return from 'items'
    """
    try:
        offset = int(request.GET.get('offset', 0))
    except ValueError:
        msg = _('offset param must be an integer')
        raise webob.exc.HTTPBadRequest(explanation=msg)

    try:
        limit = int(request.GET.get('limit', max_limit))
    except ValueError:
        msg = _('limit param must be an integer')
        raise webob.exc.HTTPBadRequest(explanation=msg)

    if limit < 0:
        msg = _('limit param must be positive')
        raise webob.exc.HTTPBadRequest(explanation=msg)

    if offset < 0:
        msg = _('offset param must be positive')
        raise webob.exc.HTTPBadRequest(explanation=msg)

    limit = min(max_limit, limit or max_limit)
    range_end = offset + limit
    return items[offset:range_end]


def remove_version_from_href(href):
    """Removes the first api version from the href.

    Given: 'http://manila.example.com/v1.1/123'
    Returns: 'http://manila.example.com/123'

    Given: 'http://www.manila.com/v1.1'
    Returns: 'http://www.manila.com'

    Given: 'http://manila.example.com/share/v1.1/123'
    Returns: 'http://manila.example.com/share/123'

    """
    parsed_url = parse.urlsplit(href)
    url_parts = parsed_url.path.split('/')

    # NOTE: this should match vX.X or vX
    expression = re.compile(r'^v([0-9]+|[0-9]+\.[0-9]+)(/.*|$)')
    for x in range(len(url_parts)):
        if expression.match(url_parts[x]):
            del url_parts[x]
            break

    new_path = '/'.join(url_parts)

    if new_path == parsed_url.path:
        msg = 'href %s does not contain version' % href
        LOG.debug(msg)
        raise ValueError(msg)

    parsed_url = list(parsed_url)
    parsed_url[2] = new_path
    return parse.urlunsplit(parsed_url)


def dict_to_query_str(params):
    # TODO(throughnothing): we should just use urllib.urlencode instead of this
    # But currently we don't work with urlencoded url's
    param_str = ""
    for key, val in params.items():
        param_str = param_str + '='.join([str(key), str(val)]) + '&'

    return param_str.rstrip('&')


class ViewBuilder(object):
    """Model API responses as dictionaries."""

    _collection_name = None
    _detail_version_modifiers = []

    def _get_links(self, request, identifier):
        return [{"rel": "self",
                 "href": self._get_href_link(request, identifier), },
                {"rel": "bookmark",
                 "href": self._get_bookmark_link(request, identifier), }]

    def _get_next_link(self, request, identifier):
        """Return href string with proper limit and marker params."""
        params = request.params.copy()
        params["marker"] = identifier
        prefix = self._update_link_prefix(request.application_url,
                                          CONF.osapi_share_base_URL)
        url = os.path.join(prefix,
                           request.environ["manila.context"].project_id,
                           self._collection_name)
        return "%s?%s" % (url, dict_to_query_str(params))

    def _get_href_link(self, request, identifier):
        """Return an href string pointing to this object."""
        prefix = self._update_link_prefix(request.application_url,
                                          CONF.osapi_share_base_URL)
        return os.path.join(prefix,
                            request.environ["manila.context"].project_id,
                            self._collection_name,
                            str(identifier))

    def _get_bookmark_link(self, request, identifier):
        """Create a URL that refers to a specific resource."""
        base_url = remove_version_from_href(request.application_url)
        base_url = self._update_link_prefix(base_url,
                                            CONF.osapi_share_base_URL)
        return os.path.join(base_url,
                            request.environ["manila.context"].project_id,
                            self._collection_name,
                            str(identifier))

    def _get_collection_links(self, request, items, id_key="uuid"):
        """Retrieve 'next' link, if applicable."""
        links = []
        limit = int(request.params.get("limit", 0))
        if limit and limit == len(items):
            last_item = items[-1]
            if id_key in last_item:
                last_item_id = last_item[id_key]
            else:
                last_item_id = last_item["id"]
            links.append({
                "rel": "next",
                "href": self._get_next_link(request, last_item_id),
            })
        return links

    def _update_link_prefix(self, orig_url, prefix):
        if not prefix:
            return orig_url
        url_parts = list(parse.urlsplit(orig_url))
        prefix_parts = list(parse.urlsplit(prefix))
        url_parts[0:2] = prefix_parts[0:2]
        return parse.urlunsplit(url_parts)

    def update_versioned_resource_dict(self, request, resource_dict, resource):
        """Updates the given resource dict for the given request version.

        This method calls every method, that is applicable to the request
        version, in _detail_version_modifiers.
        """
        for method_name in self._detail_version_modifiers:
            method = getattr(self, method_name)
            if request.api_version_request.matches_versioned_method(method):
                request_context = request.environ['manila.context']
                method.func(self, request_context, resource_dict, resource)

    @classmethod
    def versioned_method(cls, min_ver, max_ver=None, experimental=False):
        """Decorator for versioning API methods.

        :param min_ver: string representing minimum version
        :param max_ver: optional string representing maximum version
        :param experimental: flag indicating an API is experimental and is
                             subject to change or removal at any time
        """

        def decorator(f):
            obj_min_ver = api_version.APIVersionRequest(min_ver)
            if max_ver:
                obj_max_ver = api_version.APIVersionRequest(max_ver)
            else:
                obj_max_ver = api_version.APIVersionRequest()

            # Add to list of versioned methods registered
            func_name = f.__name__
            new_func = versioned_method.VersionedMethod(
                func_name, obj_min_ver, obj_max_ver, experimental, f)

            return new_func

        return decorator


def remove_invalid_options(context, search_options, allowed_search_options):
    """Remove search options that are not valid for non-admin API/context."""
    if context.is_admin:
        # Allow all options
        return
    # Otherwise, strip out all unknown options
    unknown_options = [opt for opt in search_options
                       if opt not in allowed_search_options]
    bad_options = ", ".join(unknown_options)
    LOG.debug("Removing options '%(bad_options)s' from query",
              {"bad_options": bad_options})
    for opt in unknown_options:
        del search_options[opt]


def validate_common_name(access):
    """Validate common name passed by user.

    'access' is used as the certificate's CN (common name)
    to which access is allowed or denied by the backend.
    The standard allows for just about any string in the
    common name. The meaning of a string depends on its
    interpretation and is limited to 64 characters.
    """
    if not(0 < len(access) < 65):
        exc_str = _('Invalid CN (common name). Must be 1-64 chars long.')
        raise webob.exc.HTTPBadRequest(explanation=exc_str)


def validate_username(access):
    valid_username_re = '[\w\$\.\-_\`;\'\{\}\[\]\\\\]{4,255}$'
    username = access
    if not re.match(valid_username_re, username):
        exc_str = ('Invalid user or group name. Must be 4-255 characters '
                   'and consist of alphanumeric characters and '
                   'special characters $]{.-_\'`;}[\\')
        raise webob.exc.HTTPBadRequest(explanation=exc_str)


def validate_cephx_id(cephx_id):
    if not cephx_id:
        raise webob.exc.HTTPBadRequest(explanation=_(
            'Ceph IDs may not be empty.'))

    # This restriction may be lifted in Ceph in the future:
    # http://tracker.ceph.com/issues/14626
    if not set(cephx_id) <= set(string.printable):
        raise webob.exc.HTTPBadRequest(explanation=_(
            'Ceph IDs must consist of ASCII printable characters.'))

    # Periods are technically permitted, but we restrict them here
    # to avoid confusion where users are unsure whether they should
    # include the "client." prefix: otherwise they could accidentally
    # create "client.client.foobar".
    if '.' in cephx_id:
        raise webob.exc.HTTPBadRequest(explanation=_(
            'Ceph IDs may not contain periods.'))


def validate_ip(access_to, enable_ipv6):
    try:
        if enable_ipv6:
            validator = ipaddress.ip_network
        else:
            validator = ipaddress.IPv4Network
        validator(six.text_type(access_to))
    except ValueError as error:
        err_msg = encodeutils.exception_to_unicode(error)
        raise webob.exc.HTTPBadRequest(explanation=err_msg)


def validate_access(*args, **kwargs):

    access_type = kwargs.get('access_type')
    access_to = kwargs.get('access_to')
    enable_ceph = kwargs.get('enable_ceph')
    enable_ipv6 = kwargs.get('enable_ipv6')

    if access_type == 'ip':
        validate_ip(access_to, enable_ipv6)
    elif access_type == 'user':
        validate_username(access_to)
    elif access_type == 'cert':
        validate_common_name(access_to.strip())
    elif access_type == "cephx" and enable_ceph:
        validate_cephx_id(access_to)
    else:
        if enable_ceph:
            exc_str = _("Only 'ip', 'user', 'cert' or 'cephx' access "
                        "types are supported.")
        else:
            exc_str = _("Only 'ip', 'user' or 'cert' access types "
                        "are supported.")

        raise webob.exc.HTTPBadRequest(explanation=exc_str)
