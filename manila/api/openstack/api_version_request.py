# Copyright 2014 IBM Corp.
# Copyright 2015 Clinton Knight
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

import re

from manila.api.openstack import versioned_method
from manila import exception
from manila.i18n import _
from manila import utils

# Define the minimum and maximum version of the API across all of the
# REST API. The format of the version is:
# X.Y where:
#
# - X will only be changed if a significant backwards incompatible API
# change is made which affects the API as whole. That is, something
# that is only very very rarely incremented.
#
# - Y when you make any change to the API. Note that this includes
# semantic changes which may not affect the input or output formats or
# even originate in the API code layer. We are not distinguishing
# between backwards compatible and backwards incompatible changes in
# the versioning system. It must be made clear in the documentation as
# to what is a backwards compatible change and what is a backwards
# incompatible one.

#
# You must update the API version history string below with a one or
# two line description as well as update rest_api_version_history.rst
REST_API_VERSION_HISTORY = """

    REST API Version History:

    * 1.0 - Initial version. Includes all V1 APIs and extensions in Kilo.
    * 2.0 - Versions API updated to reflect beginning of microversions epoch.
    * 2.1 - Share create() doesn't ignore availability_zone field of share.
    * 2.2 - Snapshots become optional feature.
    * 2.3 - Share instances admin API
    * 2.4 - Consistency Group support
    * 2.5 - Share Migration admin API
    * 2.6 - Return share_type UUID instead of name in Share API
    * 2.7 - Rename old extension-like API URLs to core-API-like
    * 2.8 - Attr "is_public" can be set for share using API "manage"
    * 2.9 - Add export locations API
"""

# The minimum and maximum versions of the API supported
# The default api version request is defined to be the
# the minimum version of the API supported.
_MIN_API_VERSION = "2.0"
_MAX_API_VERSION = "2.9"
DEFAULT_API_VERSION = _MIN_API_VERSION


# NOTE(cyeoh): min and max versions declared as functions so we can
# mock them for unittests. Do not use the constants directly anywhere
# else.
def min_api_version():
    return APIVersionRequest(_MIN_API_VERSION)


def max_api_version():
    return APIVersionRequest(_MAX_API_VERSION)


class APIVersionRequest(utils.ComparableMixin):
    """This class represents an API Version Request.

    This class includes convenience methods for manipulation
    and comparison of version numbers as needed to implement
    API microversions.
    """

    def __init__(self, version_string=None, experimental=False):
        """Create an API version request object."""
        self._ver_major = None
        self._ver_minor = None
        self._experimental = experimental

        if version_string is not None:
            match = re.match(r"^([1-9]\d*)\.([1-9]\d*|0)$",
                             version_string)
            if match:
                self._ver_major = int(match.group(1))
                self._ver_minor = int(match.group(2))
            else:
                raise exception.InvalidAPIVersionString(version=version_string)

    def __str__(self):
        """Debug/Logging representation of object."""
        return ("API Version Request Major: %(major)s, Minor: %(minor)s"
                % {'major': self._ver_major, 'minor': self._ver_minor})

    def is_null(self):
        return self._ver_major is None and self._ver_minor is None

    def _cmpkey(self):
        """Return the value used by ComparableMixin for rich comparisons."""
        return self._ver_major, self._ver_minor

    @property
    def experimental(self):
        return self._experimental

    @experimental.setter
    def experimental(self, value):
        if type(value) != bool:
            msg = _('The experimental property must be a bool value.')
            raise exception.InvalidParameterValue(err=msg)
        self._experimental = value

    def matches_versioned_method(self, method):
        """Compares this version to that of a versioned method."""

        if type(method) != versioned_method.VersionedMethod:
            msg = _('An API version request must be compared '
                    'to a VersionedMethod object.')
            raise exception.InvalidParameterValue(err=msg)

        return self.matches(method.start_version,
                            method.end_version,
                            method.experimental)

    def matches(self, min_version, max_version, experimental=False):
        """Compares this version to the specified min/max range.

        Returns whether the version object represents a version
        greater than or equal to the minimum version and less than
        or equal to the maximum version.

        If min_version is null then there is no minimum limit.
        If max_version is null then there is no maximum limit.
        If self is null then raise ValueError.

        :param min_version: Minimum acceptable version.
        :param max_version: Maximum acceptable version.
        :param experimental: Whether to match experimental APIs.
        :returns: boolean
        """

        if self.is_null():
            raise ValueError
        # NOTE(cknight): An experimental request should still match a
        # non-experimental API, so the experimental check isn't just
        # looking for equality.
        if not self.experimental and experimental:
            return False
        if max_version.is_null() and min_version.is_null():
            return True
        elif max_version.is_null():
            return min_version <= self
        elif min_version.is_null():
            return self <= max_version
        else:
            return min_version <= self <= max_version

    def get_string(self):
        """Returns a string representation of this object.

        If this method is used to create an APIVersionRequest,
        the resulting object will be an equivalent request.
        """
        if self.is_null():
            raise ValueError
        return ("%(major)s.%(minor)s" %
                {'major': self._ver_major, 'minor': self._ver_minor})
