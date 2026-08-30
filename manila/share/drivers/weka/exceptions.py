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

"""Weka-specific exceptions for the Manila share driver."""

from manila import exception
from manila.i18n import _


class WekaException(exception.ManilaException):
    """Base exception for all Weka driver errors."""
    message = _("Weka driver error: %(reason)s")


class WekaApiError(WekaException):
    """Raised when the Weka REST API returns an error response."""
    message = _("Weka API error %(status_code)s: %(reason)s")

    def __init__(self, status_code=None, reason=None, **kwargs):
        self.status_code = status_code
        kwargs.setdefault('status_code', status_code or 'unknown')
        kwargs.setdefault('reason', reason or 'unknown error')
        super(WekaApiError, self).__init__(**kwargs)


class WekaAuthError(WekaApiError):
    """Raised when Weka API authentication fails."""
    message = _("Weka authentication failed: %(reason)s")

    def __init__(self, reason=None, **kwargs):
        kwargs.setdefault('status_code', 401)
        kwargs.setdefault('reason', reason or 'invalid credentials')
        super(WekaAuthError, self).__init__(**kwargs)


class WekaNotFound(WekaApiError):
    """Raised when a Weka resource is not found (HTTP 404)."""
    message = _("Weka resource not found: %(reason)s")

    def __init__(self, reason=None, **kwargs):
        kwargs.setdefault('status_code', 404)
        kwargs.setdefault('reason', reason or 'resource not found')
        super(WekaNotFound, self).__init__(**kwargs)


class WekaFilesystemNotFound(WekaNotFound):
    """Raised when a specific Weka filesystem cannot be found."""
    message = _("Weka filesystem not found: %(reason)s")


class WekaConflict(WekaApiError):
    """Raised when a Weka resource already exists (HTTP 409)."""
    message = _("Weka resource conflict: %(reason)s")

    def __init__(self, reason=None, **kwargs):
        kwargs.setdefault('status_code', 409)
        kwargs.setdefault('reason', reason or 'resource already exists')
        super(WekaConflict, self).__init__(**kwargs)


class WekaRateLimited(WekaApiError):
    """Raised when the Weka API rate-limits the client (HTTP 429)."""
    message = _("Weka API rate limited: %(reason)s")

    def __init__(self, reason=None, **kwargs):
        kwargs.setdefault('status_code', 429)
        kwargs.setdefault('reason', reason or 'too many requests')
        super(WekaRateLimited, self).__init__(**kwargs)


class WekaMountError(WekaException):
    """Raised when a WekaFS POSIX mount operation fails."""
    message = _("WekaFS mount error: %(reason)s")


class WekaUnmountError(WekaException):
    """Raised when a WekaFS POSIX unmount operation fails."""
    message = _("WekaFS unmount error: %(reason)s")


class WekaCapacityError(WekaException):
    """Raised when a Weka filesystem capacity operation fails."""
    message = _("Weka capacity error: %(reason)s")


class WekaConfigurationError(WekaException):
    """Raised when the driver configuration is invalid."""
    message = _("Weka driver configuration error: %(reason)s")


class WekaOrgError(WekaException):
    """Raised when per-tenant organization provisioning fails."""
    message = _("Weka organization error: %(reason)s")
