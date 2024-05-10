# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""API request/response validating middleware."""

import functools
import typing as ty

from oslo_serialization import jsonutils
import webob

from manila.api.openstack import api_version_request as api_version
from manila.api.openstack import wsgi
from manila.api.validation import validators
from manila import exception
from manila.i18n import _


def validated(cls):
    cls._validated = True
    return cls


def _schema_validator(
    schema: ty.Dict[str, ty.Any],
    target: ty.Dict[str, ty.Any],
    min_version: ty.Optional[str],
    max_version: ty.Optional[str],
    args: ty.Any,
    kwargs: ty.Any,
    is_body: bool = True,
):
    """A helper method to execute JSON Schema Validation.

    This method checks the request version whether matches the specified
    ``max_version`` and ``min_version``. If the version range matches the
    request, we validate ``schema`` against ``target``. A failure will result
    in ``ValidationError`` being raised.

    :param schema: The JSON Schema schema used to validate the target.
    :param target: The target to be validated by the schema.
    :param min_version: A string indicating the minimum API version ``schema``
        applies against.
    :param max_version: A string indicating the maximum API version ``schema``
        applies against.
    :param args: Positional arguments which passed into original method.
    :param kwargs: Keyword arguments which passed into original method.
    :param is_body: Whether ``target`` is a HTTP request body or not.
    :returns: None.
    :raises: ``ValidationError`` if validation fails.
    """
    min_ver = api_version.APIVersionRequest(min_version)
    max_ver = api_version.APIVersionRequest(max_version)

    # NOTE: The request object is always the second argument. However, numerous
    # unittests pass in the request object via kwargs instead so we handle that
    # as well.
    # TODO(stephenfin): Fix unit tests so we don't have to to do this
    if 'req' in kwargs:
        ver = kwargs['req'].api_version_request
    else:
        ver = args[1].api_version_request

    if ver.matches(min_ver, max_ver):
        # Only validate against the schema if it lies within
        # the version range specified. Note that if both min
        # and max are not specified the validator will always
        # be run.
        schema_validator = validators._SchemaValidator(schema, is_body=is_body)
        schema_validator.validate(target)


def request_body_schema(
    schema: ty.Dict[str, ty.Any],
    min_version: ty.Optional[str] = None,
    max_version: ty.Optional[str] = None,
):
    """Register a schema to validate request body.

    ``schema`` will be used for validating the request body just before the API
    method is executed.

    :param schema: The JSON Schema schema used to validate the target.
    :param min_version: A string indicating the minimum API version ``schema``
        applies against.
    :param max_version: A string indicating the maximum API version ``schema``
        applies against.
    """

    def add_validator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            _schema_validator(
                schema,
                kwargs['body'],
                min_version,
                max_version,
                args,
                kwargs,
                is_body=True,
            )
            return func(*args, **kwargs)

        wrapper._request_body_schema = schema

        return wrapper

    return add_validator


def request_query_schema(
    schema: ty.Dict[str, ty.Any],
    min_version: ty.Optional[str] = None,
    max_version: ty.Optional[str] = None,
):
    """Register a schema to validate request query string parameters.

    ``schema`` will be used for validating request query strings just before
    the API method is executed.

    :param schema: The JSON Schema schema used to validate the target.
    :param min_version: A string indicating the minimum API version ``schema``
        applies against.
    :param max_version: A string indicating the maximum API version ``schema``
        applies against.
    """

    def add_validator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # NOTE: The request object is always the second argument. However,
            # numerous unittests pass in the request object via kwargs instead
            # so we handle that as well.
            # TODO(stephenfin): Fix unit tests so we don't have to to do this
            if 'req' in kwargs:
                req = kwargs['req']
            else:
                req = args[1]

            # NOTE: The webob package throws UnicodeError when param cannot be
            # decoded. Catch this and raise HTTP 400.
            try:
                query = req.GET.dict_of_lists()
            except UnicodeDecodeError:
                msg = _('Query string is not UTF-8 encoded')
                raise exception.ValidationError(msg)

            _schema_validator(
                schema,
                query,
                min_version,
                max_version,
                args,
                kwargs,
                is_body=True,
            )
            return func(*args, **kwargs)

        wrapper._request_query_schema = schema

        return wrapper

    return add_validator


def response_body_schema(
    schema: ty.Dict[str, ty.Any],
    min_version: ty.Optional[str] = None,
    max_version: ty.Optional[str] = None,
):
    """Register a schema to validate response body.

    ``schema`` will be used for validating the response body just after the API
    method is executed.

    :param schema: The JSON Schema schema used to validate the target.
    :param min_version: A string indicating the minimum API version ``schema``
        applies against.
    :param max_version: A string indicating the maximum API version ``schema``
        applies against.
    """

    def add_validator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            response = func(*args, **kwargs)

            # NOTE(stephenfin): If our response is an object, we need to
            # serializer and deserialize to convert e.g. date-time to strings
            if isinstance(response, wsgi.ResponseObject):
                serializer = wsgi.JSONDictSerializer()
                _body = serializer.serialize(response.obj)
            # TODO(stephenfin): We should replace all instances of this with
            # wsgi.ResponseObject
            elif isinstance(response, webob.Response):
                _body = response.body
            else:
                serializer = wsgi.JSONDictSerializer()
                _body = serializer.serialize(response)

            if _body == b'':
                body = None
            else:
                body = jsonutils.loads(_body)

            _schema_validator(
                schema,
                body,
                min_version,
                max_version,
                args,
                kwargs,
                is_body=True,
            )
            return response

        wrapper._response_body_schema = schema

        return wrapper

    return add_validator
