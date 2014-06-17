# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

from manila import exception
from manila import test
from manila import utils


class FakeNotifier(object):
    """Acts like the manila.openstack.common.notifier.api module."""
    ERROR = 88

    def __init__(self):
        self.provided_publisher = None
        self.provided_event = None
        self.provided_priority = None
        self.provided_payload = None

    def notify(self, context, publisher, event, priority, payload):
        self.provided_publisher = publisher
        self.provided_event = event
        self.provided_priority = priority
        self.provided_payload = payload


class ManilaExceptionTestCase(test.TestCase):
    def test_default_error_msg(self):
        class FakeManilaException(exception.ManilaException):
            message = "default message"

        exc = FakeManilaException()
        self.assertEqual(unicode(exc), 'default message')

    def test_error_msg(self):
        self.assertEqual(unicode(exception.ManilaException('test')),
                          'test')

    def test_default_error_msg_with_kwargs(self):
        class FakeManilaException(exception.ManilaException):
            message = "default message: %(code)s"

        exc = FakeManilaException(code=500)
        self.assertEqual(unicode(exc), 'default message: 500')

    def test_error_msg_exception_with_kwargs(self):
        # NOTE(dprince): disable format errors for this test
        self.flags(fatal_exception_format_errors=False)

        class FakeManilaException(exception.ManilaException):
            message = "default message: %(mispelled_code)s"

        exc = FakeManilaException(code=500)
        self.assertEqual(unicode(exc), 'default message: %(mispelled_code)s')

    def test_default_error_code(self):
        class FakeManilaException(exception.ManilaException):
            code = 404

        exc = FakeManilaException()
        self.assertEqual(exc.kwargs['code'], 404)

    def test_error_code_from_kwarg(self):
        class FakeManilaException(exception.ManilaException):
            code = 500

        exc = FakeManilaException(code=404)
        self.assertEqual(exc.kwargs['code'], 404)
