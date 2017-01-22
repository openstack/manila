# Copyright 2011 OpenStack LLC
# Copyright 2015 Mirantic, Inc.
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

import fixtures
import os

from oslo_config import cfg
import six

from manila import context
from manila import utils

CONF = cfg.CONF


class NamedBinaryStr(six.binary_type):

    """Wrapper for six.binary_type to facilitate overriding __name__."""


class NamedUnicodeStr(six.text_type):

    """Unicode string look-alike to facilitate overriding __name__."""

    def __init__(self, value):
        self._value = value

    def __str__(self):
        return self._value

    def encode(self, enc):
        return self._value.encode(enc)

    def __format__(self, formatstr):
        """Workaround for ddt bug.

        DDT will always call __format__ even when __name__ exists,
        which blows up for Unicode strings under Py2.
        """
        return ''


class NamedDict(dict):

    """Wrapper for dict to facilitate overriding __name__."""


class NamedTuple(tuple):

    """Wrapper for dict to facilitate overriding __name__."""


def annotated(test_name, test_input):
    if isinstance(test_input, dict):
        annotated_input = NamedDict(test_input)
    elif isinstance(test_input, six.text_type):
        annotated_input = NamedUnicodeStr(test_input)
    elif isinstance(test_input, tuple):
        annotated_input = NamedTuple(test_input)
    else:
        annotated_input = NamedBinaryStr(test_input)

    setattr(annotated_input, '__name__', test_name)
    return annotated_input


def get_test_admin_context():
    return context.get_admin_context()


def is_manila_installed():
    if os.path.exists('../../manila.manila.egg-info'):
        return True
    else:
        return False


def set_timeout(timeout):
    """Timeout decorator for unit test methods.

    Use this decorator for tests that are expected to pass in very specific
    amount of time, not common for all other tests.
    It can have either big or small value.
    """

    def _decorator(f):

        @six.wraps(f)
        def _wrapper(self, *args, **kwargs):
            self.useFixture(fixtures.Timeout(timeout, gentle=True))
            return f(self, *args, **kwargs)

        return _wrapper

    return _decorator


class create_temp_config_with_opts(object):
    """Creates temporary config file with provided opts and values.

    usage:
        data = {'FOO_GROUP': {'foo_opt': 'foo_value'}}
        assert CONF.FOO_GROUP.foo_opt != 'foo_value'
        with create_temp_config_with_opts(data):
            assert CONF.FOO_GROUP.foo_opt == 'foo_value'
        assert CONF.FOO_GROUP.foo_opt != 'foo_value'

    :param data: dict -- expected dict with two layers, first is name of
       config group and second is opts with values. Example:
       {'DEFAULT': {'foo_opt': 'foo_v'}, 'BAR_GROUP': {'bar_opt': 'bar_v'}}
    """

    def __init__(self, data):
        self.data = data

    def __enter__(self):
        config_filename = 'fake_config'
        with utils.tempdir() as tmpdir:
            tmpfilename = os.path.join(tmpdir, '%s.conf' % config_filename)
            with open(tmpfilename, "w") as configfile:
                for group, opts in self.data.items():
                    configfile.write("""[%s]\n""" % group)
                    for opt, value in opts.items():
                        configfile.write(
                            """%(k)s = %(v)s\n""" % {'k': opt, 'v': value})
                configfile.write("""\n""")

            # Add config file with updated opts
            CONF.default_config_files = [configfile.name]

            # Reload config instance to use redefined opts
            CONF.reload_config_files()
        return CONF

    def __exit__(self, exc_type, exc_value, exc_traceback):
        return False  # do not suppress errors
