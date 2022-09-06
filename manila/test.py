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

"""Base classes for our unit tests.

Allows overriding of flags for use of fakes, and some black magic for
inline callbacks.

"""

import os
import shutil
from unittest import mock
import warnings

import fixtures
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_config import fixture as config_fixture
import oslo_messaging
from oslo_messaging import conffixture as messaging_conffixture
from oslo_utils import uuidutils
import oslotest.base as base_test
from sqlalchemy import exc as sqla_exc

from manila.api.openstack import api_version_request as api_version
from manila import coordination
from manila.db import migration
from manila.db.sqlalchemy import api as db_api
from manila.db.sqlalchemy import models as db_models
from manila import policy
from manila import rpc
from manila import service
from manila.tests import conf_fixture
from manila.tests import fake_notifier

test_opts = [
    cfg.StrOpt('sqlite_clean_db',
               default='clean.sqlite',
               help='File name of clean sqlite database.'),
    cfg.StrOpt('sqlite_db',
               default='manila.sqlite',
               help='The filename to use with sqlite.'),
]

CONF = cfg.CONF
CONF.register_opts(test_opts)

_DB_CACHE = None


class DatabaseFixture(fixtures.Fixture):

    def __init__(self, db_session, db_migrate, sql_connection, sqlite_db,
                 sqlite_clean_db):
        self.sql_connection = sql_connection
        self.sqlite_db = sqlite_db
        self.sqlite_clean_db = sqlite_clean_db
        self.engine = db_session.get_engine()
        self.engine.dispose()
        conn = self.engine.connect()
        # FIXME(stephenfin): This is an issue. We're not applying our
        # migrations on SQLite in-memory backends and because the model schemas
        # and migration schemas don't currently match exactly, we are not
        # testing against something resembling what our customers would see.
        # We should (a) start applying the migrations for all backends (which
        # will require reworking the migrations since SQLite doesn't support
        # ALTER fully, meaning batch mode must be used) and (b) get the two
        # different sets of schemas in sync and keep them in sync.
        if sql_connection == "sqlite://":
            self.setup_sqlite(db_migrate)
        else:
            testdb = os.path.join(CONF.state_path, sqlite_db)
            db_migrate.upgrade('head')
            if os.path.exists(testdb):
                return
        if sql_connection == "sqlite://":
            conn = self.engine.connect()
            self._DB = "".join(line for line in conn.connection.iterdump())
            self.engine.dispose()
        else:
            cleandb = os.path.join(CONF.state_path, sqlite_clean_db)
            shutil.copyfile(testdb, cleandb)

    def setUp(self):
        super().setUp()
        if self.sql_connection == "sqlite://":
            conn = self.engine.connect()
            conn.connection.executescript(self._DB)
            self.addCleanup(self.engine.dispose)  # pylint: disable=no-member
        else:
            shutil.copyfile(
                os.path.join(CONF.state_path, self.sqlite_clean_db),
                os.path.join(CONF.state_path, self.sqlite_db),
            )

    def setup_sqlite(self, db_migrate):
        if db_migrate.version():
            return
        db_models.BASE.metadata.create_all(self.engine)
        db_migrate.stamp('head')


class WarningsFixture(fixtures.Fixture):
    """Filters out warnings during test runs."""

    def setUp(self):
        super().setUp()

        self._original_warning_filters = warnings.filters[:]

        # NOTE(sdague): Make deprecation warnings only happen once. Otherwise
        # this gets kind of crazy given the way that upstream python libs use
        # this.
        warnings.simplefilter('once', DeprecationWarning)

        # NOTE(sdague): this remains an unresolved item around the way
        # forward on is_admin, the deprecation is definitely really premature.
        warnings.filterwarnings(
            'ignore',
            message=(
                'Policy enforcement is depending on the value of is_admin. '
                'This key is deprecated. Please update your policy '
                'file to use the standard policy values.'
            ),
        )

        # NOTE(mriedem): Ignore scope check UserWarnings from oslo.policy.
        warnings.filterwarnings(
            'ignore',
            message='Policy .* failed scope check',
            category=UserWarning,
        )

        # NOTE(gibi): The UUIDFields emits a warning if the value is not a
        # valid UUID. Let's escalate that to an exception in the test to
        # prevent adding violations.
        warnings.filterwarnings('error', message='.*invalid UUID.*')

        # NOTE(mriedem): Avoid adding anything which tries to convert an
        # object to a primitive which jsonutils.to_primitive() does not know
        # how to handle (or isn't given a fallback callback).
        warnings.filterwarnings(
            'error',
            message=(
                'Cannot convert <oslo_db.sqlalchemy.enginefacade._Default '
                'object at '
            ),
            category=UserWarning,
        )

        # Enable deprecation warnings for manila itself to capture upcoming
        # SQLAlchemy changes

        warnings.filterwarnings(
            'ignore',
            category=sqla_exc.SADeprecationWarning,
        )

        warnings.filterwarnings(
            'error',
            module='manila',
            category=sqla_exc.SADeprecationWarning,
        )

        # ..but filter everything out until we get around to fixing them
        # TODO(stephenfin): Fix all of these

        warnings.filterwarnings(
            'ignore',
            module='manila',
            message='Using strings to indicate column or relationship paths ',
            category=sqla_exc.SADeprecationWarning,
        )

        warnings.filterwarnings(
            'ignore',
            module='manila',
            message='The current statement is being autocommitted ',
            category=sqla_exc.SADeprecationWarning,
        )

        warnings.filterwarnings(
            'ignore',
            module='manila',
            message='The autoload parameter is deprecated ',
            category=sqla_exc.SADeprecationWarning,
        )

        warnings.filterwarnings(
            'ignore',
            module='manila',
            message='Using strings to indicate relationship names in Query',
            category=sqla_exc.SADeprecationWarning,
        )

        # Enable general SQLAlchemy warnings also to ensure we're not doing
        # silly stuff. It's possible that we'll need to filter things out here
        # with future SQLAlchemy versions, but that's a good thing

        warnings.filterwarnings(
            'error',
            module='manila',
            category=sqla_exc.SAWarning,
        )

        self.addCleanup(self._reset_warning_filters)

    def _reset_warning_filters(self):
        warnings.filters[:] = self._original_warning_filters


class TestCase(base_test.BaseTestCase):
    """Test case base class for all unit tests."""

    def setUp(self):
        """Run before each test method to initialize test environment."""
        super(TestCase, self).setUp()

        conf_fixture.set_defaults(CONF)
        CONF([], default_config_files=[])

        global _DB_CACHE
        if not _DB_CACHE:
            _DB_CACHE = DatabaseFixture(
                db_api,
                migration,
                sql_connection=CONF.database.connection,
                sqlite_db=CONF.sqlite_db,
                sqlite_clean_db=CONF.sqlite_clean_db,
            )
        self.useFixture(_DB_CACHE)

        # NOTE(stephenfin): WarningsFixture must be after the DatabaseFixture
        self.useFixture(WarningsFixture())

        self.injected = []
        self._services = []
        self.flags(fatal_exception_format_errors=True)
        # This will be cleaned up by the NestedTempfile fixture
        lock_path = self.useFixture(fixtures.TempDir()).path
        self.fixture = self.useFixture(config_fixture.Config(lockutils.CONF))
        self.fixture.config(lock_path=lock_path, group='oslo_concurrency')
        self.fixture.config(
            disable_process_locking=True, group='oslo_concurrency')

        rpc.add_extra_exmods('manila.tests')
        self.addCleanup(rpc.clear_extra_exmods)
        self.addCleanup(rpc.cleanup)

        self.messaging_conf = messaging_conffixture.ConfFixture(CONF)
        self.messaging_conf.transport_url = 'fake:/'
        self.messaging_conf.response_timeout = 15
        self.useFixture(self.messaging_conf)

        oslo_messaging.get_notification_transport(CONF)
        self.override_config('driver', ['test'],
                             group='oslo_messaging_notifications')

        rpc.init(CONF)

        mock.patch('keystoneauth1.loading.load_auth_from_conf_options').start()

        fake_notifier.stub_notifier(self)

        self._disable_osprofiler()

        # Locks must be cleaned up after tests
        CONF.set_override('backend_url', 'file://' + lock_path,
                          group='coordination')
        coordination.LOCK_COORDINATOR.start()
        self.addCleanup(coordination.LOCK_COORDINATOR.stop)

        # policy
        policy.init(suppress_deprecation_warnings=True)
        self.addCleanup(policy.reset)

    def _disable_osprofiler(self):
        """Disable osprofiler.

        osprofiler should not run for unit tests.
        """

        def side_effect(value):
            return value
        mock_decorator = mock.MagicMock(side_effect=side_effect)
        p = mock.patch("osprofiler.profiler.trace_cls",
                       return_value=mock_decorator)
        p.start()

    def tearDown(self):
        """Runs after each test method to tear down test environment."""
        super(TestCase, self).tearDown()
        # Reset any overridden flags
        CONF.reset()

        # Stop any timers
        for x in self.injected:
            try:
                x.stop()
            except AssertionError:
                pass

        # Kill any services
        for x in self._services:
            try:
                x.kill()
            except Exception:
                pass

        # Delete attributes that don't start with _ so they don't pin
        # memory around unnecessarily for the duration of the test
        # suite
        for key in [k for k in self.__dict__.keys() if k[0] != '_']:
            del self.__dict__[key]

    def flags(self, **kw):
        """Override flag variables for a test."""
        for k, v in kw.items():
            CONF.set_override(k, v)

    def start_service(self, name, host=None, **kwargs):
        host = host and host or uuidutils.generate_uuid()
        kwargs.setdefault('host', host)
        kwargs.setdefault('binary', 'manila-%s' % name)
        svc = service.Service.create(**kwargs)
        svc.start()
        self._services.append(svc)
        return svc

    def mock_object(self, obj, attr_name, new_attr=None, **kwargs):
        """Use python mock to mock an object attribute

        Mocks the specified objects attribute with the given value.
        Automatically performs 'addCleanup' for the mock.

        """
        if not new_attr:
            new_attr = mock.Mock()
        patcher = mock.patch.object(obj, attr_name, new_attr, **kwargs)
        patcher.start()
        self.addCleanup(patcher.stop)
        return new_attr

    def mock_class(self, class_name, new_val=None, **kwargs):
        """Use python mock to mock a class

        Mocks the specified objects attribute with the given value.
        Automatically performs 'addCleanup' for the mock.

        """
        if not new_val:
            new_val = mock.Mock()
        patcher = mock.patch(class_name, new_val, **kwargs)
        patcher.start()
        self.addCleanup(patcher.stop)
        return new_val

    def assertDictListMatch(self, L1, L2):
        """Assert a list of dicts are equivalent."""
        def raise_assertion(msg):
            L1str = str(L1)
            L2str = str(L2)
            base_msg = ('List of dictionaries do not match: %(msg)s '
                        'L1: %(L1str)s L2: %(L2str)s' %
                        {"msg": msg, "L1str": L1str, "L2str": L2str})
            raise AssertionError(base_msg)

        L1count = len(L1)
        L2count = len(L2)
        if L1count != L2count:
            raise_assertion('Length mismatch: len(L1)=%(L1count)d != '
                            'len(L2)=%(L2count)d' %
                            {"L1count": L1count, "L2count": L2count})

        for d1, d2 in zip(L1, L2):
            self.assertDictEqual(d1, d2)

    def assertSubDictMatch(self, sub_dict, super_dict):
        """Assert a sub_dict is subset of super_dict."""
        self.assertTrue(set(sub_dict.keys()).issubset(set(super_dict.keys())))
        for k, sub_value in sub_dict.items():
            super_value = super_dict[k]
            if isinstance(sub_value, dict):
                self.assertSubDictMatch(sub_value, super_value)
            elif 'DONTCARE' in (sub_value, super_value):
                continue
            else:
                self.assertEqual(sub_value, super_value)

    def assertIn(self, a, b, *args, **kwargs):
        """Python < v2.7 compatibility.  Assert 'a' in 'b'."""
        try:
            f = super(TestCase, self).assertIn
        except AttributeError:
            self.assertTrue(a in b, *args, **kwargs)
        else:
            f(a, b, *args, **kwargs)

    def assertNotIn(self, a, b, *args, **kwargs):
        """Python < v2.7 compatibility.  Assert 'a' NOT in 'b'."""
        try:
            f = super(TestCase, self).assertNotIn
        except AttributeError:
            self.assertFalse(a in b, *args, **kwargs)
        else:
            f(a, b, *args, **kwargs)

    def assertIsInstance(self, a, b, *args, **kwargs):
        """Python < v2.7 compatibility."""
        try:
            f = super(TestCase, self).assertIsInstance
        except AttributeError:
            self.assertIsInstance(a, b)
        else:
            f(a, b, *args, **kwargs)

    def assertIsNone(self, a, *args, **kwargs):
        """Python < v2.7 compatibility."""
        try:
            f = super(TestCase, self).assertIsNone
        except AttributeError:
            self.assertTrue(a is None)
        else:
            f(a, *args, **kwargs)

    def _dict_from_object(self, obj, ignored_keys):
        if ignored_keys is None:
            ignored_keys = []
        return {k: v for k, v in obj.items()
                if k not in ignored_keys}

    def _assertEqualListsOfObjects(self, objs1, objs2, ignored_keys=None):
        obj_to_dict = lambda o: (  # noqa: E731
            self._dict_from_object(o, ignored_keys))
        sort_key = lambda d: [d[k] for k in sorted(d)]  # noqa: E731
        conv_and_sort = lambda obj: (  # noqa: E731
            sorted(map(obj_to_dict, obj), key=sort_key))

        self.assertEqual(conv_and_sort(objs1), conv_and_sort(objs2))

    def is_microversion_ge(self, left, right):
        return (api_version.APIVersionRequest(left) >=
                api_version.APIVersionRequest(right))

    def is_microversion_lt(self, left, right):
        return (api_version.APIVersionRequest(left) <
                api_version.APIVersionRequest(right))

    def assert_notify_called(self, mock_notify, calls):
        for i in range(0, len(calls)):
            mock_call = mock_notify.call_args_list[i]
            call = calls[i]

            posargs = mock_call[0]

            self.assertEqual(call[0], posargs[0])
            self.assertEqual(call[1], posargs[2])

    def override_config(self, name, override, group=None):
        """Cleanly override CONF variables."""
        CONF.set_override(name, override, group)
        self.addCleanup(CONF.clear_override, name, group)
