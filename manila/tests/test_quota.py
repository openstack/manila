# Copyright 2017 Mirantis Inc.
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

import ddt
import mock
from oslo_config import cfg

from manila import exception
from manila import quota
from manila import test

CONF = cfg.CONF


@ddt.ddt
class DbQuotaDriverTestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.project_id = 'fake_project_id'
        self.user_id = 'fake_user_id'
        self.share_type_id = 'fake_share_type_id'
        self.ctxt = type(
            'FakeContext', (object, ),
            {'project_id': self.project_id, 'user_id': self.user_id,
             'quota_class': 'fake_quota_class', 'elevated': mock.Mock()})
        self.driver = quota.DbQuotaDriver()
        self.reservations = ['foo', 'bar']
        self.resources = {k: quota.BaseResource(k) for k in ('foo', 'bar')}

    def test_get_by_class(self):
        self.mock_object(quota.db, 'quota_class_get')

        result = self.driver.get_by_class(
            self.ctxt, 'fake_quota_class', 'fake_res')

        self.assertEqual(quota.db.quota_class_get.return_value, result)
        quota.db.quota_class_get.assert_called_once_with(
            self.ctxt, 'fake_quota_class', 'fake_res')

    def test_get_defaults(self):
        self.mock_object(
            quota.db, 'quota_class_get_default',
            mock.Mock(return_value={'foo': 13}))

        result = self.driver.get_defaults(self.ctxt, self.resources)

        self.assertEqual(
            {'foo': 13, 'bar': self.resources['bar'].default}, result)
        quota.db.quota_class_get_default.assert_called_once_with(self.ctxt)

    @ddt.data(True, False)
    def test_get_class_quotas(self, defaults):
        self.mock_object(
            quota.db, 'quota_class_get_all_by_name',
            mock.Mock(return_value={'foo': 13}))

        result = self.driver.get_class_quotas(
            self.ctxt, self.resources, 'fake_quota_class', defaults)

        expected = {'foo': 13, 'bar': -1} if defaults else {'foo': 13}
        self.assertEqual(expected, result)
        quota.db.quota_class_get_all_by_name.assert_called_once_with(
            self.ctxt, 'fake_quota_class')

    @ddt.data(
        ('fake_project_id', {'foo': 20}, None, True, None, True),
        ('fake_different_project_id', {'bar': 40}, 'fake_quota_class', True,
         {'foo': {'in_use': 3, 'reserved': 2}}, False),
        ('fake_project_id', {'bar': 30}, 'fake_quota_class', True, None, False)
    )
    @ddt.unpack
    def test__process_quotas(self, project_id, quotas, quota_class, defaults,
                             usages, remains):
        self.mock_object(quota.db, 'quota_get_all', mock.Mock(return_value=[]))
        self.mock_object(quota.db, 'quota_class_get_all_by_name')
        self.mock_object(
            self.driver, 'get_defaults',
            mock.Mock(return_value={'foo': 11, 'bar': 12}))
        self.mock_object(
            quota.db, 'quota_get_all',
            mock.Mock(return_value=[]))

        result = self.driver._process_quotas(
            self.ctxt, self.resources, project_id, quotas, quota_class,
            defaults, usages, remains)

        expected = {key: {'limit': mock.ANY} for key in ('foo', 'bar')}
        if usages:
            for res in self.resources.values():
                usage = usages.get(res.name, {})
                expected[res.name].update(
                    in_use=usage.get('in_use', 0),
                    reserved=usage.get('reserved', 0))
        if remains:
            quota.db.quota_get_all.assert_called_once_with(
                self.ctxt, project_id)
            for res in self.resources.values():
                expected[res.name]['remains'] = mock.ANY
        else:
            self.assertEqual(0, quota.db.quota_get_all.call_count)

        self.assertEqual(expected, result)
        if quota_class or project_id == self.ctxt.project_id:
            quota.db.quota_class_get_all_by_name.assert_called_once_with(
                self.ctxt, quota_class or self.ctxt.quota_class)
        else:
            self.assertEqual(
                0, quota.db.quota_class_get_all_by_name.call_count)

    @ddt.data(
        ('fake_quota_class', True, None, 'fake_remains'),
        (None, False, 'fake_usages', False),
    )
    @ddt.unpack
    def test_get_project_quotas(self, quota_class, defaults, usages, remains):
        self.mock_object(quota.db, 'quota_get_all_by_project')
        self.mock_object(quota.db, 'quota_usage_get_all_by_project')
        self.mock_object(self.driver, '_process_quotas')

        result = self.driver.get_project_quotas(
            self.ctxt, self.resources, self.project_id,
            quota_class, defaults, usages, remains)

        self.assertEqual(
            result, self.driver._process_quotas.return_value)
        project_usages = None
        if usages:
            project_usages = (
                quota.db.quota_usage_get_all_by_project.return_value)
        self.driver._process_quotas.assert_called_once_with(
            self.ctxt, self.resources, self.project_id,
            quota.db.quota_get_all_by_project.return_value,
            quota_class, defaults=defaults, usages=project_usages,
            remains=remains)
        quota.db.quota_get_all_by_project.assert_called_once_with(
            self.ctxt, self.project_id)
        if usages:
            quota.db.quota_usage_get_all_by_project.assert_called_once_with(
                self.ctxt, self.project_id)
        else:
            self.assertEqual(
                0, quota.db.quota_usage_get_all_by_project.call_count)

    @ddt.data(
        (None, True, True),
        ('fake_quota_class', False, True),
        ('fake_quota_class', True, False),
    )
    @ddt.unpack
    def test_get_user_quotas(self, quota_class, defaults, usages):
        project_quotas = {'fake_resource': 5}
        self.mock_object(
            quota.db, 'quota_get_all_by_project',
            mock.Mock(return_value=project_quotas))
        self.mock_object(
            quota.db, 'quota_get_all_by_project_and_user',
            mock.Mock(return_value={'fake_user_defined_resource': 14}))
        mock_user_usages = self.mock_object(
            quota.db, 'quota_usage_get_all_by_project_and_user')
        self.mock_object(self.driver, '_process_quotas')

        result = self.driver.get_user_quotas(
            self.ctxt, self.resources, self.project_id, self.user_id,
            quota_class, defaults, usages)

        self.assertEqual(
            self.driver._process_quotas.return_value, result)
        quota.db.quota_get_all_by_project.assert_called_once_with(
            self.ctxt, self.project_id)
        quota.db.quota_get_all_by_project_and_user.assert_called_once_with(
            self.ctxt, self.project_id, self.user_id)
        if usages:
            user_usages = mock_user_usages.return_value
            mock_user_usages.assert_called_once_with(
                self.ctxt, self.project_id, self.user_id)
        else:
            user_usages = None
            self.assertEqual(0, mock_user_usages.call_count)
        expected_user_quotas = {'fake_user_defined_resource': 14}
        expected_user_quotas.update(project_quotas)
        self.driver._process_quotas.assert_called_once_with(
            self.ctxt, self.resources, self.project_id, expected_user_quotas,
            quota_class, defaults=defaults, usages=user_usages)

    @ddt.data(
        (None, True, True),
        ('fake_quota_class', False, True),
        ('fake_quota_class', True, False),
    )
    @ddt.unpack
    def test_get_share_type_quotas(self, quota_class, defaults, usages):
        project_quotas = {'fake_resource': 5}
        self.mock_object(
            quota.db, 'quota_get_all_by_project',
            mock.Mock(return_value=project_quotas))
        mock_st_quotas = self.mock_object(
            quota.db, 'quota_get_all_by_project_and_share_type',
            mock.Mock(return_value={'fake_st_defined_resource': 14}))
        mock_st_usages = self.mock_object(
            quota.db, 'quota_usage_get_all_by_project_and_share_type')
        self.mock_object(self.driver, '_process_quotas')

        result = self.driver.get_share_type_quotas(
            self.ctxt, self.resources, self.project_id, self.share_type_id,
            quota_class, defaults, usages)

        self.assertEqual(
            self.driver._process_quotas.return_value, result)
        quota.db.quota_get_all_by_project.assert_called_once_with(
            self.ctxt, self.project_id)
        mock_st_quotas.assert_called_once_with(
            self.ctxt, self.project_id, self.share_type_id)
        if usages:
            st_usages = mock_st_usages.return_value
            mock_st_usages.assert_called_once_with(
                self.ctxt, self.project_id, self.share_type_id)
        else:
            st_usages = None
            self.assertEqual(0, mock_st_usages.call_count)
        expected_st_quotas = {'fake_st_defined_resource': 14}
        expected_st_quotas.update(project_quotas)
        self.driver._process_quotas.assert_called_once_with(
            self.ctxt, self.resources, self.project_id, expected_st_quotas,
            quota_class, defaults=defaults, usages=st_usages)

    @ddt.data((None, None), (None, 'foo_st_id'), ('foo_user_id', None))
    @ddt.unpack
    def test_get_settable_quotas(self, user_id, st_id):
        project_quotas = {'fake': {
            'limit': 13, 'in_use': 7, 'reserved': 5, 'remains': 1,
        }}
        user_or_st_quotas = {'fake': {
            'limit': 11, 'in_use': 5, 'reserved': 2,
        }}
        self.mock_object(
            self.driver, 'get_project_quotas',
            mock.Mock(return_value=project_quotas))
        self.mock_object(
            self.driver, 'get_user_quotas',
            mock.Mock(return_value=user_or_st_quotas))
        self.mock_object(
            self.driver, 'get_share_type_quotas',
            mock.Mock(return_value=user_or_st_quotas))

        result = self.driver.get_settable_quotas(
            self.ctxt, self.resources, self.project_id, user_id, st_id)

        if user_id:
            self.driver.get_user_quotas.assert_called_once_with(
                self.ctxt, self.resources, self.project_id, user_id)
        else:
            self.assertEqual(0, self.driver.get_user_quotas.call_count)
        if st_id:
            self.driver.get_share_type_quotas.assert_called_once_with(
                self.ctxt, self.resources, self.project_id, st_id)
        else:
            self.assertEqual(0, self.driver.get_share_type_quotas.call_count)
        if user_id or st_id:
            expected_settable_quotas = {'fake': {'maximum': 13, 'minimum': 7}}
        else:
            expected_settable_quotas = {'fake': {'maximum': -1, 'minimum': 12}}
        self.driver.get_project_quotas.assert_called_once_with(
            self.ctxt, self.resources, self.project_id, remains=True)
        self.assertEqual(expected_settable_quotas, result)

    @ddt.data((None, None), (None, 'fake_st_id'), ('fake_user_id', None))
    @ddt.unpack
    def test__get_quotas(self, user_id, st_id):
        quotas = {'foo': {'limit': 5}, 'bar': {'limit': 13}}
        self.mock_object(
            self.driver, 'get_project_quotas', mock.Mock(return_value=quotas))
        self.mock_object(
            self.driver, 'get_user_quotas', mock.Mock(return_value=quotas))
        self.mock_object(
            self.driver, 'get_share_type_quotas',
            mock.Mock(return_value=quotas))

        result = self.driver._get_quotas(
            self.ctxt, self.resources, ('foo', 'bar'), False,
            self.project_id, user_id, st_id)

        expected = {k: v['limit'] for k, v in quotas.items()}
        self.assertEqual(expected, result)
        sub_resources = {k: v for k, v in self.resources.items()}
        if user_id:
            self.driver.get_user_quotas.assert_called_once_with(
                self.ctxt, sub_resources, self.project_id, user_id,
                self.ctxt.quota_class, usages=False)
            self.assertEqual(0, self.driver.get_project_quotas.call_count)
            self.assertEqual(0, self.driver.get_share_type_quotas.call_count)
        elif st_id:
            self.driver.get_share_type_quotas.assert_called_once_with(
                self.ctxt, sub_resources, self.project_id, st_id,
                self.ctxt.quota_class, usages=False)
            self.assertEqual(0, self.driver.get_project_quotas.call_count)
            self.assertEqual(0, self.driver.get_user_quotas.call_count)
        else:
            self.driver.get_project_quotas.assert_called_once_with(
                self.ctxt, sub_resources, self.project_id,
                self.ctxt.quota_class, usages=False)
            self.assertEqual(0, self.driver.get_user_quotas.call_count)
            self.assertEqual(0, self.driver.get_share_type_quotas.call_count)

    def test__get_quotas_unknown(self):
        quotas = {'foo': {'limit': 5}, 'bar': {'limit': 13}}
        self.mock_object(
            self.driver, 'get_project_quotas', mock.Mock(return_value=quotas))
        self.mock_object(
            self.driver, 'get_user_quotas', mock.Mock(return_value=quotas))
        self.mock_object(
            self.driver, 'get_share_type_quotas',
            mock.Mock(return_value=quotas))

        self.assertRaises(
            exception.QuotaResourceUnknown,
            self.driver._get_quotas,
            self.ctxt, self.resources, ['foo', 'bar'], True,
            self.project_id, self.user_id, self.share_type_id)

        self.assertEqual(0, self.driver.get_project_quotas.call_count)
        self.assertEqual(0, self.driver.get_user_quotas.call_count)
        self.assertEqual(0, self.driver.get_share_type_quotas.call_count)

    @ddt.data(
        {}, {'project_id': 'fake_project'}, {'user_id': 'fake_user'},
        {'share_type_id': 'fake_share_type_id'},
    )
    def test_reserve(self, kwargs):
        self.mock_object(quota.db, 'quota_reserve')
        deltas = {'delta1': 1, 'delta2': 2}
        quotas, user_quotas, st_quotas = 'fake1', 'fake2', 'fake3'
        self.mock_object(
            self.driver, '_get_quotas', mock.Mock(
                side_effect=[quotas, user_quotas, st_quotas]))

        result = self.driver.reserve(
            self.ctxt, self.resources, deltas, None, **kwargs)

        expected_kwargs = {
            'project_id': self.ctxt.project_id,
            'user_id': self.ctxt.user_id,
            'share_type_id': None,
        }
        expected_kwargs.update(kwargs)
        st_quotas = st_quotas if kwargs.get('share_type_id') else {}
        self.assertEqual(quota.db.quota_reserve.return_value, result)
        quota.db.quota_reserve.assert_called_once_with(
            self.ctxt, self.resources, quotas, user_quotas, st_quotas,
            deltas, mock.ANY, CONF.until_refresh, CONF.max_age,
            **expected_kwargs)
        self.assertEqual(
            3 if kwargs.get('share_type_id') else 2,
            self.driver._get_quotas.call_count)

    def test_reserve_wrong_expire(self):
        self.assertRaises(
            exception.InvalidReservationExpiration,
            self.driver.reserve,
            self.ctxt, self.resources, 'fake_deltas', 'fake_expire')

    def test_commit(self):
        self.mock_object(quota.db, 'reservation_commit')

        result = self.driver.commit(
            self.ctxt, self.reservations, self.project_id, self.user_id,
            self.share_type_id)

        self.assertIsNone(result)
        quota.db.reservation_commit.assert_called_once_with(
            self.ctxt, self.reservations, project_id=self.project_id,
            user_id=self.user_id, share_type_id=self.share_type_id)

    @ddt.data(
        (None, None),
        ('fake_project_id', 'fake_user_id'),
    )
    @ddt.unpack
    def test_rollback(self, project_id, user_id):
        self.mock_object(quota.db, 'reservation_rollback')

        result = self.driver.rollback(
            self.ctxt, self.reservations, project_id, user_id,
            self.share_type_id)

        expected_project_id = project_id or self.ctxt.project_id
        expected_user_id = user_id or self.ctxt.user_id
        self.assertIsNone(result)
        quota.db.reservation_rollback.assert_called_once_with(
            self.ctxt, self.reservations, project_id=expected_project_id,
            user_id=expected_user_id, share_type_id=self.share_type_id)

    def test_usage_reset(self):
        self.mock_object(
            quota.db, 'quota_usage_update',
            mock.Mock(side_effect=[
                'foo',
                exception.QuotaUsageNotFound(project_id=self.project_id)]))

        result = self.driver.usage_reset(self.ctxt, ['foo', 'bar'])

        self.assertIsNone(result)
        quota.db.quota_usage_update.assert_has_calls([
            mock.call(
                self.ctxt.elevated.return_value, self.ctxt.project_id,
                self.ctxt.user_id, res, in_use=-1)
            for res in ('foo', 'bar')
        ])

    def test_destroy_all_by_project(self):
        self.mock_object(quota.db, 'quota_destroy_all_by_project')

        result = self.driver.destroy_all_by_project(self.ctxt, self.project_id)

        self.assertIsNone(result)
        quota.db.quota_destroy_all_by_project.assert_called_once_with(
            self.ctxt, self.project_id)

    def test_destroy_all_by_project_and_user(self):
        self.mock_object(quota.db, 'quota_destroy_all_by_project_and_user')

        result = self.driver.destroy_all_by_project_and_user(
            self.ctxt, self.project_id, self.user_id)

        self.assertIsNone(result)
        quota.db.quota_destroy_all_by_project_and_user.assert_called_once_with(
            self.ctxt, self.project_id, self.user_id)

    def test_destroy_all_by_project_and_share_type(self):
        mock_destroy_all = self.mock_object(
            quota.db, 'quota_destroy_all_by_share_type')

        result = self.driver.destroy_all_by_project_and_share_type(
            self.ctxt, self.project_id, self.share_type_id)

        self.assertIsNone(result)
        mock_destroy_all.assert_called_once_with(
            self.ctxt, self.share_type_id, project_id=self.project_id)

    def test_expire(self):
        self.mock_object(quota.db, 'reservation_expire')

        result = self.driver.expire(self.ctxt)

        self.assertIsNone(result)
        quota.db.reservation_expire.assert_called_once_with(self.ctxt)


@ddt.ddt
class QuotaEngineTestCase(test.TestCase):

    def setUp(self):
        super(self.__class__, self).setUp()
        self.ctxt = 'fake_context'
        self.mock_class('manila.quota.DbQuotaDriver')
        self.engine = quota.QuotaEngine()
        self.driver = self.engine._driver
        self.resources = [quota.BaseResource('foo'), quota.BaseResource('bar')]
        self.project_id = 'fake_project_id'
        self.user_id = 'fake_user_id'
        self.share_type_id = 'fake_share_type_id'
        self.quota_class = 'fake_quota_class'

    def test_register_resource(self):
        self.assertNotIn(self.resources[0].name, self.engine)
        self.engine.register_resource(self.resources[0])
        self.assertIn(self.resources[0].name, self.engine)

    def test_register_resources(self):
        for res in self.resources:
            self.assertNotIn(res.name, self.engine)
        self.engine.register_resources(self.resources)
        for res in self.resources:
            self.assertIn(res.name, self.engine)

    def test_get_by_class(self):
        result = self.engine.get_by_class(
            self.ctxt, self.quota_class, 'fake_res')

        self.assertEqual(result, self.driver.get_by_class.return_value)
        self.driver.get_by_class.assert_called_once_with(
            self.ctxt, self.quota_class, 'fake_res')

    def test_get_defaults(self):
        result = self.engine.get_defaults(self.ctxt)

        self.assertEqual(result, self.driver.get_defaults.return_value)
        self.driver.get_defaults.assert_called_once_with(
            self.ctxt, self.engine._resources)

    @ddt.data(None, True, False)
    def test_get_class_quotas(self, defaults):
        kwargs = {}
        if defaults is not None:
            kwargs['defaults'] = defaults

        result = self.engine.get_class_quotas(
            self.ctxt, self.quota_class, **kwargs)

        self.assertEqual(result, self.driver.get_class_quotas.return_value)
        kwargs['defaults'] = defaults if defaults is not None else True
        self.driver.get_class_quotas.assert_called_once_with(
            self.ctxt, self.engine._resources, self.quota_class, **kwargs)

    @ddt.data(
        {},
        {'quota_class': 'foo'},
        {'defaults': False},
        {'usages': False},
    )
    def test_get_user_quotas(self, kwargs):
        expected_kwargs = {
            'quota_class': None,
            'defaults': True,
            'usages': True,
        }
        expected_kwargs.update(kwargs)

        result = self.engine.get_user_quotas(
            self.ctxt, self.project_id, self.user_id, **kwargs)

        self.assertEqual(result, self.driver.get_user_quotas.return_value)
        self.driver.get_user_quotas.assert_called_once_with(
            self.ctxt, self.engine._resources,
            self.project_id, self.user_id, **expected_kwargs)

    @ddt.data(
        {},
        {'quota_class': 'foo'},
        {'defaults': False},
        {'usages': False},
    )
    def test_get_share_type_quotas(self, kwargs):
        expected_kwargs = {
            'quota_class': None,
            'defaults': True,
            'usages': True,
        }
        expected_kwargs.update(kwargs)

        result = self.engine.get_share_type_quotas(
            self.ctxt, self.project_id, self.share_type_id, **kwargs)

        self.assertEqual(
            result, self.driver.get_share_type_quotas.return_value)
        self.driver.get_share_type_quotas.assert_called_once_with(
            self.ctxt, self.engine._resources,
            self.project_id, self.share_type_id, **expected_kwargs)

    @ddt.data(
        {},
        {'quota_class': 'foo'},
        {'defaults': False},
        {'usages': False},
        {'remains': True},
    )
    def test_get_project_quotas(self, kwargs):
        expected_kwargs = {
            'quota_class': None,
            'defaults': True,
            'usages': True,
            'remains': False,
        }
        expected_kwargs.update(kwargs)

        result = self.engine.get_project_quotas(
            self.ctxt, self.project_id, **kwargs)

        self.assertEqual(result, self.driver.get_project_quotas.return_value)
        self.driver.get_project_quotas.assert_called_once_with(
            self.ctxt, self.engine._resources,
            self.project_id, **expected_kwargs)

    @ddt.data(
        {},
        {'user_id': 'fake_user_id'},
        {'share_type_id': 'fake_share_type_id'},
    )
    def test_get_settable_quotas(self, kwargs):
        expected_kwargs = {'user_id': None, 'share_type_id': None}
        expected_kwargs.update(kwargs)

        result = self.engine.get_settable_quotas(
            self.ctxt, self.project_id, **kwargs)

        self.assertEqual(result, self.driver.get_settable_quotas.return_value)
        self.driver.get_settable_quotas.assert_called_once_with(
            self.ctxt, self.engine._resources,
            self.project_id, **expected_kwargs)

    def test_count(self):
        mock_count = mock.Mock()
        resource = quota.CountableResource('FakeCountableResource', mock_count)
        self.engine.register_resource(resource)

        result = self.engine.count(self.ctxt, resource.name)

        self.assertEqual(mock_count.return_value, result)

    def test_count_unknown_resource(self):
        self.assertRaises(
            exception.QuotaResourceUnknown,
            self.engine.count,
            self.ctxt, 'nonexistent_resource', 'foo_arg', foo='kwarg')

    def test_reserve(self):
        result = self.engine.reserve(
            self.ctxt, 'fake_expire', self.project_id, self.user_id,
            self.share_type_id, delta1=1, delta2=2)

        self.assertEqual(self.driver.reserve.return_value, result)
        self.driver.reserve.assert_called_once_with(
            self.ctxt, self.engine._resources, {'delta1': 1, 'delta2': 2},
            expire='fake_expire', project_id=self.project_id,
            user_id=self.user_id, share_type_id=self.share_type_id)

    @ddt.data(Exception('FakeException'), [None])
    def test_commit(self, side_effect):
        fake_reservations = ['foo', 'bar']
        self.driver.commit.side_effect = side_effect
        self.mock_object(quota.LOG, 'exception')

        result = self.engine.commit(
            self.ctxt, fake_reservations, 'fake_project_id',
            'fake_user_id', 'fake_share_type_id')

        self.assertIsNone(result)
        self.driver.commit.assert_called_once_with(
            self.ctxt, fake_reservations, project_id='fake_project_id',
            user_id='fake_user_id', share_type_id='fake_share_type_id')
        if side_effect == [None]:
            self.assertEqual(0, quota.LOG.exception.call_count)
        else:
            quota.LOG.exception.assert_called_once_with(
                mock.ANY, fake_reservations)

    @ddt.data(Exception('FakeException'), [None])
    def test_rollback(self, side_effect):
        fake_reservations = ['foo', 'bar']
        self.driver.rollback.side_effect = side_effect
        self.mock_object(quota.LOG, 'exception')

        result = self.engine.rollback(
            self.ctxt, fake_reservations, 'fake_project_id',
            'fake_user_id', 'fake_share_type_id')

        self.assertIsNone(result)
        self.driver.rollback.assert_called_once_with(
            self.ctxt, fake_reservations, project_id='fake_project_id',
            user_id='fake_user_id', share_type_id='fake_share_type_id')
        if side_effect == [None]:
            self.assertEqual(0, quota.LOG.exception.call_count)
        else:
            quota.LOG.exception.assert_called_once_with(
                mock.ANY, fake_reservations)

    def test_usage_reset(self):
        result = self.engine.usage_reset(self.ctxt, 'fake_resources')

        self.assertIsNone(result)
        self.driver.usage_reset.assert_called_once_with(
            self.ctxt, 'fake_resources')

    def test_destroy_all_by_project_and_user(self):
        result = self.engine.destroy_all_by_project_and_user(
            self.ctxt, 'fake_project_id', 'fake_user_id')

        self.assertIsNone(result)
        self.driver.destroy_all_by_project_and_user.assert_called_once_with(
            self.ctxt, 'fake_project_id', 'fake_user_id')

    def test_destroy_all_by_project_and_share_type(self):
        result = self.engine.destroy_all_by_project_and_share_type(
            self.ctxt, 'fake_project_id', 'fake_st_id')

        self.assertIsNone(result)
        mock_destroy_all_by_project_and_share_type = (
            self.driver.destroy_all_by_project_and_share_type)
        mock_destroy_all_by_project_and_share_type.assert_called_once_with(
            self.ctxt, 'fake_project_id', 'fake_st_id')

    def test_destroy_all_by_project(self):
        result = self.engine.destroy_all_by_project(
            self.ctxt, 'fake_project_id')

        self.assertIsNone(result)
        self.driver.destroy_all_by_project.assert_called_once_with(
            self.ctxt, 'fake_project_id')

    def test_expire(self):
        result = self.engine.expire(self.ctxt)

        self.assertIsNone(result)
        self.driver.expire.assert_called_once_with(self.ctxt)

    def test_resources(self):
        self.engine.register_resources(self.resources)
        self.assertEqual(['bar', 'foo'], self.engine.resources)

    def test_current_common_resources(self):
        self.assertEqual(
            ['gigabytes', 'share_group_snapshots', 'share_groups',
             'share_networks', 'shares', 'snapshot_gigabytes', 'snapshots'],
            quota.QUOTAS.resources)
