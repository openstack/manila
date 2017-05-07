# Copyright 2015 Mirantis Inc.
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

from manila import context
from manila.share import hook
from manila import test


class FakeHookImplementation(hook.HookBase):
    def _execute_pre_hook(self, context, func_name, *args, **kwargs):
        """Fake implementation of a pre hook action."""

    def _execute_post_hook(self, context, func_name, pre_hook_data,
                           driver_action_results, *args, **kwargs):
        """Fake implementation of a post hook action."""

    def _execute_periodic_hook(self, context, periodic_hook_data,
                               *args, **kwargs):
        """Fake implementation of a periodic hook action."""


@ddt.ddt
class HookBaseTestCase(test.TestCase):

    def setUp(self):
        super(HookBaseTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.default_config = {
            "enable_pre_hooks": True,
            "enable_post_hooks": True,
            "enable_periodic_hooks": True,
            "suppress_pre_hooks_errors": True,
            "suppress_post_hooks_errors": True,
        }
        for k, v in self.default_config.items():
            hook.CONF.set_default(k, v)

    def _fake_safe_get(self, key):
        return self.default_config.get(key)

    def _get_hook_instance(self, set_configuration=True, host="fake_host"):
        if set_configuration:
            configuration = mock.Mock()
            configuration.safe_get.side_effect = self._fake_safe_get
        else:
            configuration = None
        instance = FakeHookImplementation(
            configuration=configuration, host=host)
        return instance

    def test_instantiate_hook_fail(self):
        self.assertRaises(TypeError, hook.HookBase)

    @ddt.data(True, False)
    def test_instantiate_hook_successfully_and_set_configuration(
            self, set_configuration):
        instance = self._get_hook_instance(set_configuration)

        self.assertTrue(hasattr(instance, 'host'))
        self.assertEqual("fake_host", instance.host)
        self.assertTrue(hasattr(instance, 'configuration'))
        if not set_configuration:
            self.assertIsNone(instance.configuration)
        for attr_name in ("pre_hooks_enabled",
                          "post_hooks_enabled",
                          "periodic_hooks_enabled",
                          "suppress_pre_hooks_errors",
                          "suppress_post_hooks_errors"):
            self.assertTrue(hasattr(instance, attr_name))
        if set_configuration:
            instance.configuration.append_config_values.assert_has_calls([
                mock.call(hook.hook_options)])
            conf_func = self._fake_safe_get
        else:
            conf_func = self.default_config.get
        self.assertEqual(
            conf_func("enable_pre_hooks"), instance.pre_hooks_enabled)
        self.assertEqual(
            conf_func("enable_post_hooks"), instance.post_hooks_enabled)
        self.assertEqual(
            conf_func("enable_periodic_hooks"),
            instance.periodic_hooks_enabled)
        self.assertEqual(
            conf_func("suppress_pre_hooks_errors"),
            instance.suppress_pre_hooks_errors)
        self.assertEqual(
            conf_func("suppress_post_hooks_errors"),
            instance.suppress_post_hooks_errors)

    def test_execute_pre_hook_disabled(self):
        instance = self._get_hook_instance()
        instance.pre_hooks_enabled = False
        self.mock_object(
            instance, "_execute_pre_hook",
            mock.Mock(side_effect=Exception("I should not be raised.")))

        result = instance.execute_pre_hook(
            self.context, "fake_func_name", "some_arg", some_kwarg="foo")

        self.assertIsNone(result)

    @ddt.data(True, False)
    def test_execute_pre_hook_success(self, provide_context):
        instance = self._get_hook_instance()
        instance.pre_hooks_enabled = True
        instance.suppress_pre_hooks_errors = True
        expected = "fake_expected_result"
        some_arg = "some_arg"
        func_name = "fake_func_name"
        self.mock_object(hook.LOG, 'error')
        self.mock_object(
            instance, "_execute_pre_hook", mock.Mock(return_value=expected))
        mock_ctxt = self.mock_object(context, 'get_admin_context')
        ctxt = self.context if provide_context else mock_ctxt

        result = instance.execute_pre_hook(
            ctxt, func_name, some_arg, some_kwarg="foo")

        self.assertEqual(expected, result)
        instance._execute_pre_hook.assert_called_once_with(
            some_arg,
            context=self.context if provide_context else mock_ctxt,
            func_name=func_name,
            some_kwarg="foo")
        self.assertFalse(hook.LOG.error.called)

    def test_execute_pre_hook_exception_with_suppression(self):
        instance = self._get_hook_instance()
        instance.pre_hooks_enabled = True
        instance.suppress_pre_hooks_errors = True
        some_arg = "some_arg"
        func_name = "fake_func_name"
        FakeException = type("FakeException", (Exception, ), {})
        self.mock_object(hook.LOG, 'warning')
        self.mock_object(
            instance, "_execute_pre_hook", mock.Mock(side_effect=(
                FakeException("Some exception that should be suppressed."))))

        result = instance.execute_pre_hook(
            self.context, func_name, some_arg, some_kwarg="foo")

        self.assertIsInstance(result, FakeException)
        instance._execute_pre_hook.assert_called_once_with(
            some_arg,
            context=self.context,
            func_name=func_name,
            some_kwarg="foo")
        self.assertTrue(hook.LOG.warning.called)

    def test_execute_pre_hook_exception_without_suppression(self):
        instance = self._get_hook_instance()
        instance.pre_hooks_enabled = True
        instance.suppress_pre_hooks_errors = False
        some_arg = "some_arg"
        func_name = "fake_func_name"
        FakeException = type("FakeException", (Exception, ), {})
        self.mock_object(hook.LOG, 'warning')
        self.mock_object(
            instance, "_execute_pre_hook", mock.Mock(side_effect=(
                FakeException(
                    "Some exception that should NOT be suppressed."))))

        self.assertRaises(
            FakeException,
            instance.execute_pre_hook,
            self.context, func_name, some_arg, some_kwarg="foo")

        instance._execute_pre_hook.assert_called_once_with(
            some_arg,
            context=self.context,
            func_name=func_name,
            some_kwarg="foo")
        self.assertFalse(hook.LOG.warning.called)

    def test_execute_post_hook_disabled(self):
        instance = self._get_hook_instance()
        instance.post_hooks_enabled = False
        self.mock_object(
            instance, "_execute_post_hook",
            mock.Mock(side_effect=Exception("I should not be raised.")))

        result = instance.execute_post_hook(
            self.context, "fake_func_name", "some_pre_hook_data",
            "some_driver_action_results", "some_arg", some_kwarg="foo")

        self.assertIsNone(result)

    @ddt.data(True, False)
    def test_execute_post_hook_success(self, provide_context):
        instance = self._get_hook_instance()
        instance.post_hooks_enabled = True
        instance.suppress_post_hooks_errors = True
        expected = "fake_expected_result"
        some_arg = "some_arg"
        func_name = "fake_func_name"
        pre_hook_data = "some_pre_hook_data"
        driver_action_results = "some_driver_action_results"
        self.mock_object(hook.LOG, 'warning')
        self.mock_object(
            instance, "_execute_post_hook", mock.Mock(return_value=expected))
        mock_ctxt = self.mock_object(context, 'get_admin_context')
        ctxt = self.context if provide_context else mock_ctxt

        result = instance.execute_post_hook(
            ctxt, func_name, pre_hook_data, driver_action_results,
            some_arg, some_kwarg="foo")

        self.assertEqual(expected, result)
        instance._execute_post_hook.assert_called_once_with(
            some_arg,
            context=self.context if provide_context else mock_ctxt,
            func_name=func_name,
            pre_hook_data=pre_hook_data,
            driver_action_results=driver_action_results,
            some_kwarg="foo")
        self.assertFalse(hook.LOG.warning.called)

    def test_execute_post_hook_exception_with_suppression(self):
        instance = self._get_hook_instance()
        instance.post_hooks_enabled = True
        instance.suppress_post_hooks_errors = True
        some_arg = "some_arg"
        func_name = "fake_func_name"
        pre_hook_data = "some_pre_hook_data"
        driver_action_results = "some_driver_action_results"
        FakeException = type("FakeException", (Exception, ), {})
        self.mock_object(hook.LOG, 'warning')
        self.mock_object(
            instance, "_execute_post_hook", mock.Mock(side_effect=(
                FakeException("Some exception that should be suppressed."))))

        result = instance.execute_post_hook(
            self.context, func_name, pre_hook_data, driver_action_results,
            some_arg, some_kwarg="foo")

        self.assertIsInstance(result, FakeException)
        instance._execute_post_hook.assert_called_once_with(
            some_arg,
            context=self.context,
            func_name=func_name,
            pre_hook_data=pre_hook_data,
            driver_action_results=driver_action_results,
            some_kwarg="foo")
        self.assertTrue(hook.LOG.warning.called)

    def test_execute_post_hook_exception_without_suppression(self):
        instance = self._get_hook_instance()
        instance.post_hooks_enabled = True
        instance.suppress_post_hooks_errors = False
        some_arg = "some_arg"
        func_name = "fake_func_name"
        pre_hook_data = "some_pre_hook_data"
        driver_action_results = "some_driver_action_results"
        FakeException = type("FakeException", (Exception, ), {})
        self.mock_object(hook.LOG, 'error')
        self.mock_object(
            instance, "_execute_post_hook", mock.Mock(side_effect=(
                FakeException(
                    "Some exception that should NOT be suppressed."))))

        self.assertRaises(
            FakeException,
            instance.execute_post_hook,
            self.context, func_name, pre_hook_data, driver_action_results,
            some_arg, some_kwarg="foo")

        instance._execute_post_hook.assert_called_once_with(
            some_arg,
            context=self.context,
            func_name=func_name,
            pre_hook_data=pre_hook_data,
            driver_action_results=driver_action_results,
            some_kwarg="foo")
        self.assertFalse(hook.LOG.error.called)

    def test_execute_periodic_hook_disabled(self):
        instance = self._get_hook_instance()
        instance.periodic_hooks_enabled = False
        self.mock_object(instance, "_execute_periodic_hook")

        instance.execute_periodic_hook(
            self.context, "fake_periodic_hook_data",
            "some_arg", some_kwarg="foo")

        self.assertFalse(instance._execute_periodic_hook.called)

    @ddt.data(True, False)
    def test_execute_periodic_hook_enabled(self, provide_context):
        instance = self._get_hook_instance()
        instance.periodic_hooks_enabled = True
        expected = "some_expected_result"
        self.mock_object(
            instance,
            "_execute_periodic_hook",
            mock.Mock(return_value=expected))
        mock_ctxt = self.mock_object(context, 'get_admin_context')
        ctxt = self.context if provide_context else mock_ctxt

        result = instance.execute_periodic_hook(
            ctxt, "fake_periodic_hook_data",
            "some_arg", some_kwarg="foo")

        instance._execute_periodic_hook.assert_called_once_with(
            ctxt, "fake_periodic_hook_data",
            "some_arg", some_kwarg="foo")
        self.assertEqual(expected, result)
