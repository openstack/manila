# Copyright 2011 Piston Cloud Computing, Inc.
# All Rights Reserved.

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

"""Test of Policy Engine For Manila."""

from oslo_config import cfg
from oslo_policy import policy as common_policy

from manila import context
from manila import exception
from manila import policy
from manila import test

CONF = cfg.CONF


class PolicyTestCase(test.TestCase):
    def setUp(self):
        super(PolicyTestCase, self).setUp()
        rules = [
            common_policy.RuleDefault("true", '@'),
            common_policy.RuleDefault("test:allowed", '@'),
            common_policy.RuleDefault("test:denied", "!"),
            common_policy.RuleDefault("test:my_file",
                                      "role:compute_admin or "
                                      "project_id:%(project_id)s"),
            common_policy.RuleDefault("test:early_and_fail", "! and @"),
            common_policy.RuleDefault("test:early_or_success", "@ or !"),
            common_policy.RuleDefault("test:lowercase_admin",
                                      "role:admin"),
            common_policy.RuleDefault("test:uppercase_admin",
                                      "role:ADMIN"),
        ]
        policy.reset()
        policy.init()
        # before a policy rule can be used, its default has to be registered.
        policy._ENFORCER.register_defaults(rules)
        self.context = context.RequestContext('fake', 'fake', roles=['member'])
        self.target = {}
        self.addCleanup(policy.reset)

    def test_authorize_nonexistent_action_throws(self):
        action = "test:noexist"
        self.assertRaises(common_policy.PolicyNotRegistered, policy.authorize,
                          self.context, action, self.target)

    def test_authorize_bad_action_throws(self):
        action = "test:denied"
        self.assertRaises(exception.PolicyNotAuthorized, policy.authorize,
                          self.context, action, self.target)

    def test_authorize_bad_action_noraise(self):
        action = "test:denied"
        result = policy.authorize(self.context, action, self.target, False)
        self.assertFalse(result)

    def test_authorize_good_action(self):
        action = "test:allowed"
        result = policy.authorize(self.context, action, self.target)
        self.assertTrue(result)

    def test_templatized_authorization(self):
        target_mine = {'project_id': 'fake'}
        target_not_mine = {'project_id': 'another'}
        action = "test:my_file"
        policy.authorize(self.context, action, target_mine)
        self.assertRaises(exception.PolicyNotAuthorized, policy.authorize,
                          self.context, action, target_not_mine)

    def test_early_AND_authorization(self):
        action = "test:early_and_fail"
        self.assertRaises(exception.PolicyNotAuthorized, policy.authorize,
                          self.context, action, self.target)

    def test_early_OR_authorization(self):
        action = "test:early_or_success"
        policy.authorize(self.context, action, self.target)

    def test_ignore_case_role_check(self):
        lowercase_action = "test:lowercase_admin"
        uppercase_action = "test:uppercase_admin"
        admin_context = context.RequestContext('admin',
                                               'fake',
                                               roles=['AdMiN'])
        policy.authorize(admin_context, lowercase_action, self.target)
        policy.authorize(admin_context, uppercase_action, self.target)


class DefaultPolicyTestCase(test.TestCase):

    def setUp(self):
        super(DefaultPolicyTestCase, self).setUp()
        policy.reset()
        policy.init()

        self.rules = {
            "default": [],
            "example:exist": "false:false"
        }
        self._set_rules('default')
        self.context = context.RequestContext('fake', 'fake')

    def tearDown(self):
        super(DefaultPolicyTestCase, self).tearDown()
        policy.reset()

    def _set_rules(self, default_rule):
        these_rules = common_policy.Rules.from_dict(self.rules,
                                                    default_rule=default_rule)
        policy._ENFORCER.set_rules(these_rules)

    def test_policy_called(self):
        self.assertRaises(exception.PolicyNotAuthorized, policy.enforce,
                          self.context, "example:exist", {})

    def test_not_found_policy_calls_default(self):
        policy.enforce(self.context, "example:noexist", {})

    def test_default_not_found(self):
        new_default_rule = "default_noexist"
        # FIXME(gyee): need to overwrite the Enforcer's default_rule first
        # as it is recreating the rules with its own default_rule instead
        # of the default_rule passed in from set_rules(). I think this is a
        # bug in Oslo policy.
        policy._ENFORCER.default_rule = new_default_rule
        self._set_rules(new_default_rule)
        self.assertRaises(exception.PolicyNotAuthorized, policy.enforce,
                          self.context, "example:noexist", {})


class ContextIsAdminPolicyTestCase(test.TestCase):

    def setUp(self):
        super(ContextIsAdminPolicyTestCase, self).setUp()
        policy.reset()
        policy.init()

    def _set_rules(self, rules, default_rule):
        these_rules = common_policy.Rules.from_dict(rules,
                                                    default_rule=default_rule)
        policy._ENFORCER.set_rules(these_rules)

    def test_default_admin_role_is_admin(self):
        ctx = context.RequestContext('fake', 'fake', roles=['johnny-admin'])
        self.assertFalse(ctx.is_admin)
        ctx = context.RequestContext('fake', 'fake', roles=['admin'])
        self.assertTrue(ctx.is_admin)

    def test_custom_admin_role_is_admin(self):
        # define explicit rules for context_is_admin
        rules = {
            'context_is_admin': [["role:administrator"], ["role:johnny-admin"]]
        }
        self._set_rules(rules, CONF.oslo_policy.policy_default_rule)
        ctx = context.RequestContext('fake', 'fake', roles=['johnny-admin'])
        self.assertTrue(ctx.is_admin)
        ctx = context.RequestContext('fake', 'fake', roles=['administrator'])
        self.assertTrue(ctx.is_admin)
        # default rule no longer applies
        ctx = context.RequestContext('fake', 'fake', roles=['admin'])
        self.assertFalse(ctx.is_admin)

    def test_context_is_admin_undefined(self):
        rules = {
            "admin_or_owner": "role:admin or project_id:%(project_id)s",
            "default": "rule:admin_or_owner",
        }
        self._set_rules(rules, CONF.oslo_policy.policy_default_rule)
        ctx = context.RequestContext('fake', 'fake')
        self.assertTrue(ctx.is_admin)
        ctx = context.RequestContext('fake', 'fake', roles=['admin'])
        self.assertTrue(ctx.is_admin)
