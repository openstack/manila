# Copyright 2026 Red Hat, LLC.
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

"""Enable eventlet monkey patching."""

"""This approach is based on Nova's monkey_patch.py and adapted for Manila."""

import os

MONKEY_PATCHED = False


def is_patched():
    return MONKEY_PATCHED


def _monkey_patch():
    if is_patched():
        return False

    # NOTE(mdbooth): Anything imported here will not be monkey patched. It is
    # important to take care not to import anything here which requires monkey
    # patching.
    # NOTE(artom) eventlet processes environment variables at import-time.
    # as such any eventlet configuration should happen here if needed.
    import eventlet
    eventlet.monkey_patch()

    return True


def patch(backend='eventlet'):
    """Apply eventlet monkey patching according to environment.

    :param backend: Defines the default backend if not explicitly set via
        the environment. If 'eventlet', then monkey patch if environment
        variable is not defined. If 'threading', then do not monkey patch if
        environment variable is not defined. Any other value results in a
        ValueError. If the environment variable is defined this parameter
        is ignored.
    """
    if backend not in ('eventlet', 'threading'):
        raise ValueError(
            "the backend can only be 'eventlet' or 'threading'")

    env = os.environ.get('OS_MANILA_DISABLE_EVENTLET_PATCHING', '').lower()
    if env == '':
        should_patch = (backend == 'eventlet')
    elif env in ('1', 'true', 'yes'):
        should_patch = False
    else:
        should_patch = True

    if should_patch:
        if _monkey_patch():
            global MONKEY_PATCHED
            MONKEY_PATCHED = True

            import oslo_service.backend as service
            service.init_backend(service.BackendType.EVENTLET)
            from oslo_log import log as logging
            LOG = logging.getLogger(__name__)
            LOG.info("Service is starting with Eventlet based service backend")
    else:
        # We asked not to monkey patch so we will run in native threading mode
        # NOTE(gibi): This will raise if the backend is already initialized
        # with Eventlet
        import oslo_service.backend as service
        service.init_backend(service.BackendType.THREADING)

        # NOTE(gibi): We were asked not to monkey patch. Let's enforce it by
        # removing the possibility to monkey_patch accidentally
        poison_eventlet()

        from oslo_log import log as logging
        LOG = logging.getLogger(__name__)
        LOG.warning(
            "Service is starting with native threading. This is currently "
            "experimental. Do not use it in production without first "
            "testing it in pre-production.")


def _poison(*args, **kwargs):
    raise RuntimeError(
        "The service is started with native threading via "
        "OS_MANILA_DISABLE_EVENTLET_PATCHING set to '%s', but then the "
        "service tried to call eventlet.monkey_patch(). This is a bug."
        % os.environ.get('OS_MANILA_DISABLE_EVENTLET_PATCHING', ''))


def poison_eventlet():
    import eventlet
    eventlet.monkey_patch = _poison
    eventlet.patcher.monkey_patch = _poison
