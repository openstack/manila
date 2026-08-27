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

"""Service concurrency backend selection."""

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


def patch(backend='threading'):
    """Select the service concurrency backend.

    :param backend: Defines the default backend if not explicitly set via
        the environment. If 'threading', use native threads when the
        environment variable is not defined. If 'eventlet', monkey patch
        when the environment variable is not defined. Any other value
        results in a ValueError. If the environment variable is defined
        this parameter is ignored.
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

    import oslo_service.backend as service
    from oslo_service.backend.exceptions import BackendAlreadySelected

    if should_patch:
        if _monkey_patch():
            global MONKEY_PATCHED
            MONKEY_PATCHED = True

            try:
                service.init_backend(service.BackendType.EVENTLET)
            except BackendAlreadySelected:
                pass
            from oslo_log import log as logging
            LOG = logging.getLogger(__name__)
            LOG.warning(
                "Service is starting with the eventlet backend. Eventlet "
                "is deprecated and will be removed in the next release. "
                "Unset OS_MANILA_DISABLE_EVENTLET_PATCHING to use the "
                "native threading backend.")
    else:
        try:
            service.init_backend(service.BackendType.THREADING)
        except BackendAlreadySelected:
            pass

        poison_eventlet()

        from oslo_log import log as logging
        LOG = logging.getLogger(__name__)
        LOG.info("Service is starting with the native threading backend.")


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
