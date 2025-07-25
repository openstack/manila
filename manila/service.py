# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Justin Santa Barbara
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

"""Generic Node base class for all workers that run on hosts."""

import inspect
import os
import random

from oslo_config import cfg
from oslo_log import log
import oslo_messaging as messaging
from oslo_service import service
from oslo_service import wsgi
from oslo_utils import importutils

from manila import context
from manila import coordination
from manila import db
from manila import exception
from manila import rpc
from manila import utils
from manila import version

osprofiler_initializer = importutils.try_import('osprofiler.initializer')
profiler = importutils.try_import('osprofiler.profiler')
profiler_opts = importutils.try_import('osprofiler.opts')

LOG = log.getLogger(__name__)

service_opts = [
    cfg.IntOpt('report_interval',
               default=10,
               help='Seconds between nodes reporting state to datastore.'),
    cfg.IntOpt('cleanup_interval',
               min=300,
               default=1800,
               help='Seconds between cleaning up the stopped nodes.'),
    cfg.IntOpt('periodic_interval',
               default=60,
               help='Seconds between running periodic tasks.'),
    cfg.IntOpt('periodic_fuzzy_delay',
               default=60,
               help='Range of seconds to randomly delay when starting the '
                    'periodic task scheduler to reduce stampeding. '
                    '(Disable by setting to 0)'),
    cfg.HostAddressOpt('osapi_share_listen',
                       default="::",
                       help='IP address for OpenStack Share API to listen '
                            'on.'),
    cfg.PortOpt('osapi_share_listen_port',
                default=8786,
                help='Port for OpenStack Share API to listen on.'),
    cfg.IntOpt('osapi_share_workers',
               default=1,
               help='Number of workers for OpenStack Share API service.'),
    cfg.BoolOpt('osapi_share_use_ssl',
                default=False,
                help='Wraps the socket in a SSL context if True is set. '
                     'A certificate file and key file must be specified.'),
]

CONF = cfg.CONF
CONF.register_opts(service_opts)
if profiler_opts:
    profiler_opts.set_defaults(CONF)


def setup_profiler(binary, host):
    if (osprofiler_initializer is None or
            profiler is None or
            profiler_opts is None):
        LOG.debug('osprofiler is not present')
        return

    if CONF.profiler.enabled:
        osprofiler_initializer.init_from_conf(
            conf=CONF,
            context=context.get_admin_context().to_dict(),
            project="manila",
            service=binary,
            host=host
        )
        LOG.warning("OSProfiler is enabled.")


class Service(service.Service):
    """Service object for binaries running on hosts.

    A service takes a manager and enables rpc by listening to queues based
    on topic. It also periodically runs tasks on the manager and reports
    it state to the database services table.
    """

    def __init__(self, host, binary, topic, manager, report_interval=None,
                 periodic_interval=None, periodic_fuzzy_delay=None,
                 service_name=None, coordination=False, *args, **kwargs):
        super(Service, self).__init__()
        if not rpc.initialized():
            rpc.init(CONF)
        self.host = host
        self.binary = binary
        self.topic = topic
        self.manager_class_name = manager
        manager_class = importutils.import_class(self.manager_class_name)
        if CONF.profiler.enabled and profiler is not None:
            manager_class = profiler.trace_cls("rpc")(manager_class)

        self.service = None
        self.manager = manager_class(host=self.host,
                                     service_name=service_name,
                                     *args, **kwargs)
        self.availability_zone = self.manager.availability_zone
        self.report_interval = report_interval
        self.cleanup_interval = CONF.cleanup_interval
        self.periodic_interval = periodic_interval
        self.periodic_fuzzy_delay = periodic_fuzzy_delay
        self.saved_args, self.saved_kwargs = args, kwargs
        self.coordinator = coordination

        self.rpcserver = None

    def start(self):
        version_string = version.version_string()
        LOG.info('Starting %(topic)s node (version %(version_string)s)',
                 {'topic': self.topic, 'version_string': version_string})
        self.model_disconnected = False
        ctxt = context.get_admin_context()
        setup_profiler(self.binary, self.host)

        try:
            service_ref = db.service_get_by_args(ctxt,
                                                 self.host,
                                                 self.binary)
            self.service_id = service_ref['id']
            db.service_update(ctxt, self.service_id, {'state': 'down'})
        except exception.NotFound:
            self._create_service_ref(ctxt)

        self.manager.init_host(service_id=self.service_id)

        if self.coordinator:
            coordination.LOCK_COORDINATOR.start()

        LOG.debug("Creating RPC server for service %s.", self.topic)

        target = messaging.Target(topic=self.topic, server=self.host)
        endpoints = [self.manager]
        endpoints.extend(self.manager.additional_endpoints)
        self.rpcserver = rpc.get_server(target, endpoints)
        self.rpcserver.start()

        self.manager.init_host_with_rpc()

        if self.report_interval:
            self.tg.add_timer(self.report_interval, self.report_state,
                              initial_delay=self.report_interval)

        self.tg.add_timer(self.cleanup_interval, self.cleanup_services,
                          initial_delay=self.cleanup_interval)

        if self.periodic_interval:
            if self.periodic_fuzzy_delay:
                initial_delay = random.randint(0, self.periodic_fuzzy_delay)
            else:
                initial_delay = None

            self.tg.add_timer(self.periodic_interval, self.periodic_tasks,
                              initial_delay=initial_delay)

    def _create_service_ref(self, context):
        service_args = {
            'host': self.host,
            'binary': self.binary,
            'topic': self.topic,
            'state': 'up',
            'report_count': 0,
            'availability_zone': self.availability_zone
        }
        service_ref = db.service_create(context, service_args)
        self.service_id = service_ref['id']

    def __getattr__(self, key):
        manager = self.__dict__.get('manager', None)
        return getattr(manager, key)

    @classmethod
    def create(cls, host=None, binary=None, topic=None, manager=None,
               report_interval=None, periodic_interval=None,
               periodic_fuzzy_delay=None, service_name=None,
               coordination=False):
        """Instantiates class and passes back application object.

        :param host: defaults to CONF.host
        :param binary: defaults to basename of executable
        :param topic: defaults to bin_name - 'manila-' part
        :param manager: defaults to CONF.<topic>_manager
        :param report_interval: defaults to CONF.report_interval
        :param periodic_interval: defaults to CONF.periodic_interval
        :param periodic_fuzzy_delay: defaults to CONF.periodic_fuzzy_delay

        """
        if not host:
            host = CONF.host
        if not binary:
            binary = os.path.basename(inspect.stack()[-1][1])
        if not topic:
            topic = binary
        if not manager:
            subtopic = topic.rpartition('manila-')[2]
            manager = CONF.get('%s_manager' % subtopic, None)
        if report_interval is None:
            report_interval = CONF.report_interval
        if periodic_interval is None:
            periodic_interval = CONF.periodic_interval
        if periodic_fuzzy_delay is None:
            periodic_fuzzy_delay = CONF.periodic_fuzzy_delay
        service_obj = cls(host, binary, topic, manager,
                          report_interval=report_interval,
                          periodic_interval=periodic_interval,
                          periodic_fuzzy_delay=periodic_fuzzy_delay,
                          service_name=service_name,
                          coordination=coordination)

        return service_obj

    def kill(self):
        """Destroy the service object in the datastore."""
        self.stop()
        try:
            db.service_destroy(context.get_admin_context(), self.service_id)
        except exception.NotFound:
            LOG.warning('Service killed that has no database entry.')

    def stop(self):
        # Try to shut the connection down, but if we get any sort of
        # errors, go ahead and ignore them.. as we're shutting down anyway
        try:
            self.rpcserver.stop()
        except Exception:
            pass

        try:
            db.service_update(context.get_admin_context(),
                              self.service_id, {'state': 'stopped'})
        except exception.NotFound:
            LOG.warning('Service stopped that has no database entry.')

        if self.coordinator:
            try:
                coordination.LOCK_COORDINATOR.stop()
            except Exception:
                LOG.exception("Unable to stop the Tooz Locking "
                              "Coordinator.")

        super(Service, self).stop(graceful=True)

    def wait(self):
        if self.rpcserver:
            self.rpcserver.wait()
        super(Service, self).wait()

    def periodic_tasks(self, raise_on_error=False):
        """Tasks to be run at a periodic interval."""
        ctxt = context.get_admin_context()
        self.manager.periodic_tasks(ctxt, raise_on_error=raise_on_error)

    def report_state(self):
        """Update the state of this service in the datastore."""
        if not self.manager.is_service_ready():
            # NOTE(haixin): If the service is still initializing or failed to
            #               intialize.
            LOG.error('Manager for service %s is not ready yet, skipping state'
                      ' update routine. Service will appear "down".',
                      self.binary)
            return

        ctxt = context.get_admin_context()
        state_catalog = {}
        try:
            try:
                service_ref = db.service_get(ctxt, self.service_id)
            except exception.NotFound:
                LOG.debug('The service database object disappeared, '
                          'Recreating it.')
                self._create_service_ref(ctxt)
                service_ref = db.service_get(ctxt, self.service_id)

            state_catalog['report_count'] = service_ref['report_count'] + 1
            if (self.availability_zone !=
                    service_ref['availability_zone']['name']):
                state_catalog['availability_zone'] = self.availability_zone

            if utils.service_is_up(service_ref):
                state_catalog['state'] = 'up'
            else:
                if service_ref['state'] != 'stopped':
                    state_catalog['state'] = 'down'
            db.service_update(ctxt, self.service_id, state_catalog)

            # TODO(termie): make this pattern be more elegant.
            if getattr(self, 'model_disconnected', False):
                self.model_disconnected = False
                LOG.error('Recovered model server connection!')

        # TODO(vish): this should probably only catch connection errors
        except Exception:  # pylint: disable=W0702
            if not getattr(self, 'model_disconnected', False):
                self.model_disconnected = True
                LOG.exception('model server went away')

    def cleanup_services(self):
        """Remove the stopped services of same topic from the datastore."""
        ctxt = context.get_admin_context()
        try:
            services = db.service_get_all_by_topic(ctxt, self.topic)
        except exception.NotFound:
            LOG.debug('The service database object disappeared,'
                      'Exiting from cleanup.')
            return

        for svc in services:
            if (svc['state'] == 'stopped' and
                    not utils.service_is_up(svc)):
                db.service_destroy(ctxt, svc['id'])


class WSGIService(service.ServiceBase):
    """Provides ability to launch API from a 'paste' configuration."""

    def __init__(self, name, loader=None):
        """Initialize, but do not start the WSGI server.

        :param name: The name of the WSGI server given to the loader.
        :param loader: Loads the WSGI application using the given name.
        :returns: None

        """
        self.name = name
        self.manager = self._get_manager()
        self.loader = loader or wsgi.Loader(CONF)
        if not rpc.initialized():
            rpc.init(CONF)
        self.app = self.loader.load_app(name)
        self.host = getattr(CONF, '%s_listen' % name, "0.0.0.0")  # nosec B104
        self.port = getattr(CONF, '%s_listen_port' % name, 0)
        self.workers = getattr(CONF, '%s_workers' % name, None)
        self.use_ssl = getattr(CONF, '%s_use_ssl' % name, False)
        if self.workers is not None and self.workers < 1:
            LOG.warning(
                "Value of config option %(name)s_workers must be integer "
                "greater than 1.  Input value ignored.", {'name': name})
            # Reset workers to default
            self.workers = None

        self.server = wsgi.Server(
            CONF,
            name,
            self.app,
            host=self.host,
            port=self.port,
            use_ssl=self.use_ssl
        )

    def _get_manager(self):
        """Initialize a Manager object appropriate for this service.

        Use the service name to look up a Manager subclass from the
        configuration and initialize an instance. If no class name
        is configured, just return None.

        :returns: a Manager instance, or None.

        """
        fl = '%s_manager' % self.name
        if fl not in CONF:
            return None

        manager_class_name = CONF.get(fl, None)
        if not manager_class_name:
            return None

        manager_class = importutils.import_class(manager_class_name)
        return manager_class()

    def start(self):
        """Start serving this service using loaded configuration.

        Also, retrieve updated port number in case '0' was passed in, which
        indicates a random port should be used.

        :returns: None

        """
        setup_profiler(self.name, self.host)
        if self.manager:
            self.manager.init_host()
        self.server.start()
        self.port = self.server.port

    def stop(self):
        """Stop serving this API.

        :returns: None

        """
        self.server.stop()

    def wait(self):
        """Wait for the service to stop serving this API.

        :returns: None

        """
        self.server.wait()

    def reset(self):
        """Reset server greenpool size to default.

        :returns: None
        """
        self.server.reset()


def process_launcher():
    return service.ProcessLauncher(CONF, restart_method='mutate')


# NOTE(vish): the global launcher is to maintain the existing
#             functionality of calling service.serve +
#             service.wait
_launcher = None


def serve(server, workers=None):
    global _launcher
    if _launcher:
        raise RuntimeError('serve() can only be called once')
    _launcher = service.launch(CONF, server, workers=workers,
                               restart_method='mutate')


def wait():
    CONF.log_opt_values(LOG, log.DEBUG)
    try:
        _launcher.wait()
    except KeyboardInterrupt:
        _launcher.stop()
    rpc.cleanup()
