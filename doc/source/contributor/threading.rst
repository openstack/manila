Threading model
===============

Manila uses Python's native threading for concurrency. All services
(``manila-share``, ``manila-scheduler``, ``manila-data``) run under
oslo.service's threading backend.

The ``manila-api`` service should be deployed behind an external WSGI
server such as uWSGI, gunicorn, or Apache mod_wsgi. The built-in
eventlet-based WSGI server is deprecated. See :doc:`apache-httpd` for
deployment examples.

Use ``time.sleep()`` and ``threading`` primitives from the standard
library. The ``@utils.synchronized(...)`` decorator is available for
protecting critical sections against races.

Legacy eventlet backend
-----------------------
The eventlet concurrency backend is deprecated and will be removed in a
future release. If you need to force it for testing, set the environment
variable before starting each service::

    export OS_MANILA_DISABLE_EVENTLET_PATCHING=False

Unset the variable (or leave it unset) to use the default native
threading backend.
