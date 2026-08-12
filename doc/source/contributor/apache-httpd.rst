====================================
Deploying the manila API
====================================

The ``manila-api`` service must be deployed behind an external WSGI
server. The WSGI application entry point is
``manila.wsgi.api:application``.

This page describes three deployment options. All three expect
Manila's configuration file at ``/etc/manila/manila.conf`` and the
PasteDeploy pipeline at ``/etc/manila/api-paste.ini``.

.. contents::
   :local:

Gunicorn
--------

`Gunicorn <https://gunicorn.org/>`_ is a pure-Python WSGI HTTP server
with a pre-fork worker model. It requires no additional system packages
or Apache modules.

Install gunicorn into the Manila virtualenv::

    pip install gunicorn

Create ``/etc/manila/gunicorn.conf.py``:

.. code-block:: python

    bind = "127.0.0.1:8786"
    workers = 4
    threads = 1
    timeout = 90
    graceful_timeout = 90
    accesslog = "-"
    errorlog = "-"

Start the service::

    gunicorn manila.wsgi.api:application \
        --config /etc/manila/gunicorn.conf.py

To run behind Apache as a reverse proxy, bind gunicorn to a unix socket
or a local port and use ``mod_proxy_http``::

    ProxyPass "/share" "http://127.0.0.1:8786" retry=0

Gunicorn supports ``SIGHUP`` for graceful config reload and ``SIGTERM``
for graceful shutdown.

uWSGI behind Apache (mod_proxy)
-------------------------------

`uWSGI <https://uwsgi-docs.readthedocs.io/>`_ is a C-based
application server. This setup binds uWSGI to a unix socket and uses
Apache with ``mod_proxy_uwsgi`` to route incoming requests.

Install uWSGI:

On RHEL/CentOS/Fedora::

    sudo dnf install uwsgi uwsgi-plugin-python3

On Ubuntu/Debian::

    sudo apt-get install uwsgi uwsgi-plugin-python3

Copy ``httpd/manila-uwsgi.ini`` to ``/etc/manila/`` and adjust the
number of processes to match your hardware:

.. code-block:: ini

    [uwsgi]
    module = manila.wsgi.api:application
    processes = 4
    master = true
    enable-threads = true
    socket = /var/run/uwsgi/manila.socket
    chmod-socket = 666
    lazy-apps = true
    thunder-lock = true
    buffer-size = 65535
    die-on-term = true
    add-header = Connection: close

Copy ``httpd/uwsgi-manila.conf`` to the Apache configuration
directory:

On RHEL/CentOS/Fedora::

    /etc/httpd/conf.d/uwsgi-manila.conf

On Ubuntu/Debian::

    /etc/apache2/sites-available/uwsgi-manila.conf

Enable ``mod_proxy`` (on Ubuntu/Debian, run ``sudo a2enmod proxy``),
enable the site (``sudo a2ensite uwsgi-manila``), and restart Apache.

Start uWSGI::

    uwsgi --ini /etc/manila/manila-uwsgi.ini

Apache mod_wsgi
---------------

``mod_wsgi`` embeds a Python interpreter directly inside the Apache
process. No separate application server is needed. This option uses
more memory per Apache worker but has the simplest process topology.

Copy ``httpd/mod_wsgi-manila.conf`` to the Apache configuration
directory:

On RHEL/CentOS/Fedora::

    /etc/httpd/conf.d/mod_wsgi-manila.conf

On Ubuntu/Debian::

    /etc/apache2/sites-available/mod_wsgi-manila.conf

The sample configuration creates a ``WSGIDaemonProcess`` with two
processes and one thread each. Adjust to match your workload:

.. code-block:: apache

    Listen 8786
    <VirtualHost *:8786>
        WSGIDaemonProcess osapi_share processes=4 threads=1 \
            user=manila display-name=%{GROUP}
        WSGIProcessGroup osapi_share
        WSGIScriptAlias / /var/www/cgi-bin/manila/osapi_share
        WSGIApplicationGroup %{GLOBAL}
        WSGIPassAuthorization On
        ErrorLogFormat "%{cu}t %M"
        ErrorLog /var/log/httpd/manila_error.log
        CustomLog /var/log/httpd/manila_access.log combined
    </VirtualHost>

Enable the site and restart Apache.

.. NOTE::

   ``/etc/manila/manila.conf`` and ``/etc/manila/api-paste.ini`` must
   be readable by the user specified in ``WSGIDaemonProcess``.

Choosing a server
-----------------

All three options produce the same functional result. The differences
are operational:

- **Gunicorn** is the simplest to set up (one pip install, one process,
  no Apache dependency). Good for containerized deployments and
  environments that do not already run Apache.

- **uWSGI + Apache** is the configuration used in OpenStack CI (via
  devstack). It gives Apache control over TLS termination and request
  routing while uWSGI manages the Python workers. Preferred when
  Apache already serves other OpenStack APIs on the same host.

- **mod_wsgi** has the fewest moving parts at runtime (just Apache) but
  ties the Python interpreter lifetime to Apache. Restarting Manila
  requires restarting Apache, which may affect other services.

Access control
--------------

If you are running with a Linux kernel security module (SELinux or
AppArmor), ensure that the configuration files and the WSGI application
module have the appropriate context for the web server to access them.
