====================================
Running manila API with a web server
====================================

As part of the `community goals for Pike`_, manila has packaged
a wsgi script entrypoint that allows you to run it with a real web server
like Apache HTTPD or NGINX.

This doc shows a sample of deploying manila with uwsgi

Installing the API via uwsgi
-----------------------------

For this deployment we use uwsgi as a web server bound to a random
local port. Then we configure apache using mod_proxy to forward all incoming
requests on the specified endpoint to that local webserver. This has the
advantage of letting apache manage all inbound http connections, but allowing
uwsgi run the python code. This also means that when we make
changes to manila code or configuration we don't need to restart all of apache
(which may be running other services as well) and just need to restart the local
uwsgi daemon.

The httpd/ directory contains sample files for configuring HTTPD to run manila
under uwsgi. To use sample configs, simply copy `httpd/uwsgi-manila.conf` to the
appropiate location for your apache server.

On RHEL/CentOS/Fedora it is::

    /etc/httpd/conf.d/uwsgi-manila.conf

On SLES/OpenSUSE it is::

    /etc/apache2/vhosts.d/uwsgi-manila.conf

On Debian/Ubuntu it is::

    /etc/apache2/sites-available/uwsgi-manila.conf

Enable mod_proxy by running ``sudo a2enmod proxy``

On Ubuntu/Debian systems enable the site using the a2ensite tool::

    sudo a2ensite /etc/apache2/sites-available/uwsgi-manila.conf

This is not required on RHEL/CentOS/Fedora systems.

Start or restart HTTPD/Apache2 to pick up the new configuration.

Now we have to configure and start the uwsgi service.
Copy the `httpd/manila-uwsgi.ini` file to `/etc/manila`. Update the file to
match your system configuration (i.e. tweak the number of processes and threads)

Install uwsgi.

On RHEL/CentOS::

    sudo yum install uwsgi-plugin-python3

On Fedora::

    sudo dnf install uwsgi-plugin-python3

On SLES/OpenSUSE::

    sudo zypper install uwsgi-python3

On Ubuntu/Debian::

    sudo apt-get install uwsgi-plugin-python3

And start the manila server using uwsgi::

    uwsgi --ini /etc/manila/manila-uwsgi.ini

.. NOTE::

   In the sample configs port 51999 is used, this is a randomly selected number.

Installing the API via mod_wsgi
-------------------------------

The httpd/ directory contains sample files for configuring HTTPD to run manila
API via mod_wsgi. To use sample configs, simply copy `httpd/mod_wsgi-manila.conf` to the
appropiate location for your apache server.

On RHEL/CentOS/Fedora it is::

    /etc/httpd/conf.d/mod_wsgi-manila.conf

On SLES/OpenSUSE it is::

    /etc/apache2/vhosts.d/mod_wsgi-manila.conf

On Debian/Ubuntu it is::

    /etc/apache2/sites-available/mod_wsgi-manila.conf

On Ubuntu/Debian systems enable the site using the a2ensite tool::

    sudo a2ensite /etc/apache2/sites-available/mod_wsgi-manila.conf

This is not required on RHEL/CentOS/Fedora systems.

Start or restart HTTPD/Apache2 to pick up the new configuration.

.. NOTE::

   manila's primary configuration file (etc/manila.conf) and the PasteDeploy
   configuration file (etc/manila-paste.ini) must be readable to httpd in one
   of the default locations described in Configuring Manila.

Access Control
--------------

If you are running with Linux kernel security module enabled (for example
SELinux or AppArmor), make sure that the configuration file has the
appropriate context to access the linked file.

.. _community goals for Pike: https://governance.openstack.org/tc/goals/pike/deploy-api-in-wsgi.html#control-plane-api-endpoints-deployment-via-wsgi
