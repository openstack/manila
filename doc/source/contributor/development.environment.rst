..
      Copyright 2010-2011 United States Government as represented by the
      Administrator of the National Aeronautics and Space Administration.
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Setting Up a Development Environment
====================================

This page describes how to setup a working Python development
environment that can be used in developing manila on Ubuntu, Fedora or
Mac OS X. These instructions assume you're already familiar with
git. Refer to `Getting the code`_ for additional information.

.. _Getting the code: http://wiki.openstack.org/GettingTheCode

Following these instructions will allow you to run the manila unit
tests. If you want to be able to run manila (i.e., create NFS/CIFS shares),
you will also need to install dependent projects: nova, neutron, cinder and glance.
For this purpose 'devstack' project can be used (A documented shell script to build
complete OpenStack development environments).
You can check out `Setting up a development environment with devstack`_ for instructions
on how to enable manila on devstack.

.. _Setting up a development environment with devstack: https://docs.openstack.org/manila/latest/contributor/development-environment-devstack.html

Virtual environments
--------------------

Manila development uses `virtualenv <http://pypi.python.org/pypi/virtualenv>`__ to track and manage Python
dependencies while in development and testing. This allows you to
install all of the Python package dependencies in a virtual
environment or "virtualenv" (a special subdirectory of your manila
directory), instead of installing the packages at the system level.

.. note::

   Virtualenv is useful for running the unit tests, but is not
   typically used for full integration testing or production usage.

Linux Systems
-------------

.. note::

  This section is tested for manila on Ubuntu and Fedora-based
  distributions. Feel free to add notes and change according to
  your experiences or operating system.

Install the prerequisite packages.

- On Ubuntu/Debian::

    sudo apt-get install python-dev libssl-dev python-pip \
    libmysqlclient-dev libxml2-dev libxslt-dev libpq-dev git \
    git-review libffi-dev gettext graphviz libjpeg-dev

- On Fedora 21/RHEL7/Centos7::

    sudo yum install python-devel openssl-devel python-pip mysql-devel \
    libxml2-devel libxslt-devel postgresql-devel git git-review \
    libffi-devel gettext graphviz gcc libjpeg-turbo-devel \
    python-tox python3-devel python3

.. note::

   If using RHEL and yum reports "No package python-pip available" and "No
   package git-review available", use the EPEL software repository.
   Instructions can be found at `<http://fedoraproject.org/wiki/EPEL/FAQ#howtouse>`_.

- On Fedora 22 and higher::

    sudo dnf install python-devel openssl-devel python-pip mysql-devel \
    libxml2-devel libxslt-devel postgresql-devel git git-review \
    libffi-devel gettext graphviz gcc libjpeg-turbo-devel \
    python-tox python3-devel python3

.. note::

   Additionally, if using Fedora 23, ``redhat-rpm-config`` package should be
   installed so that development virtualenv can be built successfully.


Mac OS X Systems
----------------

Install virtualenv::

    sudo easy_install virtualenv

Check the version of OpenSSL you have installed::

    openssl version

If you have installed OpenSSL 1.0.0a, which can happen when installing a
MacPorts package for OpenSSL, you will see an error when running
``manila.tests.auth_unittest.AuthTestCase.test_209_can_generate_x509``.

The stock version of OpenSSL that ships with Mac OS X 10.6 (OpenSSL 0.9.8l)
or Mac OS X 10.7 (OpenSSL 0.9.8r) works fine with manila.


Getting the code
----------------
Grab the code::

    git clone https://github.com/openstack/manila.git
    cd manila


Running unit tests
------------------
The preferred way to run the unit tests is using ``tox``. Tox executes tests in
isolated environment, by creating separate virtualenv and installing
dependencies from the ``requirements.txt`` and ``test-requirements.txt`` files,
so the only package you install is ``tox`` itself::

    sudo pip install tox

Run the unit tests with::

    tox -e py{python-version}

Example::

    tox -epy27
    tox -epy36

See :doc:`unit_tests` for more details.

.. _virtualenv:

Manually installing and using the virtualenv
--------------------------------------------

You can also manually install the virtual environment::

  tox -epy27 --notest

or::

  tox -epy36 --notest

This will install all of the Python packages listed in the
``requirements.txt`` file into your virtualenv.

To activate the Manila virtualenv you can run::

     $ source .tox/py27/bin/activate

or::

     $ source .tox/py36/bin/activate

To exit your virtualenv, just type::

     $ deactivate

Or, if you prefer, you can run commands in the virtualenv on a case by case
basis by running::

     $ tox -e venv -- <your command>

Contributing Your Work
----------------------

Once your work is complete you may wish to contribute it to the
project. Manila uses the Gerrit code review system. For information on
how to submit your branch to Gerrit, see GerritWorkflow_.

.. _GerritWorkflow: https://docs.openstack.org/infra/manual/developers.html#development-workflow
