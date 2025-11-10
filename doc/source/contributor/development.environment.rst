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

Manila development uses `virtualenv <https://pypi.org/project/virtualenv/>`__ to track and manage Python
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

- On RHEL8/Centos8::

    sudo dnf install openssl-devel python3-pip mysql-devel \
    libxml2-devel libxslt-devel postgresql-devel git git-review \
    libffi-devel gettext graphviz gcc libjpeg-turbo-devel \
    python3-tox python3-devel python3

.. note::

   If using RHEL and dnf reports "No package python3-pip available" and "No
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

    git clone https://opendev.org/openstack/manila
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

    tox -epy36

See :doc:`unit_tests` for more details.

.. _virtualenv:

Manually installing and using the virtualenv
--------------------------------------------

You can also manually install the virtual environment::

  tox -epy36 --notest

This will install all of the Python packages listed in the
``requirements.txt`` file into your virtualenv.

To activate the Manila virtualenv you can run::

     $ source .tox/py36/bin/activate

To exit your virtualenv, just type::

     $ deactivate

Or, if you prefer, you can run commands in the virtualenv on a case by case
basis by running::

     $ tox -e venv -- <your command>

Code Style and Quality Checks
------------------------------

Manila uses `pre-commit <https://pre-commit.com/>`_ to perform automated
linting tests and ensure conformance to the coding style guide. This repository
follows an evolved form of the original `PEP 8 <https://peps.python.org/pep-0008/>`_
guideline for Python code style.

On top of PEP 8, Manila performs "hacking" checks where a collection of
style and consistency checks are performed to adhere to coding standards
established within the Manila project, as well as the wider OpenStack projects.
These checks are defined in the `OpenStack Hacking Guidelines
<https://docs.openstack.org/hacking/latest/user/hacking.html>`_.

Setting up pre-commit
~~~~~~~~~~~~~~~~~~~~~

Pre-commit hooks are automatically configured when you run the pep8 tox environment::

    tox -e pep8

This will install pre-commit and run all configured checks on your codebase.

The pre-commit configuration includes:

* **Basic checks**: trailing whitespace, line ending normalization, merge conflict detection
* **Python style checks**: PEP 8 compliance via hacking rules
* **Documentation checks**: RST formatting and style via doc8
* **Shell script checks**: Bash style checks via bashate

You can also run pre-commit manually on all files::

    pre-commit run --all-files

Or install the git hook to run automatically on each commit::

    pre-commit install

In some cases, pre-commit will modify files in place. If you want to see what
changes will be made without applying them, you can run::

    pre-commit run --all-files --show-diff-on-failure

Or, if you want to apply the changes, you can run::

    pre-commit run --all-files --fix
    git add .

Manual style checking
~~~~~~~~~~~~~~~~~~~~~

You can also run style checks manually using tox::

    # Run all style checks
    tox -e pep8

    # Run only Python style checks
    tox -e fast8

The style checks will report any violations that need to be fixed before
your code can be merged.

Contributing Your Work
----------------------

Once your work is complete you may wish to contribute it to the
project. Manila uses the Gerrit code review system. For information on
how to submit your branch to Gerrit, see GerritWorkflow_.

.. _GerritWorkflow: https://docs.openstack.org/infra/manual/developers.html#development-workflow
