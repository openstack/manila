Tempest Tests
=============

Manila stores tempest tests as plugin under ``manila_tempest_tests`` directory.
It contains functional and scenario tests.

Installation of plugin to tempest
---------------------------------
Tempest plugin installation is common for all its plugins and detailed
information can be found in its `docs`_.
In simple words: if you have installed manila project on the same machine as
tempest, then tempest will find it.

In case the plugin is not installed (see the verification steps below),
you can clone and install it yourself.

.. code-block:: console

   $ git clone https://git.openstack.org/openstack/manila-tempest-plugin
   $ pip install -e manila-tempest-plugin

.. _docs: https://docs.openstack.org/tempest/latest/plugin.html#using-plugins

Verifying installation
----------------------
To verify that the plugin is installed on your system, run the following
command and find "manila_tests" in its output.

.. code-block:: console

   $ tempest list-plugins

Alternatively, or to double-check, list all the tests available on the system
and find manila tests in it.

.. code-block:: console

   $ tempest run -l

Configuration of manila-related tests in tempest.conf
-----------------------------------------------------
All config options for manila are defined in ``manila_tempest_tests/config.py``
module. They can be set/redefined in ``tempest.conf`` file.

Here is a configuration example:

.. code-block:: ini

    [service_available]
    manila = True

    [share]
    # Capabilities
    capability_storage_protocol = NFS
    capability_snapshot_support = True
    capability_create_share_from_snapshot_support = True
    backend_names = Backendname1,BackendName2
    backend_replication_type = readable

    # Enable/Disable test groups
    multi_backend = True
    multitenancy_enabled = True
    enable_protocols = nfs,cifs,glusterfs,cephfs
    enable_ip_rules_for_protocols = nfs
    enable_user_rules_for_protocols = cifs
    enable_cert_rules_for_protocols = glusterfs
    enable_cephx_rules_for_protocols = cephfs
    username_for_user_rules = foouser
    enable_ro_access_level_for_protocols = nfs
    run_quota_tests = True
    run_extend_tests = True
    run_shrink_tests = True
    run_snapshot_tests = True
    run_replication_tests = True
    run_migration_tests = True
    run_manage_unmanage_tests = True
    run_manage_unmanage_snapshot_tests = True

.. note::
    None of existing share drivers support all features. So, make sure
    that share backends really support features you enable in config.

Running tests
-------------

To run tests, it is required to install `pip`_, `tox`_ and `virtualenv`_
packages on host machine. Then run following command
from tempest root directory:

.. code-block:: console

    $ tox -e all-plugin -- manila_tempest_tests.tests.api

or to run only scenario tests:

.. code-block:: console

    $ tox -e all-plugin -- manila_tempest_tests.tests.scenario

.. _pip: https://pypi.python.org/pypi/pip
.. _tox: https://pypi.python.org/pypi/tox
.. _virtualenv: https://pypi.python.org/pypi/virtualenv

Running a subset of tests based on test location
------------------------------------------------

Instead of running all tests, you can specify an individual directory, file,
class, or method that contains test code.

To run the tests in the ``manila_tempest_tests/tests/api/admin`` directory:

.. code-block:: console

    $ tox -e all-plugin -- manila_tempest_tests.tests.api.admin

To run the tests in the
``manila_tempest_tests/tests/api/admin/test_admin_actions.py`` module:

.. code-block:: console

    $ tox -e all-plugin -- manila_tempest_tests.tests.api.admin.test_admin_actions

To run the tests in the `AdminActionsTest` class in
``manila_tempest_tests/tests/api/admin/test_admin_actions.py`` module:

.. code-block:: console

    $ tox -e all-plugin -- manila_tempest_tests.tests.api.admin.test_admin_actions.AdminActionsTest

To run the `AdminActionsTest.test_reset_share_state` test method in
``manila_tempest_tests/tests/api/admin/test_admin_actions.py`` module:

.. code-block:: console

    $ tox -e all-plugin -- manila_tempest_tests.tests.api.admin.test_admin_actions.AdminActionsTest.test_reset_share_state

Running a subset of tests based on service involvement
------------------------------------------------------
To run the tests that require only `manila-api` service running:

.. code-block:: console

    $ tox -e all-plugin -- \
      \(\?\=\.\*\\\[\.\*\\bapi\\b\.\*\\\]\) \
      \(\^manila_tempest_tests.tests.api\)

To run the tests that require all manila services running,
but intended to test API behaviour:

.. code-block:: console

    $ tox -e all-plugin -- \
      \(\?\=\.\*\\\[\.\*\\b\(api\|api_with_backend\)\\b\.\*\\\]\) \
      \(\^manila_tempest_tests.tests.api\)

To run the tests that require all manila services running,
but intended to test back-end (manila-share) behaviour:

.. code-block:: console

    $ tox -e all-plugin -- \
      \(\?\=\.\*\\\[\.\*\\bbackend\\b\.\*\\\]\) \
      \(\^manila_tempest_tests.tests.api\)

Running a subset of positive or negative tests
----------------------------------------------
To run only positive tests, use following command:

.. code-block:: console

    $ tox -e all-plugin -- \
      \(\?\=\.\*\\\[\.\*\\bpositive\\b\.\*\\\]\) \
      \(\^manila_tempest_tests.tests.api\)

To run only negative tests, use following command:

.. code-block:: console

    $ tox -e all-plugin -- \
      \(\?\=\.\*\\\[\.\*\\bnegative\\b\.\*\\\]\) \
      \(\^manila_tempest_tests.tests.api\)

To run only positive API tests, use following command:

.. code-block:: console

    $ tox -e all-plugin -- \
      \(\?\=\.\*\\\[\.\*\\bpositive\\b\.\*\\\]\) \
      \(\?\=\.\*\\\[\.\*\\bapi\\b\.\*\\\]\) \
      \(\^manila_tempest_tests.tests.api\)
