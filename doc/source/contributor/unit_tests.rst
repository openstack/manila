Unit Tests
==========

Manila contains a suite of unit tests, in the manila/tests directory.

Any proposed code change will be automatically rejected by the OpenStack
Jenkins server if the change causes unit test failures.

Running the tests
-----------------

To run all unit tests simply run::

    tox

This will create a virtual environment, load all the packages from
test-requirements.txt and run all unit tests as well as run flake8 and hacking
checks against the code.

You may run individual test targets, for example only py27 tests, by running::

    tox -e py27

Note that you can inspect the tox.ini file to get more details on the available
options and what the test run does by default.

Running a subset of tests
-------------------------
Instead of running all tests, you can specify an individual directory, file,
class, or method that contains test code.

To run the tests in the ``manila/tests/scheduler`` directory::

    tox -epy27 -- manila.tests.scheduler

To run the tests in the `ShareManagerTestCase` class in
``manila/tests/share/test_manager.py``::

    tox -epy27 -- manila.tests.share.test_manager.ShareManagerTestCase

To run the `ShareManagerTestCase::test_share_manager_instance` test method in
``manila/tests/share/test_manager.py``::

  tox -epy27 -- manila.tests.share.test_manager.ShareManagerTestCase.test_share_manager_instance

For more information on these options and details about stestr, please see the
`stestr documentation <http://stestr.readthedocs.io/en/latest/MANUAL.html>`_.

Database Setup
--------------

Some unit tests will use a local database. You can use
``tools/test-setup.sh`` to set up your local system the same way as
it's setup in the CI environment.


Gotchas
-------

**Running Tests from Shared Folders**

If you are running the unit tests from a shared folder, you may see tests start
to fail or stop completely as a result of Python lockfile issues [#f3]_. You
can get around this by manually setting or updating the following line in
``manila/tests/conf_fixture.py``::

    FLAGS['lock_path'].SetDefault('/tmp')

Note that you may use any location (not just ``/tmp``!) as long as it is not
a shared folder.

.. rubric:: Footnotes

.. [#f1] See :doc:`development.environment` for more details about the use of
   virtualenv.

.. [#f2] There is an effort underway to use a fake DB implementation for the
   unit tests. See https://lists.launchpad.net/openstack/msg05604.html

.. [#f3] See Vish's comment in this bug report: https://bugs.launchpad.net/manila/+bug/882933
