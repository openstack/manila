=======================================
OpenStack Manila Testing Infrastructure
=======================================

A note of clarification is in order, to help those who are new to testing in
OpenStack Manila:

- actual unit tests are created in the "tests" directory;
- the "testing" directory is used to house the infrastructure needed to support
  testing in OpenStack Manila.

This README file attempts to provide current and prospective contributors with
everything they need to know in order to start creating unit tests and
utilizing the convenience code provided in manila.testing.

Writing Unit Tests
------------------

- All new unit tests are to be written in python-mock.
- Old tests that are still written in mox should be updated to use python-mock.
    Usage of mox has been deprecated for writing Manila unit tests.
- use addCleanup in favor of tearDown

test.TestCase
-------------
The TestCase class from manila.test (generally imported as test) will
automatically manage self.stubs using the stubout module.
They will automatically verify and clean up during the tearDown step.

If using test.TestCase, calling the super class setUp is required and
calling the super class tearDown is required to be last if tearDown
is overridden.

Running Tests
-------------

In the root of the Manila source code run the run_tests.sh script. This will
offer to create a virtual environment and populate it with dependencies.
If you don't have dependencies installed that are needed for compiling Manila's
direct dependencies, you'll have to use your operating system's method of
installing extra dependencies. To get help using this script execute it with
the -h parameter to get options `./run_tests.sh -h`

Tests and assertRaises
----------------------
When asserting that a test should raise an exception, test against the
most specific exception possible. An overly broad exception type (like
Exception) can mask errors in the unit test itself.

Example::

    self.assertRaises(exception.InstanceNotFound, db.instance_get_by_uuid,
                      elevated, instance_uuid)
