Continuous Integration with Jenkins
===================================

Manila uses a `Jenkins`_ server to automate development tasks. The Jenkins
front-end is at http://jenkins.openstack.org. You must have an
account on `Launchpad`_ to be able to access the OpenStack Jenkins site.

Jenkins performs tasks such as:

`gate-manila-unittests`_
    Run unit tests on proposed code changes that have been reviewed.

`gate-manila-pep8`_
    Run PEP8 checks on proposed code changes that have been reviewed.

`gate-manila-merge`_
    Merge reviewed code into the git repository.

`manila-coverage`_
    Calculate test coverage metrics.

`manila-docs`_
    Build this documentation and push it to http://manila.openstack.org.

`manila-tarball`_
    Do ``python setup.py sdist`` to create a tarball of the manila code and upload
    it to http://manila.openstack.org/tarballs

.. _Jenkins: http://jenkins-ci.org
.. _Launchpad: http://launchpad.net
.. _gate-manila-merge: https://jenkins.openstack.org/view/Manila/job/gate-manila-merge
.. _gate-manila-pep8: https://jenkins.openstack.org/view/Manila/job/gate-manila-pep8
.. _gate-manila-unittests: https://jenkins.openstack.org/view/Manila/job/gate-manila-unittests
.. _manila-coverage: https://jenkins.openstack.org/view/Manila/job/manila-coverage
.. _manila-docs: https://jenkins.openstack.org/view/Manila/job/manila-docs
.. _manila-pylint: https://jenkins.openstack.org/job/manila-pylint
.. _manila-tarball: https://jenkins.openstack.org/job/manila-tarball
