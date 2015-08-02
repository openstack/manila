Continuous Integration with Jenkins
===================================

Manila uses a `Jenkins`_ server to automate development tasks. The Jenkins
front-end is at http://jenkins.openstack.org. You must have an
account on `Launchpad`_ to be able to access the OpenStack Jenkins site.

Jenkins performs tasks such as:

`gate-manila-pep8`_
    Run PEP8 checks on proposed code changes that have been reviewed.

`gate-manila-pylint`_
    Run Pylint checks on proposed code changes that have been reviewed.

`gate-manila-python27`_
    Run unit tests using python2.7 on proposed code changes that have been reviewed.

`gate-manila-python34`_
    Run unit tests using python3.4 on proposed code changes that have been reviewed.

`manila-coverage`_
    Calculate test coverage metrics.

`manila-docs`_
    Build this documentation and push it to http://docs.openstack.org/developer/manila.

`manila-merge-release-tags`_
    Merge reviewed code into the git repository.

`manila-tarball`_
    Do ``python setup.py sdist`` to create a tarball of the manila code and upload
    it to http://tarballs.openstack.org/manila/

.. _Jenkins: http://jenkins-ci.org
.. _Launchpad: http://launchpad.net
.. _gate-manila-pep8: https://jenkins.openstack.org/job/gate-manila-pep8
.. _gate-manila-pylint: https://jenkins.openstack.org/job/gate-manila-pylint
.. _gate-manila-python27: https://jenkins.openstack.org/job/gate-manila-python27/
.. _gate-manila-python34: https://jenkins.openstack.org/job/gate-manila-python34/
.. _manila-coverage: https://jenkins.openstack.org/job/manila-coverage
.. _manila-docs: https://jenkins.openstack.org/job/manila-docs
.. _manila-merge-release-tags: https://jenkins.openstack.org/job/manila-merge-release-tags
.. _manila-tarball: https://jenkins.openstack.org/job/manila-tarball
