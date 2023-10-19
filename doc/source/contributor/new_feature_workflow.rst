..
      Copyright 2023 Red Hat, Inc.
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

Proposing new features
======================

Planning and working on new features is a hard task. This documentation
suggests a workflow and highlights what is expected, suggested and
required when working on new features in the OpenStack Manila project.

Planning the feature
~~~~~~~~~~~~~~~~~~~~

Features should always start with planning. It is important to start by
discussing the problems and possible solutions with the community, bringing up
the use cases it will cover, corner cases and alternative approaches,
so we suggest the following process:

Registering a blueprint
-----------------------

When starting a new feature, you should file a blueprint in the
OpenStack Manila `Launchpad tracker <https://blueprints.launchpad.net/manila>`_.
This blueprint should have a brief description of the feature, and it will be
used to track all changes proposed to the implementation, including the Manila
core changes, functional tests and the OpenStack client changes. One example
blueprint would be the share server migration
`blueprint <https://blueprints.launchpad.net/manila/+spec/share-server-migration>`_.

Discussing the feature during the PTG
-------------------------------------

The OpenStack PTG is a very good timing to discuss new features, as the
upstream community is focused on planning and shaping the upcoming release.
So it is encouraged that you host a topic during the PTG to talk about the
design of the feature and have the community helping you shape it.

In case you missed the PTG deadline to bring up such features, you can also
add a topic to the Manila community weekly IRC meeting
`agenda <https://wiki.openstack.org/wiki/Manila/Meetings#Next_meeting>`_ and
request feedback from the community.

As a result, you can get different perspectives on the design of the feature
and raise awareness, so there are no surprises when the feature is being
proposed.

One other outcome of this discussion is determining the necessity of a
specification. The community will use
:ref:`pre-defined <features-that-require-spefication>` factors to decide if you
need a specification or not.

Writing a specification
-----------------------

After determining if a specification is necessary for your proposed feature,
you will need to write in more details about the problem you are trying to
solve, the use cases and all the impact this change will have in terms of API
changes, database, security and other aspects. The specification will be
reviewed by different people, and this process is crucial for hashing out
details. Please check the OpenStack Manila
`example specification <https://specs.openstack.org/openstack/manila-specs/specs/template.html>`_
and follow its guidelines. If you are working on a smaller feature, you may
submit a "lite spec". Please follow
`this example <https://github.com/openstack/manila-specs/blob/master/specs/wallaby/spec-lite-add-max-shares-on-share-server-limit.rst>`_.


Working on the implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is when the coding happens. You will work on the feature and the code
you write must follow the OpenStack coding
`guidelines <https://docs.openstack.org/hacking/latest/user/hacking.html>`_.
You can find examples of database migrations, driver implementations,
RPC APIs and many other changes in the Manila code base. As our code has been
worked on and improved over the years, there is a high chance that someone else
implemented something similar to what you are doing now, so keeping the
consistency with feature implementation is very important.

In case you are making changes to the API or adding new APIs, please
read the :ref:`Manila API contributor docs <adding-a-new-api>`.

Development environment
-----------------------

So you have worked on your changes and would like to test them?
:ref:`Devstack <setting-up-manila-devstack>` is likely the easiest way to go.
With devstack, you can have OpenStack installed quickly. You can chose to
install it using the Manila Dummy Driver or another backend driver of your
choice.

SDK and OpenStack client
------------------------

If the feature changes the Manila API, please ensure that support these changes
through the SDK bindings and OpenStack client in the
`python-manilaclient repository <https://github.com/openstack/python-manilaclient>`_.

Unit tests
----------

All new changes you implement must be covered by unit tests. We have a Zuul job
that will always check the coverage percentage of the changes and the reviewers
will also be actively looking at it.

.. important::

    Please :ref:`run the unit tests locally <running-unit-tests>` to ensure
    that your tests are passing before submitting them to the upstream gerrit.

Tempest tests
-------------

All API changes must be tested with negative and positive tests within the
`manila-tempest-plugin repository <https://github.com/openstack/python-manilaclient>`_.
You can use your development environment to
:ref:`run such tests <installing-tempest-tests>`, and ensure your changes
don't break existing functional tests.

Documenting your work
---------------------

:ref:`Documenting your work <documenting_your_work>` is very important. `API
documentation <https://docs.openstack.org/api-ref/shared-file-system/index.html>`_
and make changes where necessary. Also, you must include a release notes with
your change. On devstack you may use `tox -e reno new insert-title-here` to
generate a release note."

Collaborative review sessions
-----------------------------

`Collaborative review sessions <https://www.youtube.com/playlist?list=PLnpzT0InFrqCZB_t2B3IHEYH3_gPFEhck>`_
are a good way to speed up the review process. It is encouraged that you
propose one as early as possible. In the session, you can walk through the key
aspects of the changes you are working on and explain some decisions you took
during the implementation. It has proven to be very valuable to both change
owners and reviewers. To schedule, please bring it up during the Manila
upstream weekly meeting or send an email using the manila tag to OpenStack
discuss mailing list.

Complying to the deadlines
~~~~~~~~~~~~~~~~~~~~~~~~~~

The deadlines are defined in the official
`OpenStack release schedule <https://releases.openstack.org/>`_. The
Manila team also defines some extra project specific deadlines. Below, we have
specified what is expected from you in each of these deadlines.

Manila spec freeze
------------------

All specifications must be merged prior to this date.

Manila feature proposal freeze
------------------------------

New features must be submitted to gerrit before this deadline. The core,
client and tempest changes must be available on gerrit, but it does not mean
the changes should be merged by this deadline.

Manila new driver deadline
--------------------------

By the end of the week all new backend drivers for Manila must be substantially
complete, with unit tests, and passing 3rd party CI. Drivers do not have to
actually merge until feature freeze.

Feature freeze
--------------

The client release follows a different timeline from the core component, so the
client changes must be merged prior to this deadline, as defined in the release
schedule. The client must contain unit and functional tests.

.. important::

    API changes must have the documentation updated in the same change as the
    entire feature change.

All features and new drivers must be merged by the feature freeze date. In case
you need extra time for the Manila core change, please reach out to the team's
PTL during an upstream weekly meeting, and we can discuss a possible feature
freeze exception, considering if the comments were resolved in a reasonable
amount of time and if the change is already in a good shape to be merged.

Acceptance criteria
~~~~~~~~~~~~~~~~~~~

- Changes were proposed in time and module deadlines were respected
- The code introduced or changed is covered by unit tests
- New functional tests were proposed and reports are positive
- API changes are correct and not introducing backwards compatible changes
- API changes are documented

Additional tips
~~~~~~~~~~~~~~~

- Remember to join the upstream meetings often
- Make sure to use the :ref:`commit message tags <commit_message_tags>` in your
  changes.
- Submit the changes upstream as early as possible.
- Remember to run pep8, unit tests and coverage locally before you submit your
  changes to gerrit.
- Ensure you keep a review discipline. The best way to have reviewers
  looking at your change is to also provide reviews to other people's changes.
