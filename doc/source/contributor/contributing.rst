============================
So You Want to Contribute...
============================

For general information on contributing to OpenStack, check out the
`contributor guide <https://docs.openstack.org/contributors/>`_ to get started.
It covers all the basics that are common to all OpenStack projects: the
accounts you need, the basics of interacting with our Gerrit review system,
how we communicate as a community, etc.

Below will cover the more project specific information you need to get started
with Manila (Shared File System service).


Where is the code?
~~~~~~~~~~~~~~~~~~

manila
    | The OpenStack Shared File System Service
    | code: https://opendev.org/openstack/manila
    | docs: https://docs.openstack.org/manila/
    | api-ref: https://docs.openstack.org/api-ref/shared-file-system
    | release model: https://releases.openstack.org/reference/release_models.html#cycle-with-rc
    | Launchpad: https://launchpad.net/manila


python-manilaclient
    | Python client library for the OpenStack Shared File System Service API;
      includes standalone CLI shells and OpenStack client plugin and shell
    | code: https://opendev.org/openstack/python-manilaclient
    | docs: https://docs.openstack.org/python-manilaclient
    | release model: https://releases.openstack.org/reference/release_models.html#cycle-with-intermediary
    | Launchpad: https://launchpad.net/python-manilaclient


manila-ui
    | OpenStack dashboard plugin for the Shared File System Service
    | code: https://opendev.org/openstack/manila-ui
    | docs: https://docs.openstack.org/manila-ui
    | release model: https://releases.openstack.org/reference/release_models.html#cycle-with-intermediary
    | Launchpad: https://launchpad.net/manila-ui


manila-tempest-plugin
    | An OpenStack test integration (tempest) plugin containing API and
      scenario tests for the Shared File System Service
    | code: https://opendev.org/openstack/manila-tempest-plugin
    | release model: https://releases.openstack.org/reference/release_models.html#cycle-automatic
    | Launchpad: https://launchpad.net/manila


manila-image-elements
    | A Disk Image Builder project with scripts to build a bootable Linux
      image for testing and use by some Shared File System Service storage
      drivers including the Generic Driver
    | code: https://opendev.org/openstack/manila-tempest-plugin
    | release model: no releases
    | Launchpad: https://launchpad.net/manila


manila-test-image
    | A project with scripts to create a Buildroot based image to create a
      small bootable Linux image, primarily for the purposes of testing Manila
    | code: https://opendev.org/openstack/manila-image-elements
    | images: https://tarballs.opendev.org/openstack/manila-image-elements/
    | release model: no releases
    | Launchpad: https://launchpad.net/manila-image-elements


manila-specs
    | Design Specifications for the Shared File System service
    | code: https://opendev.org/openstack/manila-specs
    | published specs: https://specs.openstack.org/openstack/manila-specs/
    | release model: no releases
    | Launchpad: https://launchpad.net/manila


See the ``CONTRIBUTING.rst`` file in each code repository for more
information about contributing to that specific deliverable. Additionally,
you should look over the docs links above; most components have helpful
developer information specific to that deliverable.

Manila and its associated projects follow a coordinated release alongside
other OpenStack projects. Development cycles are code named. See the
`OpenStack Releases website`_ for names and schedules of the current, past
and future development cycles.


Communication
~~~~~~~~~~~~~

IRC
---

The team uses `IRC <https://docs.openstack.org/contributors/common/irc.html>`_
extensively for communication and coordination of project activities. The
IRC channel is ``#openstack-manila`` on OFTC. Contributors work in various
timezones across the world; so many of them run IRC Bouncers and appear to be
always online. If you ping someone, or raise a question on the IRC channel,
someone will get back to you when they are back on their computer.
Additionally, the IRC channel is logged, so if you ask a question
when no one is around, you can `check the log
<http://eavesdrop.openstack.org/irclogs/%23openstack-manila/>`_
to see if it has been answered.


Team Meetings
-------------
We host a one-hour IRC based community meeting every Thursday at 1500
UTC on ``#openstack-meeting-alt`` channel. See the `OpenStack meetings page
<http://eavesdrop.openstack.org/#Manila_Team_Meeting>`_ for the most
up-to-date meeting information and for downloading the ICS file to integrate
this slot with your calendar. The community meeting is a good opportunity to
gather the attention of multiple contributors synchronously. If you wish to
do so, add a meeting topic along with your IRC nick to the
`Meeting agenda <https://wiki.openstack.org/wiki/Manila/Meetings>`_.

Mailing List
------------

In addition to IRC, the team uses the `OpenStack Discuss Mailing List`_
for development discussions. This list is meant for communication
about all things developing OpenStack; so we also use this list to engage with
contributors across projects, and make any release cycle announcements.
Since it is a wide distribution list, the use of subject line tags is
encouraged to make sure you reach the right people. Prefix the
subject line with ``[manila]`` when sending email that concern Manila on
this list.


Other Communication Avenues
---------------------------

Contributors gather at least once per release at the `OpenDev Project Team
Gathering <https://www.openstack.org/ptg>`_ to discuss plans for an upcoming
development cycle. This is usually where developers pool ideas and
brainstorm features and bug fixes. We have had both virtual, and in-person
Project Technical Gathering events in the past. Before every such event, we
gather opinions from the community via IRC Meetings and the Mailing list on
planning these Project Technical Gatherings.

We make extensive use of `Etherpads <https://etherpad.opendev.org>`_. You can
find some of them that the team used in the past `in the project Wiki
<https://wiki.openstack.org/wiki/Manila/Etherpads>`_. To share code
snippets or logs, we use `PasteBin <http://paste.openstack.org>`_.

.. _contacting-the-core-team:

Contacting the Core Team
~~~~~~~~~~~~~~~~~~~~~~~~

When you contribute patches, your change will need to be approved by one or
more `maintainers (collectively known as the "Core Team")
<https://wiki.openstack.org/wiki/Manila#People>`_.

We're always looking for more maintainers! If you're looking to help
maintain Manila, express your interest to the existing core team. We have
mentored many individuals for one or more development cycles and added them to
the core team.

Any new core reviewer needs to be nominated to the team by an existing core
reviewer by making a proposal on `OpenStack Discuss Mailing List`_. Other
maintainers and contributors can then express their approval or disapproval
by responding to the proposal. If there is a decision, the project team lead
will add the concerned individual to the core reviewers team. An example
proposal is `here.
<http://lists.openstack.org/pipermail/openstack-discuss/2020-February/012677.html>`_


New Feature Planning
~~~~~~~~~~~~~~~~~~~~

If you'd like to propose a new feature, do so by `creating a blueprint
on Launchpad. <https://blueprints.launchpad.net/manila>`_ For significant
changes we might require a design specification.

Feature changes that need a specification include:
--------------------------------------------------

- Adding new API methods
- Substantially modifying the behavior of existing API methods
- Adding a new database resource or modifying existing resources
- Modifying a share back end driver interface, thereby affecting all share
  back end drivers

What doesn't need a design specification:
-----------------------------------------

- Making trivial (backwards compatible) changes to the behavior of an
  existing API method. Examples include adding a new field to the response
  schema of an existing method, or introducing a new query parameter. See
  :doc:`api_microversion_dev` on how Manila APIs are versioned.
- Adding new share back end drivers or modifying share drivers, without
  affecting the share back end driver interface
- Adding or changing tests

After filing a blueprint, if you're in doubt whether to create a design
specification, contact the maintainers.

Design specifications are tracked in the `Manila
Specifications <https://opendev.org/openstack/manila-specs>`_ repository and
are published on the `OpenStack Project Specifications website.
<https://specs.openstack.org/openstack/manila-specs/>`_ Refer to the
`specification template
<https://specs.openstack.org/openstack/manila-specs/specs/template.html>`_
to structure your design spec.

Specifications and new features have deadlines. Usually, specifications for
an upcoming release are frozen midway into the release development
cycle. To determine the exact deadlines, see the published release calendars
by navigating to the specific release from the `OpenStack releases website`_.


Task Tracking
~~~~~~~~~~~~~

- We track our bugs in Launchpad:

  https://bugs.launchpad.net/manila

  If you're looking for some smaller, easier work item to pick up and get
  started on, search for the 'low-hanging-fruit' tag

- We track future features as blueprints on Launchpad:

  https://blueprints.launchpad.net/manila

- Unimplemented specifications are tracked here:

  https://specs.openstack.org/openstack/manila-specs/#unimplemented-specs

  These specifications need a new owner. If you're interested to pick them
  up and drive them to completion, you can update the corresponding blueprint
  and get in touch with the project maintainers for help


Reporting a Bug
~~~~~~~~~~~~~~~

You found an issue and want to make sure we are aware of it? You can do so on
`Launchpad <https://bugs.launchpad.net/manila>`_.

Getting Your Patch Merged
~~~~~~~~~~~~~~~~~~~~~~~~~

When you submit your change through Gerrit, a number of automated Continuous
Integration tests are run on your change. A change must receive a +1 vote
from the `OpenStack CI system <https://zuul.opendev.org/t/openstack/status>`_
in order for it to be merge-worthy. If these tests are failing and you can't
determine why, contact the maintainers.

See the :doc:`manila-review-policy` to understand our code review
conventions. Generally, reviewers look at new code submissions pro-actively;
if you do not have sufficient attention to your change, or are looking for
help, do not hesitate to jump into the team's IRC channel, or bring our
attention to your issue during a community meeting. The core team would
prefer to have an open discussion instead of a one-on-one/private chat.


Project Team Lead Duties
~~~~~~~~~~~~~~~~~~~~~~~~

A `project team lead <https://docs.openstack.org/project-team-guide/ptl.html>`_
is elected from the project contributors each cycle. Manila Project specific
responsibilities for a lead are listed in the :doc:`project-team-lead`.


.. _OpenStack Releases website: <https://releases.openstack.org>
.. _OpenStack Discuss Mailing List: http://lists.openstack.org/cgi-bin/mailman/listinfo/openstack-discuss
.. _Manila Project Team Lead guide: ../project-team-lead.rst
.. _API Microversions: ../api_microversion_dev.rst
