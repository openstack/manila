..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Manila Project Team Lead guide
==============================

A `project team lead <https://docs.openstack.org/project-team-guide/ptl.html>`_
for Manila is elected from the project contributors. A candidate for PTL
needn't be a core reviewer on the team, but, must be a contributor,
and be familiar with the project to lead the project through
its release process. If you would like to be a core reviewer begin by
:ref:`contacting-the-core-team`. All the responsibilities below help us in
maintaining the project. A project team lead can perform any of these or
delegate tasks to other contributors.

General Responsibilities
------------------------

* Ensure manila meetings have a chair

  * https://opendev.org/opendev/irc-meetings/src/branch/master/meetings/manila-team-meeting.yaml

* Update the team people wiki

  * https://wiki.openstack.org/wiki/Manila#People


Release cycle activities
------------------------

* Get acquainted with the release schedule and set Project specific
  milestones in the `OpenStack Releases repository
  <https://opendev.org/openstack/releases>`_

  * Example: https://releases.openstack.org/victoria/schedule.html

* Ensure the Manila `Cross Project Liaisons
  <https://wiki.openstack.org/wiki/CrossProjectLiaisons>`_ are aware of
  their duties and are plugged into the respective areas

* Acknowledge `community wide cycle goals
  <https://governance.openstack.org/tc/goals/#community-goals>`_ and find
  leaders and coordinate with the goal liaisons

* Plan team activities such as:

  * ``Documentation day/s`` to groom documentation bugs and re-write
    release cycle docs
  * ``Bug Triage day/s`` to ensure the bug backlog is well groomed
  * ``Bug Squash day/s`` to close bugs
  * ``Collaborative Review meeting/s`` to perform a high-touch review of a code
    submission over a synchronous call

* Milestone driven work:

  * ``Milestone-1``:

    - Request a release for the python-manilaclient and manila-ui
    - Retarget any bugs whose fixes missed Milestone-1

  * ``Milestone-2``:

    - Retarget any bugs whose fixes missed Milestone-2
    - Create a review priority etherpad and share it with the community
      and have reviewers sign up

  * ``Milestone-3``:

    - Groom the release notes for python-manilaclient and add a 'prelude'
      section describing the most important changes in the release
    - Request a final cycle release for python-manilaclient
    - Retarget any bugs whose fixes missed Milestone-3
    - Grant/Deny any Feature Freeze Exception Requests
    - Update task trackers for Community Wide Goals
    - Write the cycle-highlights in marketing-friendly sentences
      and propose to the openstack/releases repo. Usually based on reno
      prelude but made more readable and friendly

      * Example: https://review.opendev.org/717801/

    - Create the launchpad series and milestones for the next cycle in
      manila, python-manilaclient and manila-ui. Examples:

      * manila: https://launchpad.net/manila/ussuri
      * python-manilaclient: https://launchpad.net/python-manilaclient/ussuri
      * manila-ui: https://launchpad.net/manila-ui/ussuri

  * ``Before RC-1``:

    - Groom the release notes for manila-ui and add a 'prelude'
      section describing the most important changes in the release
    - Request a final cycle release for manila-ui
    - Groom the release notes for manila, add a 'prelude' section
      describing the most important changes in the release
    - Mark bugs as {release}-rc-potential bugs in launchpad, ensure they
      are targeted and addressed by RC

  * ``RC-1``:

    - Request a RC-1 release for manila
    - Request a final cycle tagged release for manila-tempest-plugin
    - Ensure all blueprints for the release have been marked "Implemented"
      or are re-targeted

  * ``After RC-1``:

    - Close the currently active series on Launchpad for manila,
      python-manilaclient and manila-ui and set the "Development Focus"
      to the next release. Alternatively, you can switch this on the
      series page by setting the next release to “active development”
    - Set the last series status in each of these projects to “current
      stable branch release”
    - Set the previous release's series status to “supported”
    - Move any Unimplemented specs in `the specs repo
      <https://opendev.org/openstack/manila-specs>`_ to "Unimplemented"
    - Create a new specs directory in the specs repo for the next
      cycle so people can start proposing new specs

* You should NOT plan to have more than one RC. RC2 should only happen
  if there was a mistake and something was missed for RC-1, or a new regression
  was discovered

* Periodically during the release:

  * ``Every Week``:

    - Coordinate the weekly Community Meeting agenda
    - Coordinate with the Bug Czar and ensure bugs are properly triaged
    - Check whether any bug-fixes must be back-ported to older stable
      releases

  * ``Every 3 weeks``:

    - Ensure stable branch releases are proposed in case there are any
      release worthy changes. If there are only documentation or CI/test
      related fixes, no release for that branch is necessary

* To request a release of any manila deliverable:

  * ``git checkout {branch-to-release-from}``

  * ``git log --no-merges {last tag}..``

    * Examine commits that will go into the release and use it to decide
      whether the release is a major, minor, or revision bump according to
      semver

  * Then, propose the release with version according to semver x.y.z

    * X - backward-incompatible changes

    * Y - features

    * Z - bug fixes

  * Use the ``new-release`` command to generate the release

    * https://releases.openstack.org/reference/using.html#using-new-release-command

  .. note::
     When proposing new releases, ensure that the releases for newer branches
     are proposed and accepted in the order of the most recent branch to the
     older.


Project Team Gathering
----------------------

* Create etherpads for PTG planning, cycle retrospective and PTG discussions
  and announce the Planning etherpad to the community members via the Manila
  community meeting as well as the `OpenStack Discuss Mailing List`

  * `Example PTG Planning Etherpad <https://etherpad.opendev.org/p/manila-shanghai-ptg-planning>`_
  * `Example Retrospective Etherpad <https://etherpad.opendev.org/p/manila-stein-retrospective>`_
  * `Example PTG Discussions Etherpad <https://etherpad.opendev.org/p/manila-ptg-train>`_

* If the PTG is a physical event, gather an estimate of attendees and
  request the OpenDev Foundation staff for appropriate meeting space. Ensure
  the sessions are remote attendee friendly. Coordinate A/V logistics

* Set discussion schedule and find an owner to run each proposed discussion at
  the PTG

* All sessions must be recorded, nominate note takers for each discussion

* Sign up for group photo at the PTG (if applicable)

* After the event, send PTG session summaries and the meeting recording to the
  `OpenStack Discuss Mailing List`

Summit
------

* Prepare the project update presentation. Enlist help of others

* Prepare the on-boarding session materials. Enlist help of others


.. _OpenStack Discuss Mailing List: http://lists.openstack.org/cgi-bin/mailman/listinfo/openstack-discuss
.. _contacting the core team: contributing#contacting-the-core-team
