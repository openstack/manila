..
      Copyright 2016 Red Hat, Inc.
      All Rights Reserved.
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Setting up a development environment with devstack
==================================================

This page describes how to setup a working development
environment that can be used in deploying manila on latest releases
of Ubuntu or Fedora. These instructions assume you are already familiar
with git. Refer to `Getting the code`_ for additional information.

.. _Getting the code: http://wiki.openstack.org/GettingTheCode

Following these instructions will allow you to have a fully functional manila
environment using the devstack project (a shell script to build
complete OpenStack development environments).

Configuring devstack with manila
--------------------------------

Manila
``````

Manila can be enabled in devstack by using the plug-in based interface it
offers.

Start by cloning the devstack repository:

::

    git clone https://github.com/openstack-dev/devstack

Change to devstack directory:

::

    cd devstack/

Copy the local.conf sample file to the upper level directory:

::

    cp samples/local.conf .

Enable the manila plugin adding the following line to the end of the local.conf file:

::

    enable_plugin manila https://github.com/openstack/manila

If you would like to install python-manilaclient from git, add to local.conf:

::

    LIBS_FROM_GIT="python-manilaclient"

Manila UI
`````````

In order to use the manila UI you will need to enable the UI plugin separately.

This is done in a similar fashion than enabling manila for devstack.

Make sure you have horizon enabled (enabled by default in current devstack).

Then, enable the manila UI plugin adding the following line to the end of the local.conf file,
just after manila plugin enablement:

::

    enable_plugin manila-ui https://github.com/openstack/manila-ui

Running devstack
----------------

Run the stack.sh script:

::

    ./stack.sh

After it completes, you should have manila services running.
You can check if they are running by attaching to the screen:

::

    screen -r stack

And navigating to the manila service tabs (use ctrl+a n, ctrl+a p,
ctrl+a " <screen number> to navigate,
ctrl+a esc to enter scrollback mode
and ctrl+a d to detach from the screen).

If you enabled manila UI as well, you should be able to access manila UI
from the dashboard.
