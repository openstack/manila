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
environment that can be used in deploying ``manila`` and ``manila-ui`` on
latest releases of Ubuntu, Fedora or CentOS. These instructions assume you
are already familiar with git.

We recommend using devstack to develop and test code changes to ``manila``
and/or ``manila-ui``, in order to simply evaluate the manila and/or project.
Devstack is a shell script to build complete OpenStack development
environments on a virtual machine. If you are not familiar with devstack,
these pages can give you context:

* `Testing Changes with DevStack <https://docs.openstack.org/contributors/code-and-documentation/devstack.html>`_
* `Devstack project documentation <https://docs.openstack.org/devstack/latest>`_

Be aware that ``manila`` and ``manila-ui`` are not enabled in devstack by
default; you will need to add a few lines to the devstack ``local.conf``
file to let devstack deploy and configure ``manila`` and ``manila-ui`` on
your virtual machine.

.. note::

    If you do not intend to deploy with the OpenStack Dashboard (horizon)
    service, you can ignore instructions about enabling ``manila-ui``.

Getting devstack
----------------

Start by cloning the devstack repository::

    git clone https://opendev.org/openstack/devstack

Change to devstack directory::

    cd devstack/


You're now on ``master`` branch of devstack, switch to the branch you want
to test or develop against.

Sample local.conf files that get you started
--------------------------------------------

Now that you have cloned the devstack repository, you need to
configure devstack before deploying it.  This is done with a ``local.conf``
file.  For manila, the local.conf file can also determine which back end(s)
are set up. The choice of back end(s) is important because there are optional
API features in Manila `that are not supported by some drivers
<../admin/share_back_ends_feature_support_mapping.html>`_.

.. caution::

    When using devstack with the below configurations, be aware that you will
    be setting up with node local storage. The `LVM`, `Generic`,
    `ZFSOnLinux` drivers have not been developed for production use.
    They exist to provide a vanilla development and testing environment for
    manila contributors.

DHSS=False (`driver_handles_share_servers=False`) mode:
`````````````````````````````````````````````````````````
This is the easier mode for new contributors. Manila share back-end drivers
that operate in ``driver_handles_share_servers=False`` mode do not allow
creating shares on private project networks. On the resulting stack, all
manila shares created by you are exported on the host network and hence are
accessible to any compute resource (e.g.: virtual machine, baremetal,
container) that is able to reach the devstack host.

* :download:`LVM driver <samples/lvm_local.conf>`
* :download:`ZFSOnLinux driver <samples/zfsonlinux_local.conf>`
* :download:`CEPHFS driver <samples/cephfs_local.conf>`

DHSS=True (`driver_handles_share_servers=True`) mode:
```````````````````````````````````````````````````````

You may use the following setups if you are familiar with manila,
and would like to test with the project (tenant) isolation that manila
provides on the network and data path. Manila share back-end drivers that
operate in ``driver_handles_share_servers=True`` mode create shares on
isolated project networks if told to do so. On the resulting stack, when
creating a share, you must specify a share network to export the share to,
and the share will be accessible to any compute resource (e.g.: Virtual
machine, baremetal, containers) that is able to reach the share network you
indicated.

Typically, new contributors take a while to understand OpenStack networking,
and we recommend that you familiarize yourself with the ``DHSS=False`` mode
setup before attempting ``DHSS=True``.

* :download:`Generic driver <samples/generic_local.conf>`
* :download:`Container driver <samples/container_local.conf>`

Using a dummy back end driver
`````````````````````````````

If you're absolutely new to manila code development, you may want to skip a
real storage driver altogether and attempt a development environment that
abstracts the back end storage layer. This could also be the situation if
you're building API integrations such as CLI, UI or SDK clients. Here, you
probably don't care about restrictions that individual back end choices bring
you such as their lack of support for optional API features. Manila ships a
fake backend driver called "Dummy Driver" that supports all API features and
is capable of operating in both DHSS modes. You may use the following `local
.conf` sample to bootstrap your devstack with a "Dummy" driver. Do remember
however that you cannot really *use* the resources that are provisioned by
this driver.

* :download:`Dummy driver <samples/dummy_local.conf>`

Building your devstack
----------------------

* Copy the appropriate sample local.conf file into the devstack folder on your
  virtual machine, make sure to name it ``local.conf``
* Make sure to read inline comments and customize values where necessary
* If you would like to run minimal services in your stack, or allow devstack
  to bootstrap tempest testing framework for you, see :ref:`more-customization`
* Finally, run the ``stack.sh`` script from within the devstack directory. We
  recommend that your run this inside a screen or tmux session because it
  could take a while::

    ./stack.sh

* After the script completes, you should have manila services running. You can
  verify that the services are running with the following commands::

    $ systemctl status devstack@m-sch
    $ systemctl status devstack@m-shr
    $ systemctl status devstack@m-dat

* By default, devstack sets up manila-api behind apache. The service name is
  ``httpd`` on Red Hat based systems and ``apache2`` on Debian based systems.

* You may also use your "demo" credentials to invoke the command line
  clients::

    $ source DEVSTACK_DIR/openrc admin demo
    $ manila service-list

* The logs are accessible through ``journalctl``. The following commands let
  you query logs. You may use the ``-f`` option to tail these logs::

    $ journalctl -a -o short-precise --unit devstack@m-sch
    $ journalctl -a -o short-precise --unit devstack@m-shr
    $ journalctl -a -o short-precise --unit devstack@m-dat

* If running behind apache, the manila-api logs will be in
  ``/var/log/httpd/manila_api.log`` (Red Hat) or
  in ``/var/log/apache2/manila_api.log`` (Debian).

* Manila UI will now be available through OpenStack Horizon; look for the
  Shares tab under Project > Share.


.. _more-customization:

More devstack customizations
----------------------------

Testing branches and changes submitted for review
`````````````````````````````````````````````````

To test a patch in review::

    enable_plugin manila https://opendev.org/openstack/manila <ref>

If the ref is from review.opendev.org, it is structured as::

    refs/changes/<last two digits of review number>/<review number>/<patchset number>

For example, if you want to test patchset 4 of https://review.opendev.org/#/c/614170/,
you can provide this in your ``local.conf``::

    enable_plugin manila https://opendev.org/openstack/manila refs/changes/70/614170/4

ref can also simply be a stable branch name, for example::

    enable_plugin manila https://opendev.org/openstack/manila stable/train

Limiting the services enabled in your stack
````````````````````````````````````````````

Manila needs only a message queue (rabbitmq) and a database (mysql,
postgresql) to operate. Additionally, keystone service provides project
administration if necessary, all other OpenStack services are not necessary
to set up a basic test system. [#f1]_ [#f2]_

You can add the following to your ``local.conf`` to deploy your stack in a
minimal fashion. This saves you a lot of time and resources, but could limit
your testing::

    ENABLED_SERVICES=key,mysql,rabbit,tempest,manila,m-api,m-sch,m-shr,m-dat

Optionally, you can deploy with Manila, Nova, Neutron, Glance and Tempest::

    ENABLED_SERVICES=key,mysql,rabbit,tempest,g-api
    ENABLED_SERVICES+=n-api,n-cpu,n-cond,n-sch,n-crt,n-cauth,n-obj,placement-api,placement-client
    ENABLED_SERVICES+=q-svc,q-dhcp,q-meta,q-l3,q-agt
    ENABLED_SERVICES+=tempest

You can also enable ``tls-proxy`` with ``ENABLED_SERVICES`` to allow
devstack to use Apache and setup a TLS proxy to terminate TLS connections.
Using tls-proxy secures all OpenStack service API endpoints and inter-service
communication on your devstack.

Bootstrapping Tempest
`````````````````````

Add the following options in your ``local.conf`` to set up tempest::

    ENABLE_ISOLATED_METADATA=True
    TEMPEST_USE_TEST_ACCOUNTS=True
    TEMPEST_ALLOW_TENANT_ISOLATION=False
    TEMPEST_CONCURRENCY=8


.. [#f1] The Generic driver cannot be run without deploying Cinder, Nova,
         Glance and Neutron.
.. [#f2] You must enable Horizon to use manila-ui. Horizon will not work
         well when Nova, Cinder, Glance and Neutron are not enabled.
