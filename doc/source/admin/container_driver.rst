..
      Copyright 2016 Mirantis Inc.
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

Container Driver
================

The Container driver provides a lightweight solution for share servers
management. It allows to use Docker containers for hosting userspace
shared file systems services.


Supported operations
--------------------

- Create CIFS share;
- Delete CIFS share;
- Allow user access to CIFS share;
- Deny user access to CIFS share;
- Extend CIFS share.

Restrictions
------------

- Current implementation has been tested only on Ubuntu. Devstack plugin won't
  work on other distributions however it should be possible to install
  prerequisites and set the driver up manually;
- The only supported protocol is CIFS;
- The following features are not implemented:
  * Manage/unmanage share;
  * Shrink share;
  * Create/delete snapshots;
  * Create a share from a snapshot;
  * Manage/unmanage snapshots.

Known problems
--------------

- May demonstrate unstable behaviour when running concurrently. It is strongly
  suggested that the driver should be used with extreme care in cases
  other than building lightweight development and testing environments.

Setting up container driver with devstack
=========================================

The driver could be set up via devstack. This requires the following update to
local.conf:

.. code-block:: ini

 enable_plugin manila https://git.openstack.org/openstack/manila <ref>
 MANILA_BACKEND1_CONFIG_GROUP_NAME=london
 MANILA_SHARE_BACKEND1_NAME=LONDON
 MANILA_OPTGROUP_london_driver_handles_share_servers=True
 MANILA_OPTGROUP_london_neutron_host_id=<hostname>
 SHARE_DRIVER=manila.share.drivers.container.driver.ContainerShareDriver
 SHARE_BACKING_FILE_SIZE=<backing file size>
 MANILA_DEFAULT_SHARE_TYPE_EXTRA_SPECS='snapshot_support=false'

where <ref> is change reference, which could be copied from gerrit web-interface,
<hostname> is the name of the host with running neutron



Setting Container Driver Up Manually
====================================

This section describes steps needed to be performed to set the driver up
manually. The driver has been tested on Ubuntu 14.04, thus in case of
any other distribution package names might differ.
The following packages must be installed:

- docker.io

One can verify if the package is installed by issuing ``sudo docker info``
command. In case of normal operation it should return docker usage statistics.
In case it fails complaining on inaccessible socket try installing
``apparmor``. Please note that docker usage requires superuser privileges.

After docker is successfully installed a docker image containing necessary
packages must be provided. Currently such image could be downloaded from
https://github.com/a-ovchinnikov/manila-image-elements-lxd-images/releases/download/0.1.0/manila-docker-container.tar.gz
The image has to be unpacked but not untarred. This could be achieved by
running 'gzip -d <imagename>' command. Resulting tar-archive of the
image could be uploaded to docker via

.. code-block:: console

  sudo docker load --input <imagename.tar>

If the previous command finished successfully you will be able to see the image
in the image list:

.. code-block:: console

  sudo docker images

The driver expects to find a folder /tmp/shares on the host where it is running
as well as a logical volume group "manila_docker_volumes".

When installing the driver manually one must make sure that 'brctl' and
'docker' commands are present in the /etc/manila/rootwrap.d/share.filters
and could be executed as root.

Finally to use the driver one must add a backend to the config file
containing the following  settings:

.. code-block:: ini

  driver_handles_share_servers = True
  share_driver = manila.share.drivers.container.driver.ContainerShareDriver
  neutron_host_id = <hostname>

where <hostname> is the name of the host running neutron. (In case of single
VM devstack it is VM's name).

After restarting manila services you should be able to use the driver.
