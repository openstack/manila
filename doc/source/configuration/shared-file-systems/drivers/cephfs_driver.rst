..
      Copyright 2016 Red Hat, Inc.
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

=============
CephFS driver
=============

The CephFS driver enables manila to export shared filesystems backed by Ceph's
File System (CephFS) using either the Ceph network protocol or NFS protocol.
Guests require a native Ceph client or an NFS client in order to mount the
filesystem.

When guests access CephFS using the native Ceph protocol, access is
controlled via Ceph's cephx authentication system. If a user requests
share access for an ID, Ceph creates a corresponding Ceph auth ID and a secret
key if they do not already exist, and authorizes the ID to access the share.
The client can then mount the share using the ID and the secret key. To learn
more about configuring Ceph clients to access the shares created using this
driver, please see the `Ceph documentation`_

And when guests access CephFS through NFS, an NFS-Ganesha server (or CephFS
NFS service) mediates access to CephFS. The driver enables access control by
managing the NFS-Ganesha server's exports.


Supported Operations
~~~~~~~~~~~~~~~~~~~~

The following operations are supported with CephFS backend:

- Create, delete, update and list share
- Allow/deny access to share

  * Only ``cephx`` access type is supported for CephFS native protocol.
  * Only ``ip`` access type is supported for NFS protocol.
  * ``read-only`` and ``read-write`` access levels are supported.

- Extend/shrink share
- Create, delete, update and list snapshot
- Create, delete, update and list share groups
- Delete and list share group snapshots

.. important:: Share group snapshot creation is no longer supported in mainline
               CephFS. This feature has been removed from manila W release.

Prerequisites
~~~~~~~~~~~~~

.. important:: A manila share backed by CephFS is only as good as the
               underlying filesystem. Take care when configuring your Ceph
               cluster, and consult the latest guidance on the use of
               CephFS in the `Ceph documentation`_.



Ceph testing matrix
-------------------

As Ceph and Manila continue to grow, it is essential to test and support
combinations of releases supported by both projects. However, there is
little community bandwidth to cover all of them. For simplicity sake,
we are focused on testing (and therefore supporting) the current Ceph
active releases. Check out the list of Ceph active releases `here <https://docs.ceph.com/en/latest/releases/general/>`_.

Below is the current state of testing for Ceph releases with this project.
Adjacent components such as `devstack-plugin-ceph <https://opendev.org/openstack/devstack-plugin-ceph>`_
and `tripleo <https://opendev.org/openstack/tripleo-heat-templates>`_ are
added to the table below. Contributors to those projects can determine what
versions of ceph are tested and supported with manila by those components;
however, their state is presented here for ease of access.

+-----------------------+---------+----------------------+
|   OpenStack release   | Manila  | devstack-plugin-ceph |
+=======================+=========+======================+
| Wallaby               | Pacific | Pacific              |
+-----------------------+---------+----------------------+
| Xena                  | Pacific | Quincy               |
+-----------------------+---------+----------------------+
| Yoga                  | Quincy  | Quincy               |
+-----------------------+---------+----------------------+
| Zed                   | Quincy  | Quincy               |
+-----------------------+---------+----------------------+
| 2023.1 ("Antelope")   | Quincy  | Quincy               |
+-----------------------+---------+----------------------+
| 2023.2 ("Bobcat")     | Quincy  | Reef                 |
+-----------------------+---------+----------------------+
| 2024.1 ("Caracal")    | Reef    | Reef                 |
+-----------------------+---------+----------------------+
| 2024.2 ("Dalmation")  | Reef    | Reef                 |
+-----------------------+---------+----------------------+

Additionally, it is expected that the version of the Ceph client
available to manila is aligned with the Ceph server version. Mixing
server and client versions is strongly unadvised.

In case of using the NFS Ganesha driver, it's also a good practice to use
the versions that align with the Ceph version of choice.

Common Prerequisites
--------------------

- A Ceph cluster with a filesystem configured (See `Create ceph filesystem`_ on
  how to create a filesystem.)
- ``python3-rados`` and ``python3-ceph-argparse`` packages installed in the
  servers running the :term:`manila-share` service.
- Network connectivity between your Ceph cluster's public network and the
  servers running the :term:`manila-share` service.

For CephFS native shares
------------------------

- Ceph client installed in the guest
- Network connectivity between your Ceph cluster's public network and guests.
  See :ref:`security_cephfs_native`.

For CephFS NFS shares
---------------------

There are two ways for the CephFS driver to provision and export CephFS
shares via NFS. Both ways involve the user space NFS service, NFS-Ganesha.

Since the Quincy release of Ceph, there is support to create and manage an
NFS-Ganesha based "ceph nfs" service. This service can be clustered, i.e.,
it can have one or more active NFS services working in tandem to provide
high availability. You can also optionally deploy an ingress service to
front-end this cluster natively using ceph's management commands. Doing this
allows ease of management of an NFS service to serve CephFS shares securely as
well provides an active/active high availability configuration for it which
may be highly desired in production environments.
Please `follow the ceph documentation <https://docs.ceph
.com/en/latest/cephadm/services/nfs/>`_ for instructions to deploy a cluster
with necessary configuration. With an NFS cluster, the CephFS driver uses
Ceph mgr APIs to create and manipulate exports when share access rules are
created and deleted.

The CephFS driver can also work with Manila's in-built NFS-Ganesha driver to
interface with an independent, standalone NFS-Ganesha service that is not
orchestrated via Ceph. Unlike when under Ceph's management, the high
availability of the NFS server must be externally managed. Typically deployers
use Pacemaker/Corosync for providing active/passive availability for such a
standalone NFS-Ganesha service. See `the NFS-Ganesha documentation
<https://github.com/nfs-ganesha/nfs-ganesha/wiki/NFS-Ganesha-and-High-Availability>`_
for more information. The CephFS driver can be configured to store the NFS
recovery data in a RADOS pool to facilitate the server's recovery if the
service is shut down and respawned due to failures/outages.

Since the Antelope (2023.1) release of OpenStack Manila, we recommend the
use of ceph orchestrator deployed NFS service. The use of a standalone
NFS-Ganesha service is deprecated as of the Caracal release (2024.1) and
support will be removed in a future release.

The CephFS driver does not specify an NFS protocol version when setting up
exports. This is to allow the deployer to configure the appropriate NFS
protocol version/s directly in NFS-Ganesha configuration. NFS-Ganesha enables
both NFS version 3 and version 4.x by virtue of default configuration.
Please note that there are many differences at the protocol level
between NFS versions. Many deployers enable only NFS version 4.1 (and beyond)
to take advantage of enhancements in locking, security and ease of port
management. Be aware that not all clients support the latest versions
of NFS.

The pre-requisites for NFS are:

- NFS client installed in the guest.
- Network connectivity between your Ceph cluster's public network and
  NFS-Ganesha service.
- Network connectivity between your NFS-Ganesha service and the client
  mounting the manila share.
- Appropriate firewall rules to permit port access
  between the clients and the NFS-Ganesha service.

If you're deploying a standalone NFS-Ganesha service, we recommend using
the latest version of NFS-Ganesha. The server must be deployed with at least
NFS-Ganesha version 3.5.

.. _authorize_ceph_driver:

Authorizing the driver to communicate with Ceph
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Capabilities required for the Ceph manila identity have changed from the Wallaby
release. The Ceph manila identity configured no longer needs any MDS capability.
The MON and OSD capabilities can be reduced as well. However new MGR
capabilities are now required. If not accorded, the driver cannot
communicate to the Ceph Cluster.

.. important::

    The driver in the Wallaby (or later) release requires a Ceph identity
    with a different set of Ceph capabilities when compared to the driver
    in a pre-Wallaby release.

    When upgrading to Wallaby you'll also have to update the capabilities
    of the Ceph identity used by the driver (refer to `Ceph user capabilities docs
    <https://docs.ceph.com/en/octopus/rados/operations/user-management/#modify-user-capabilities>`_)
    E.g. a native driver that already uses `client.manila` Ceph identity,
    issue command `ceph auth caps client.manila mon 'allow r' mgr 'allow rw'`

If you are deploying the CephFS driver with Native CephFS or using an NFS
service deployed with ceph management commands, the auth ID should be set as
follows:

.. code-block:: console

    ceph auth get-or-create client.manila -o manila.keyring \
      mgr 'allow rw' \
      mon 'allow r'

If you're deploying the CephFS NFS driver with a standalone NFS-Ganesha
service, we use a specific pool to store exports (configurable with the
config option "ganesha_rados_store_pool_name"). The `client.manila` ceph
user requires permission to access this pool. So, the auth ID should be set
as follows:

.. code-block:: console

    ceph auth get-or-create client.manila -o manila.keyring \
      osd 'allow rw pool=<ganesha_rados_store_pool_name>" \
      mgr 'allow rw' \
      mon 'allow r'

``manila.keyring``, along with your ``ceph.conf`` file, will then need to be
placed on the server running the :term:`manila-share` service.

.. important::

    To communicate with the Ceph backend, a CephFS driver instance
    (represented as a backend driver section in manila.conf) requires its own
    Ceph auth ID that is not used by other CephFS driver instances running in
    the same controller node.

In the server running the :term:`manila-share` service, you can place the
``ceph.conf`` and ``manila.keyring`` files in the /etc/ceph directory. Set the
same owner for the :term:`manila-share` process and the ``manila.keyring``
file. Add the following section to the ``ceph.conf`` file.

.. code-block:: ini

    [client.manila]
    client mount uid = 0
    client mount gid = 0
    log file = /opt/stack/logs/ceph-client.manila.log
    admin socket = /opt/stack/status/stack/ceph-$name.$pid.asok
    keyring = /etc/ceph/manila.keyring

It is advisable to modify the Ceph client's admin socket file and log file
locations so that they are co-located with manila services's pid files and
log files respectively.


Enabling snapshot support in Ceph backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

From Ceph Nautilus, all new filesystems created on Ceph have snapshots
enabled by default. If you've upgraded your ceph cluster and want to enable
snapshots on a pre-existing filesystem, you can do so:

.. code-block:: console

    ceph fs set {fs_name} allow_new_snaps true

Configuring CephFS backend in manila.conf
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configure CephFS native share backend in manila.conf
----------------------------------------------------

Add CephFS to ``enabled_share_protocols`` (enforced at manila api layer). In
this example we leave NFS and CIFS enabled, although you can remove these
if you will only use a CephFS backend:

.. code-block:: ini

    enabled_share_protocols = NFS,CIFS,CEPHFS

Create a section like this to define a CephFS native backend:

.. code-block:: ini

    [cephfsnative1]
    driver_handles_share_servers = False
    share_backend_name = CEPHFSNATIVE1
    share_driver = manila.share.drivers.cephfs.driver.CephFSDriver
    cephfs_conf_path = /etc/ceph/ceph.conf
    cephfs_protocol_helper_type = CEPHFS
    cephfs_auth_id = manila
    cephfs_cluster_name = ceph
    cephfs_filesystem_name = cephfs

Set ``driver-handles-share-servers`` to ``False`` as the driver does not
manage the lifecycle of ``share-servers``. For the driver backend to expose
shares via the native Ceph protocol, set ``cephfs_protocol_helper_type`` to
``CEPHFS``.

Then edit ``enabled_share_backends`` to point to the driver's backend section
using the section name. In this example we are also including another backend
("generic1"), you would include whatever other backends you have configured.

Finally, edit ``cephfs_filesystem_name`` with the name of the Ceph filesystem
(also referred to as a CephFS volume) you want to use.
If you have more than one Ceph filesystem in the cluster, you need to set this
option.

.. important::
  For Native CephFS shares, the backing ``cephfs_filesystem_name`` is visible
  to end users through the ``__mount_options`` metadata. Make sure to add
  the ``__mount_options`` metadata key to the list of admin only modifiable
  metadata keys (``admin_only_metadata``), as explained in the
  :ref:`additional configuration options page <manila-common>`.


.. code-block:: ini

    enabled_share_backends = generic1, cephfsnative1


Configure CephFS NFS share backend in manila.conf
-------------------------------------------------

.. note::

    Prior to configuring the Manila CephFS driver to use NFS, you must have
    installed and configured NFS-Ganesha. If you're using ceph orchestrator to
    create the NFS-Ganesha service and manage it alongside ceph, refer to
    the Ceph documentation on how to setup this service. If you're using an
    independently deployed standalone NFS-Ganesha service,  refer to the
    `NFS-Ganesha setup guide <../contributor/ganesha.html#nfs-ganesha-configuration>`_.

Add NFS to ``enabled_share_protocols`` if it's not already there:

.. code-block:: ini

    enabled_share_protocols = NFS,CIFS,CEPHFS


Create a section to define a CephFS NFS share backend.
The following is an example for using a ceph orchestrator deployed NFS service:

.. code-block:: ini

    [cephfsnfs1]
    driver_handles_share_servers = False
    share_backend_name = CEPHFSNFS1
    share_driver = manila.share.drivers.cephfs.driver.CephFSDriver
    cephfs_protocol_helper_type = NFS
    cephfs_conf_path = /etc/ceph/ceph.conf
    cephfs_auth_id = manila
    cephfs_cluster_name = ceph
    cephfs_filesystem_name = cephfs
    cephfs_nfs_cluster_id = mycephfsnfscluster


The following is an example for using an independently deployed standalone
NFS-Ganesha service:

.. code-block:: ini

    [cephfsnfs1]
    driver_handles_share_servers = False
    share_backend_name = CEPHFSNFS1
    share_driver = manila.share.drivers.cephfs.driver.CephFSDriver
    cephfs_protocol_helper_type = NFS
    cephfs_conf_path = /etc/ceph/ceph.conf
    cephfs_auth_id = manila
    cephfs_cluster_name = ceph
    cephfs_filesystem_name = cephfs
    cephfs_ganesha_server_is_remote= False
    cephfs_ganesha_server_ip = 172.24.4.3
    ganesha_rados_store_enable = True
    ganesha_rados_store_pool_name = cephfs_data


The following options are set in the driver backend sections above:

* ``driver-handles-share-servers`` to ``False`` as the driver does not
  manage the lifecycle of ``share-servers``.

* ``cephfs_protocol_helper_type`` to ``NFS`` to allow NFS protocol access to
  the CephFS backed shares.

* ``ceph_auth_id`` to the ceph auth ID created in :ref:`authorize_ceph_driver`.

* ``cephfs_nfs_cluster_id`` - Use this option with a ceph orchestrator deployed
  clustered NFS service. Set it to the name of the cluster created with the
  ceph orchestrator.

* ``cephfs_ganesha_server_is_remote`` - Use this option with a standalone
  NFS-Ganesha service. Set it to False if the NFS-ganesha server is
  co-located with the :term:`manila-share`  service. If the NFS-Ganesha
  server is remote, then set the options to ``True``, and set other options
  such as ``cephfs_ganesha_server_ip``, ``cephfs_ganesha_server_username``,
  and ``cephfs_ganesha_server_password`` (or ``cephfs_ganesha_path_to_private_key``)
  to allow the driver to manage the NFS-Ganesha export entries over SSH.

* ``cephfs_ganesha_server_ip`` - Use this option with a standalone
  NFS-Ganesha service. Set it to the ganesha server IP address. It is
  recommended to set this option even if the ganesha server is co-located
  with the :term:`manila-share` service.

* ``ganesha_rados_store_enable`` - Use this option with a standalone
  NFS-Ganesha service. Set it to True or False. Setting this option to
  True allows NFS Ganesha to store exports and its export counter in Ceph
  RADOS objects. We recommend setting this to True and using a RADOS object
  since it is useful for highly available NFS-Ganesha deployments to store
  their configuration efficiently in an already available distributed
  storage system.

* ``ganesha_rados_store_pool_name`` - Use this option with a standalone
  NFS-Ganesha service. Set it to the name of the RADOS pool you have
  created for use with NFS-Ganesha. Set this option only if also setting
  the ``ganesha_rados_store_enable`` option to True. If you want to use
  one of the backend CephFS's RADOS pools, then using CephFS's data pool is
  preferred over using its metadata pool.

Edit ``enabled_share_backends`` to point to the driver's backend section
using the section name, ``cephfsnfs1``.

Finally, edit ``cephfs_filesystem_name`` with the name of the Ceph filesystem
(also referred to as a CephFS volume) you want to use.
If you have more than one Ceph filesystem in the cluster, you need to set this
option.

.. code-block:: ini

    enabled_share_backends = generic1, cephfsnfs1


Space considerations
~~~~~~~~~~~~~~~~~~~~

The CephFS driver reports total and free capacity available across the Ceph
cluster to manila to allow provisioning. All CephFS shares are thinly
provisioned, i.e., empty shares do not consume any significant space
on the cluster. The CephFS driver does not allow controlling oversubscription
via manila. So, as long as there is free space, provisioning will continue,
and eventually this may cause your Ceph cluster to be over provisioned and
you may run out of space if shares are being filled to capacity. It is advised
that you use Ceph's monitoring tools to monitor space usage and add more
storage when required in order to honor space requirements for provisioned
manila shares. You may use the driver configuration option
``reserved_share_percentage`` to prevent manila from filling up your Ceph
cluster, and allow existing shares to grow.

Creating shares
~~~~~~~~~~~~~~~

Create CephFS native share
--------------------------

The default share type may have ``driver_handles_share_servers`` set to True.
Configure a share type suitable for CephFS native share:

.. code-block:: console

    openstack share type create cephfsnativetype false
    openstack share type set cephfsnativetype --extra-specs vendor_name=Ceph storage_protocol=CEPHFS

Then create a share,

.. code-block:: console

    openstack share create --share-type cephfsnativetype --name cephnativeshare1 cephfs 1

Note the export location of the share:

.. code-block:: console

    openstack share export location list cephnativeshare1

The export location of the share contains the Ceph monitor (mon) addresses and
ports, and the path to be mounted. It is of the form,
``{mon ip addr:port}[,{mon ip addr:port}]:{path to be mounted}``

Create CephFS NFS share
-----------------------

Configure a share type suitable for CephFS NFS share:

.. code-block:: console

    openstack share type create cephfsnfstype false
    openstack share type set cephfsnfstype --extra-specs vendor_name=Ceph storage_protocol=NFS

Then create a share:

.. code-block:: console

    openstack share create --share-type cephfsnfstype --name cephnfsshare1 nfs 1

Note the export location of the share:

.. code-block:: console

    openstack share export location list cephnfsshare1

The export location of the share contains the IP address of the NFS-Ganesha
server and the path to be mounted. It is of the form,
``{NFS-Ganesha server address}:{path to be mounted}``


Allowing access to shares
~~~~~~~~~~~~~~~~~~~~~~~~~

Allow access to CephFS native share
-----------------------------------

Allow Ceph auth ID ``alice`` access to the share using ``cephx`` access type.

.. code-block:: console

    openstack share access create cephnativeshare1 cephx alice

Note the access status, and the access/secret key of ``alice``.

.. code-block:: console

    openstack share access list cephnativeshare1


Allow access to CephFS NFS share
--------------------------------

Allow a guest access to the share using ``ip`` access type.

.. code-block:: console

    openstack share access create cephnfsshare1 ip 172.24.4.225


Mounting CephFS shares
~~~~~~~~~~~~~~~~~~~~~~

.. note::
  The cephfs filesystem name will be available in the ``__mount_options``
  share's metadata.

Mounting CephFS native share using FUSE client
----------------------------------------------

Using the secret key of the authorized ID ``alice`` create a keyring file,
``alice.keyring`` like:

.. code-block:: ini

    [client.alice]
            key = AQA8+ANW/4ZWNRAAOtWJMFPEihBA1unFImJczA==


Using the mon IP addresses from the share's export location, create a
configuration file, ``ceph.conf`` like:

.. code-block:: ini

    [client]
            client quota = true
            mon host = 192.168.1.7:6789, 192.168.1.8:6789, 192.168.1.9:6789

Finally, mount the filesystem, substituting the filenames of the keyring and
configuration files you just created, and substituting the path to be mounted
from the share's export location:

.. code-block:: console

    sudo ceph-fuse ~/mnt \
    --id=alice \
    --conf=./ceph.conf \
    --keyring=./alice.keyring \
    --client-mountpoint=/volumes/_nogroup/4c55ad20-9c55-4a5e-9233-8ac64566b98c


Mounting CephFS native share using Kernel client
------------------------------------------------

If you have the ``ceph-common`` package installed in the client host, you can
use the kernel client to mount CephFS shares.

.. important::

    If you choose to use the kernel client rather than the FUSE client the
    share size limits set in manila may not be obeyed in versions of kernel
    older than 4.17 and Ceph versions older than mimic. See the
    `quota limitations documentation`_ to understand CephFS quotas.

The mount command is as follows:

.. code-block:: console

    mount -t ceph {mon1 ip addr}:6789,{mon2 ip addr}:6789,{mon3 ip addr}:6789:/ \
        {mount-point} -o name={access-id},secret={access-key}

With our earlier examples, this would be:

.. code-block:: console

    mount -t ceph 192.168.1.7:6789, 192.168.1.8:6789, 192.168.1.9:6789:/ \
        /volumes/_nogroup/4c55ad20-9c55-4a5e-9233-8ac64566b98c \
        -o name=alice,secret='AQA8+ANW/4ZWNRAAOtWJMFPEihBA1unFImJczA=='


Mount CephFS NFS share using NFS client
---------------------------------------

In the guest, mount the share using the NFS client and knowing the share's
export location.

.. code-block:: ini

    sudo mount -t nfs 172.24.4.3:/volumes/_nogroup/6732900b-32c1-4816-a529-4d6d3f15811e /mnt/nfs/

Known restrictions
~~~~~~~~~~~~~~~~~~

- A CephFS driver instance, represented as a backend driver section in
  manila.conf, requires a Ceph auth ID unique to the backend Ceph Filesystem.
  Using a non-unique Ceph auth ID will result in the driver unintentionally
  evicting other CephFS clients using the same Ceph auth ID to connect to the
  backend.

- Snapshots are read-only. A user can read a snapshot's contents from the
  ``.snap/{manila-snapshot-id}_{unknown-id}`` folder within the mounted
  share.


Security
~~~~~~~~

- Each share's data is mapped to a distinct Ceph RADOS namespace. A guest is
  restricted to access only that particular RADOS namespace.
  https://docs.ceph.com/en/latest/cephfs/file-layouts/

.. _security_cephfs_native:

Security with CephFS native share backend
-----------------------------------------

As the guests need direct access to Ceph's public network, CephFS native
share backend is suitable only in private clouds where guests can be trusted.

.. _Ceph documentation: https://docs.ceph.com/en/latest/cephfs/
.. _Create ceph filesystem: https://docs.ceph.com/en/latest/cephfs/createfs/
.. _limitations on snapshots: https://docs.ceph.com/en/latest/dev/cephfs-snapshots/
.. _quota limitations documentation: https://docs.ceph.com/en/latest/cephfs/quota/#limitations

Configuration Reference
-----------------------

.. include:: ../../tables/manila-cephfs.inc


The :mod:`manila.share.drivers.cephfs.driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.cephfs.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
