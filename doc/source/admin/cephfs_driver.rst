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
key, if they do not already exist, and authorizes the ID to access the share.
The client can then mount the share using the ID and the secret key. To learn
more about configuring Ceph clients to access the shares created using this
driver, please see the Ceph documentation (http://docs.ceph.com/docs/master/cephfs/).
If you choose to use the kernel client rather than the FUSE client, the share
size limits set in manila may not be obeyed.

And when guests access CephFS through NFS, an NFS-Ganesha server mediates
access to CephFS. The driver enables access control by managing the NFS-Ganesha
server's exports.


Supported Operations
~~~~~~~~~~~~~~~~~~~~

The following operations are supported with CephFS backend:

- Create/delete share
- Allow/deny CephFS native protocol access to share

  * Only ``cephx`` access type is supported for CephFS native protocol.
  * ``read-only`` access level is supported in Newton or later versions
    of manila.
  * ``read-write`` access level is supported in Mitaka or later versions
    of manila.

  (or)

  Allow/deny NFS access to share

  * Only ``ip`` access type is supported for NFS protocol.
  * ``read-only`` and ``read-write`` access levels are supported in Pike or
    later versions of manila.

- Extend/shrink share
- Create/delete snapshot
- Create/delete consistency group (CG)
- Create/delete CG snapshot

.. warning::

    CephFS currently supports snapshots as an experimental feature, therefore
    the snapshot support with the CephFS Native driver is also experimental
    and should not be used in production environments. For more information,
    see
    (http://docs.ceph.com/docs/master/cephfs/experimental-features/#snapshots).


Prerequisites
~~~~~~~~~~~~~

.. important:: A manila share backed by CephFS is only as good as the
               underlying filesystem. Take care when configuring your Ceph
               cluster, and consult the latest guidance on the use of
               CephFS in the Ceph documentation (
               http://docs.ceph.com/docs/master/cephfs/)

For CephFS native shares
------------------------

- Mitaka or later versions of manila.
- Jewel or later versions of Ceph.
- A Ceph cluster with a filesystem configured (
  http://docs.ceph.com/docs/master/cephfs/createfs/)
- ``ceph-common`` package installed in the servers running the
  :term:`manila-share` service.
- Ceph client installed in the guest, preferably the FUSE based client,
  ``ceph-fuse``.
- Network connectivity between your Ceph cluster's public network and the
  servers running the :term:`manila-share` service.
- Network connectivity between your Ceph cluster's public network and guests.
  See :ref:security_cephfs_native

For CephFS NFS shares
---------------------

- Pike or later versions of manila.
- Kraken or later versions of Ceph.
- 2.5 or later versions of NFS-Ganesha.
- A Ceph cluster with a filesystem configured (
  http://docs.ceph.com/docs/master/cephfs/createfs/)
- ``ceph-common`` package installed in the servers running the
  :term:`manila-share` service.
- NFS client installed in the guest.
- Network connectivity between your Ceph cluster's public network and the
  servers running the :term:`manila-share` service.
- Network connectivity between your Ceph cluster's public network and
  NFS-Ganesha server.
- Network connectivity between your NFS-Ganesha server and the manila
  guest.

.. _authorize_ceph_driver:

Authorizing the driver to communicate with Ceph
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run the following commands to create a Ceph identity for a driver instance
to use:

.. code-block:: console

    read -d '' MON_CAPS << EOF
    allow r,
    allow command "auth del",
    allow command "auth caps",
    allow command "auth get",
    allow command "auth get-or-create"
    EOF

    ceph auth get-or-create client.manila -o manila.keyring \
    mds 'allow *' \
    osd 'allow rw' \
    mon "$MON_CAPS"


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

Enable snapshots in Ceph if you want to use them in manila:

.. code-block:: console

    ceph mds set allow_new_snaps true --yes-i-really-mean-it

.. warning::
    Note that the snapshot support for the CephFS driver is experimental and is
    known to have several caveats for use. Only enable this and the
    equivalent ``manila.conf`` option if you understand these risks. See
    (http://docs.ceph.com/docs/master/cephfs/experimental-features/#snapshots)
    for more details.


Configuring CephFS backend in manila.conf
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Configure CephFS native share backend in manila.conf
----------------------------------------------------

Add CephFS to ``enabled_share_protocols`` (enforced at manila api layer). In
this example we leave NFS and CIFS enabled, although you can remove these
if you will only use CephFS:

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
    cephfs_enable_snapshots = False

Set ``driver-handles-share-servers`` to ``False`` as the driver does not
manage the lifecycle of ``share-servers``. To let the driver perform snapshot
related operations, set ``cephfs_enable_snapshots`` to True. For the driver
backend to expose shares via the the native Ceph protocol, set
``cephfs_protocol_helper_type`` to ``CEPHFS``.

Then edit ``enabled_share_backends`` to point to the driver's backend section
using the section name. In this example we are also including another backend
("generic1"), you would include whatever other backends you have configured.


.. note::

    For Mitaka, Newton, and Ocata releases, the ``share_driver`` path
    was ``manila.share.drivers.cephfs.cephfs_native.CephFSNativeDriver``


.. code-block:: ini

    enabled_share_backends = generic1, cephfsnative1


Configure CephFS NFS share backend in manila.conf
-------------------------------------------------

Add NFS to ``enabled_share_protocols`` if it's not already there:

.. code-block:: ini

    enabled_share_protocols = NFS,CIFS,CEPHFS


Create a section to define a CephFS NFS share backend:

.. code-block:: ini

    [cephfsnfs1]
    driver_handles_share_servers = False
    share_backend_name = CEPHFSNFS1
    share_driver = manila.share.drivers.cephfs.driver.CephFSDriver
    cephfs_protocol_helper_type = NFS
    cephfs_conf_path = /etc/ceph/ceph.conf
    cephfs_auth_id = manila
    cephfs_cluster_name = ceph
    cephfs_enable_snapshots = False
    cephfs_ganesha_server_is_remote= False
    cephfs_ganesha_server_ip = 172.24.4.3


The following options are set in the driver backend section above:

* ``driver-handles-share-servers`` to ``False`` as the driver does not
  manage the lifecycle of ``share-servers``.

* ``cephfs_protocol_helper_type`` to ``NFS`` to allow NFS protocol access to
  the CephFS backed shares.

* ``ceph_auth_id`` to the ceph auth ID created in :ref:`authorize_ceph_driver`.

* ``cephfs_ganesha_server_is_remote`` to False if the NFS-ganesha server is
  co-located with the :term:`manila-share`  service. If the NFS-Ganesha
  server is remote, then set the options to ``True``, and set other options
  such as ``cephfs_ganesha_server_ip``, ``cephfs_ganesha_server_username``,
  and ``cephfs_ganesha_server_password`` (or ``cephfs_ganesha_path_to_private_key``)
  to allow the driver to manage the NFS-Ganesha export entries over SSH.

* ``cephfs_ganesha_server_ip`` to the ganesha server IP address. It is
  recommended to set this option even if the ganesha server is co-located
  with the :term:`manila-share` service.


With NFS-Ganesha (v2.5.4 or later), Ceph (v12.2.2 or later), the driver (Queens
or later) can store NFS-Ganesha exports and export counter in Ceph RADOS
objects. This is useful for highly available NFS-Ganesha deployments to store
its configuration efficiently in an already available distributed storage
system. Set additional options in the NFS driver section to enable the driver
to do this.

.. code-block:: ini

    [cephfsnfs1]
    ganesha_rados_store_enable = True
    ganesha_rados_store_pool_name = cephfs_data
    driver_handles_share_servers = False
    share_backend_name = CEPHFSNFS1
    share_driver = manila.share.drivers.cephfs.driver.CephFSDriver
    cephfs_protocol_helper_type = NFS
    cephfs_conf_path = /etc/ceph/ceph.conf
    cephfs_auth_id = manila
    cephfs_cluster_name = ceph
    cephfs_enable_snapshots = False
    cephfs_ganesha_server_is_remote= False
    cephfs_ganesha_server_ip = 172.24.4.3


The following ganesha library (See manila's ganesha library documentation for
more details) related options are set in the driver backend section above:

* ``ganesha_rados_store_enable`` to True for persisting Ganesha exports and
  export counter in Ceph RADOS objects.

* ``ganesha_rados_store_pool_name`` to the Ceph RADOS pool that stores Ganesha
  exports and export counter objects. If you want to use one of the backend
  CephFS's RADOS pools, then using CephFS's data pool is preferred over using
  its metadata pool.

Edit ``enabled_share_backends`` to point to the driver's backend section
using the section name, ``cephfnfs1``.

.. code-block:: ini

    enabled_share_backends = generic1, cephfsnfs1


Creating shares
~~~~~~~~~~~~~~~

Create CephFS native share
--------------------------

The default share type may have ``driver_handles_share_servers`` set to True.
Configure a share type suitable for CephFS native share:

.. code-block:: console

     manila type-create cephfsnativetype false
     manila type-key cephfsnativetype set vendor_name=Ceph storage_protocol=CEPHFS

Then create yourself a share:

.. code-block:: console

    manila create --share-type cephfsnativetype --name cephnativeshare1 cephfs 1

Note the export location of the share:

.. code-block:: console

    manila share-export-location-list cephnativeshare1

The export location of the share contains the Ceph monitor (mon) addresses and
ports, and the path to be mounted. It is of the form,
``{mon ip addr:port}[,{mon ip addr:port}]:{path to be mounted}``

Create CephFS NFS share
-----------------------

Configure a share type suitable for CephFS NFS share:

.. code-block:: console

     manila type-create cephfsnfstype false
     manila type-key cephfsnfstype set vendor_name=Ceph storage_protocol=NFS

Then create a share:

.. code-block:: console

    manila create --share-type cephfsnfstype --name cephnfsshare1 nfs 1

Note the export location of the share:

.. code-block:: console

    manila share-export-location-list cephnfsshare1

The export location of the share contains the IP address of the NFS-Ganesha
server and the path to be mounted. It is of the form,
``{NFS-Ganesha server address}:{path to be mounted}``


Allowing access to shares
~~~~~~~~~~~~~~~~~~~~~~~~~

Allow access to CephFS native share
-----------------------------------

Allow Ceph auth ID ``alice`` access to the share using ``cephx`` access type.

.. code-block:: console

    manila access-allow cephnativeshare1 cephx alice

Note the access status, and the access/secret key of ``alice``.

.. code-block:: console

    manila access-list cephnativeshare1

.. note::

    In Mitaka release, the secret key is not exposed by any manila API. The
    Ceph storage admin needs to pass the secret key to the guest out of band of
    manila. You can refer to the link below to see how the storage admin
    could obtain the secret key of an ID.
    http://docs.ceph.com/docs/jewel/rados/operations/user-management/#get-a-user

    Alternatively, the cloud admin can create Ceph auth IDs for each of the
    tenants. The users can then request manila to authorize the pre-created
    Ceph auth IDs, whose secret keys are already shared with them out of band
    of manila, to access the shares.

    Following is a command that the cloud admin could run from the
    server running the :term:`manila-share` service to create a Ceph auth ID
    and get its keyring file.

    .. code-block:: console

        ceph --name=client.manila --keyring=/etc/ceph/manila.keyring auth \
        get-or-create client.alice -o alice.keyring

    For more details, please see the Ceph documentation.
    http://docs.ceph.com/docs/jewel/rados/operations/user-management/#add-a-user

Allow access to CephFS NFS share
--------------------------------

Allow a guest access to the share using ``ip`` access type.

.. code-block:: console

    manila access-allow cephnfsshare1 ip 172.24.4.225


Mounting CephFS shares
~~~~~~~~~~~~~~~~~~~~~~

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

- The snapshot support of the driver is disabled by default. The
  ``cephfs_enable_snapshots`` configuration option needs to be set to ``True``
  to allow snapshot operations. Snapshot support will also need to be enabled
  on the backend CephFS storage.

- Snapshots are read-only. A user can read a snapshot's contents from the
  ``.snap/{manila-snapshot-id}_{unknown-id}`` folder within the mounted
  share.


Restrictions with CephFS native share backend
---------------------------------------------

- To restrict share sizes, CephFS uses quotas that are enforced in the client
  side. The CephFS FUSE clients are relied on to respect quotas.

Mitaka release only

- The secret-key of a Ceph auth ID required to mount a share is not exposed to
  an user by a manila API. To workaround this, the storage admin would need to
  pass the key out of band of manila, or the user would need to use the Ceph ID
  and key already created and shared with her by the cloud admin.


Security
~~~~~~~~

- Each share's data is mapped to a distinct Ceph RADOS namespace. A guest is
  restricted to access only that particular RADOS namespace.
  http://docs.ceph.com/docs/master/cephfs/file-layouts/

- An additional level of resource isolation can be provided by mapping a
  share's contents to a separate RADOS pool. This layout would be be preferred
  only for cloud deployments with a limited number of shares needing strong
  resource separation. You can do this by setting a share type specification,
  ``cephfs:data_isolated`` for the share type used by the cephfs driver.

  .. code-block:: console

       manila type-key cephfstype set cephfs:data_isolated=True

.. _security_cephfs_native:

Security with CephFS native share backend
-----------------------------------------

As the guests need direct access to Ceph's public network, CephFS native
share backend is suitable only in private clouds where guests can be trusted.


The :mod:`manila.share.drivers.cephfs.driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.cephfs.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
