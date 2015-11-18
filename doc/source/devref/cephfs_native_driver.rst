
CephFS Native driver
====================

The CephFS Native driver enables manila to export shared filesystems to guests
using the Ceph network protocol.  Guests require a Ceph client in order to
mount the filesystem.

Access is controlled via Ceph's cephx authentication system.  Each share has
a distinct authentication key that must be passed to clients for them to use
it.

To learn more about configuring Ceph clients to access the shares created
using this driver, please see the Ceph documentation(
http://docs.ceph.com/docs/master/cephfs/).  If you choose to use the kernel
client rather than the FUSE client, the share size limits set in Manila
may not be obeyed.

Prerequisities
--------------

- A Ceph cluster with a filesystem configured (
  http://docs.ceph.com/docs/master/cephfs/createfs/)
- Network connectivity between your Ceph cluster's public network and the
  server running the :term:`manila-share` service.
- Network connectivity between your Ceph cluster's public network and guests

.. important:: A manila share backed onto CephFS is only as good as the
               underlying filesystem.  Take care when configuring your Ceph
               cluster, and consult the latest guidance on the use of
               CephFS in the Ceph documentation (
               http://docs.ceph.com/docs/master/cephfs/)

Authorize the driver to communicate with Ceph
---------------------------------------------

Run the following command to create a Ceph identity for manila to use:

.. code-block:: console

    ceph auth get-or-create client.manila mon 'allow r; allow command "auth del" with entity prefix client.manila.; allow command "auth caps" with entity prefix client.manila.; allow command "auth get" with entity prefix client.manila., allow command "auth get-or-create" with entity prefix client.manila.' mds 'allow *' osd 'allow rw' > keyring.manila

keyring.manila, along with your ceph.conf file, will then need to be placed
on the server where the :term:`manila-share` service runs, and the paths to these
configured in your manila.conf.


Enable snapshots in Ceph if you want to use them in manila:

.. code-block:: console

    ceph mds set allow_new_snaps true --yes-i-really-mean-it

Configure CephFS backend in manila.conf
---------------------------------------

Add CephFS to ``enabled_share_protocols`` (enforced at manila api layer).  In
this example we leave NFS and CIFS enabled, although you can remove these
if you will only use CephFS:

.. code-block:: ini

    enabled_share_protocols = NFS,CIFS,CEPHFS

Create a section like this to define a CephFS backend:

.. code-block:: ini

    [cephfs1]
    driver_handles_share_servers = False
    share_backend_name = CEPHFS1
    share_driver = manila.share.drivers.cephfs.cephfs_native.CephFSNativeDriver
    cephfs_conf_path = /etc/ceph/ceph.conf
    cephfs_auth_id = manila

Then edit ``enabled_share_backends`` to point to it, using the same
name that you used for the backend section.  In this example we are
also including another backend ("generic1"), you would include
whatever other backends you have configured.

.. code-block:: ini

    enabled_share_backends = generic1, cephfs1


Creating shares
---------------

The default share type may have driver_handles_share_servers set to True.
Configure a share type suitable for cephfs:

.. code-block:: console

     manila type-create cephfstype false

Then create yourself a share:

.. code-block:: console

    manila create --share-type cephfstype --name cephshare1 cephfs 1


Mounting a client with FUSE
---------------------------

Using the key from your export location, and the share ID, create a keyring
file like:

.. code-block:: ini

    [client.share-4c55ad20-9c55-4a5e-9233-8ac64566b98c]
            key = AQA8+ANW/4ZWNRAAOtWJMFPEihBA1unFImJczA==

Using the mon IP addresses from your export location, create a ceph.conf file
like:

.. code-block:: ini

    [client]
            client quota = true

    [mon.a]
            mon addr = 192.168.1.7:6789

    [mon.b]
            mon addr = 192.168.1.8:6789

    [mon.c]
            mon addr = 192.168.1.9:6789

Finally, mount the filesystem, substituting the filenames of the keyring and
configuration files you just created:

.. code-block:: console

    ceph-fuse --id=share-4c55ad20-9c55-4a5e-9233-8ac64566b98c -c ./client.conf --keyring=./client.keyring --client-mountpoint=/volumes/share-4c55ad20-9c55-4a5e-9233-8ac64566b98c ~/mnt
