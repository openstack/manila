====================
Dell EMC VMAX driver
====================

The Dell EMC Shared File Systems service driver framework (EMCShareDriver)
utilizes the Dell EMC storage products to provide the shared file systems
to OpenStack. The Dell EMC driver is a plug-in based driver which is designed
to use different plug-ins to manage different Dell EMC storage products.

The VMAX plug-in manages the VMAX to provide shared file systems. The EMC
driver framework with the VMAX plug-in is referred to as the VMAX driver
in this document.

This driver performs the operations on VMAX eNAS by XMLAPI and the file
command line. Each back end manages one Data Mover of VMAX. Multiple
Shared File Systems service back ends need to be configured to manage
multiple Data Movers.

Requirements
~~~~~~~~~~~~

-  VMAX eNAS OE for File version 8.1 or higher

-  VMAX Unified or File only

-  The following licenses should be activated on VMAX for File:

   -  CIFS

   -  NFS

   -  SnapSure (for snapshot)

   -  ReplicationV2 (for create share from snapshot)

Supported shared file systems and operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The driver supports CIFS and NFS shares.

The following operations are supported:

-  Create a share.

-  Delete a share.

-  Allow share access.

   Note the following limitations:

   -  Only IP access type is supported for NFS.
   -  Only user access type is supported for CIFS.

-  Deny share access.

-  Create a snapshot.

-  Delete a snapshot.

-  Create a share from a snapshot.

While the generic driver creates shared file systems based on cinder
volumes attached to nova VMs, the VMAX driver performs similar operations
using the Data Movers on the array.

Pre-configurations on VMAX
~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Configure a storage pool

   There is a one to one relationship between a storage pool in embedded NAS
   to a storage group on the VMAX. The best way to provision
   storage for file is from the Unisphere for VMAX UI rather than eNAS UI.
   Go to :menuselection:`{array} > SYSTEM > FIle` and under
   :menuselection:`Actions` click :menuselection:`PROVISION STORAGE FOR FILE`

   .. note::

      When creating a new storage group you have the ability to assign a
      service level e.g. Diamond and disable compression/deduplication
      which is enabled by default.

   To pick up the newly created storage pool in the eNAS UI,
   go to :menuselection:`{Control Station} > Storage > Storage Configuration > Storage Pools`
   and under :menuselection:`File Storage` click :menuselection:`Rescan Storage Systems`

   or on the command line:

   .. code-block:: console

      $ nas_diskmark -mark -all -discovery y -monitor y

   The new storage pool should now appear in the eNAS UI

#. Make sure you have the appropriate licenses

   .. code-block:: console

      $ nas_license -l
      key                 status    value
      site_key            online    xx xx xx xx
      nfs                 online
      cifs                online
      snapsure            online
      replicatorV2        online
      filelevelretention  online


#. Enable CIFS service on Data Mover.

   Ensure the CIFS service is enabled on the Data Mover which is going
   to be managed by VMAX driver.

   To start the CIFS service, use the following command:

   .. code-block:: console

      $ server_setup <movername> -Protocol cifs -option start [=<n>]
        # movername = name of the Data Mover
        # n = number of threads for CIFS users

   .. note::

      If there is 1 GB of memory on the Data Mover, the default is 96
      threads. However, if there is over 1 GB of memory, the default
      number of threads is 256.

   To check the CIFS service status, use the following command:

   .. code-block:: console

      $ server_cifs <movername> | head
        # movername = name of the Data Mover

   The command output will show the number of CIFS threads started.

#. NTP settings on Data Mover.

   VMAX driver only supports CIFS share creation with share network
   which has an Active Directory security-service associated.

   Creating CIFS share requires that the time on the Data Mover is in
   sync with the Active Directory domain so that the CIFS server can
   join the domain. Otherwise, the domain join will fail when creating
   a share with this security service. There is a limitation that the
   time of the domains used by security-services, even for different
   tenants and different share networks, should be in sync. Time
   difference should be less than 5 minutes.

   .. note::

      If there is a clock skew then you may see the following error
      "The local machine and the remote machine are not synchronized.
      Kerberos protocol requires a synchronization of both participants
      within the same 5 minutes". To fix this error you must make sure
      the times of the eNas controller host and the Domain Controller
      or within 5 minutes of each other. You must be root to change the
      date of the eNas control station.  Check also that your time zones
      coincide.


   We recommend setting the NTP server to the same public NTP
   server on both the Data Mover and domains used in security services
   to ensure the time is in sync everywhere.

   Check the date and time on Data Mover with the following command:

   .. code-block:: console

      $ server_date <movername>
        # movername = name of the Data Mover

   Set the NTP server for Data Mover with the following command:

   .. code-block:: console

      $ server_date <movername> timesvc start ntp <host> [<host> ...]
        # movername = name of the Data Mover
        # host = IP address of the time server host

   .. note::

      The host must be running the NTP protocol. Only 4 host entries
      are allowed.

#. Configure User Mapping on the Data Mover.

   Before creating CIFS share using VMAX driver, you must select a
   method of mapping Windows SIDs to UIDs and GIDs. DELL EMC recommends
   using usermapper in single protocol (CIFS) environment which is
   enabled on VMAX eNAS by default.

   To check usermapper status, use the following command syntax:

   .. code-block:: console

      $ server_usermapper <movername>
        # movername = name of the Data Mover

   If usermapper does not start, use the following command
   to start the usermapper:

   .. code-block:: console

      $ server_usermapper <movername> -enable
        # movername = name of the Data Mover

   For a multiple protocol environment, refer to Configuring VMAX eNAS User
   Mapping on `EMC support site <http://support.emc.com>`_ for
   additional information.

#. Configure network connection.

   Find the network devices (physical port on NIC) of the Data Mover that
   has access to the share network.

   To check the device list on the eNAS UI go
   to :menuselection:`{Control Station} > Settings > Network > Devices`.

   or on the command line:

   .. code-block:: console

      $ server_sysconfig server_2 -pci
      server_2 : PCI DEVICES:

      On Board:
        VendorID=0x1120 DeviceID=0x1B00  Controller
          0:  scsi-0  IRQ: 32

          0:  scsi-16  IRQ: 33

          0:  scsi-32  IRQ: 34

          0:  scsi-48  IRQ: 35

        Broadcom 10 Gigabit Ethernet Controller
          0:  fxg-3-0  IRQ: 36
          speed=10000 duplex=full txflowctl=disable rxflowctl=disable
          Link: Up

           0:  fxg-3-1  IRQ: 38
          speed=10000 duplex=full txflowctl=disable rxflowctl=disable
          Link: Down


Back-end configurations
~~~~~~~~~~~~~~~~~~~~~~~

The following parameters need to be configured in the
``/etc/manila/manila.conf`` file for the VMAX driver:

.. code-block:: ini

   emc_share_backend = vmax
   emc_nas_server = <IP address>
   emc_nas_password = <password>
   emc_nas_login = <user>
   driver_handles_share_servers = True
   vmax_server_container = <Data Mover name>
   vmax_share_data_pools = <Comma separated pool names>
   share_driver = manila.share.drivers.dell_emc.driver.EMCShareDriver
   vmax_ethernet_ports = <Comma separated ports list>
   emc_ssl_cert_verify = True
   emc_ssl_cert_path = <path to cert>

- `emc_share_backend`
    The plug-in name. Set it to ``vmax`` for the VMAX driver.

- `emc_nas_server`
    The control station IP address of the VMAX system to be managed.

- `emc_nas_password` and `emc_nas_login`
    The fields that are used to provide credentials to the
    VMAX system. Only local users of VMAX File is supported.

- `driver_handles_share_servers`
    VMAX only supports True, where the share driver handles the provisioning
    and management of the share servers.

- `vmax_server_container`
    Name of the Data Mover to serve the share service.

- `vmax_share_data_pools`
    Comma separated list specifying the name of the pools to be used
    by this back end. Do not set this option if all storage pools
    on the system can be used.
    Wild card character is supported.

    Examples: pool_1, pool_*, *

- `vmax_ethernet_ports (optional)`
    Comma-separated list specifying the ports (devices) of Data Mover
    that can be used for share server interface. Do not set this
    option if all ports on the Data Mover can be used.
    Wild card character is supported.

    Examples: fxg-9-0, fxg-_*, *

- `emc_ssl_cert_verify (optional)`
    By default this is True, setting it to False is not recommended

- `emc_ssl_cert_path (optional)`
    The path to the This must be set if emc_ssl_cert_verify is True which is
    the recommended configuration.  See ``SSL Support`` section for more
    details.

Restart of the ``manila-share`` service is needed for the configuration
changes to take effect.

SSL Support
-----------

#. Run the following on eNas Control Station, to display the CA certification
   for the active CS.

   .. code-block:: console

      $ /nas/sbin/nas_ca_certificate -display

   .. warning::

      This cert will be different for the secondary CS so if there is a failover
      a different certificate must be used.

#. Copy the contents and create a file with a .pem extention on your manila host.

   .. code-block:: ini

      -----BEGIN CERTIFICATE-----
      the cert contents are here
      -----END CERTIFICATE-----

#. To verify the cert by running the following and examining the output:

   .. code-block:: console

      $ openssl x509 -in test.pem -text -noout

   .. code-block:: ini

      Certificate:
       Data:
           Version: 3 (0x2)
           Serial Number: xxxxxx
       Signature Algorithm: sha1WithRSAEncryption
           Issuer: O=VNX Certificate Authority, CN=xxx
           Validity
               Not Before: Feb 27 16:02:41 2019 GMT
               Not After : Mar  4 16:02:41 2024 GMT
           Subject: O=VNX Certificate Authority, CN=xxxxxx
           Subject Public Key Info:
               Public Key Algorithm: rsaEncryption
                   Public-Key: (2048 bit)
                   Modulus:
                       xxxxxx
                   Exponent: xxxxxx
           X509v3 extensions:
               X509v3 Subject Key Identifier:
                   xxxxxx
               X509v3 Authority Key Identifier:
                   keyid:xxxxx
                   DirName:/O=VNX Certificate Authority/CN=xxxxxx
                   serial:xxxxx

               X509v3 Basic Constraints:
                   CA:TRUE
               X509v3 Subject Alternative Name:
                   DNS:xxxxxx, DNS:xxxxxx.localdomain, DNS:xxxxxxx, DNS:xxxxx
       Signature Algorithm: sha1WithRSAEncryption
               xxxxxx

#. As it is the capath and not the cafile that is expected, copy the file to either
   new directory or an existing directory (where other .pem files exist).

#. Run the following on the directory

   .. code-block:: console

      $ c_rehash $PATH_TO_CERTS

#. Update manila.conf with the directory where the .pem exists.

   .. code-block:: ini

       emc_ssl_cert_path = /path_to_certs/

#. Restart manila services.


Snapshot Support
~~~~~~~~~~~~~~~~

Snapshot support is disabled by default, so in order to allow shapshots for a
share type, the ``snapshot_support`` extra spec must be set to True.
Creating a share from a snapshot is also disabled by default so
``create_share_from_snapshot_support`` must also be set to True if this
functionality is required.

For a new share type:

.. code-block:: console

   $ manila type-create --snapshot_support True \
                        --create_share_from_snapshot_support True \
                        ${share_type_name} True

For an existing share type:

.. code-block:: console

   $ manila type-key ${share_type_name} \
                     set snapshot_support=True
   $ manila type-key ${share_type_name} \
                     set create_share_from_snapshot_support=True

To create a snapshot from a share where snapshot_support=True:

.. code-block:: console

   $ manila snapshot-create ${source_share_name} --name ${target_snapshot_name}

To create a target share from a shapshot where create_share_from_snapshot_support=True:

.. code-block:: console

   $ manila create cifs 3 --name ${target_share_name} \
                          --share-network ${share_network} \
                          --share-type ${share_type_name} \
                          --metadata source=snapshot \
                          --snapshot-id ${snapshot_id}

Restrictions
~~~~~~~~~~~~

The VMAX driver has the following restrictions:

-  Only ``driver_handles_share_servers`` equals True is supported.

-  Only IP access type is supported for NFS.

-  Only user access type is supported for CIFS.

-  Only FLAT network and VLAN network are supported.

-  VLAN network is supported with limitations. The neutron subnets in
   different VLANs that are used to create share networks cannot have
   overlapped address spaces. Otherwise, VMAX may have a problem to
   communicate with the hosts in the VLANs. To create shares for
   different VLANs with same subnet address, use different Data Movers.

-  The **Active Directory** security service is the only supported
   security service type and it is required to create CIFS shares.

-  Only one security service can be configured for each share network.

-  The domain name of the ``active_directory`` security
   service should be unique even for different tenants.

-  The time on the Data Mover and the Active Directory domains used in
   security services should be in sync (time difference should be less
   than 10 minutes). We recommended using same NTP server on both
   the Data Mover and Active Directory domains.

-  On eNAS, the snapshot is stored in the SavVols. eNAS system allows the
   space used by SavVol to be created and extended until the sum of the
   space consumed by all SavVols on the system exceeds the default 20%
   of the total space available on the system. If the 20% threshold
   value is reached, an alert will be generated on eNAS. Continuing to
   create snapshot will cause the old snapshot to be inactivated (and
   the snapshot data to be abandoned). The limit percentage value can be
   changed manually by storage administrator based on the storage needs.
   We recommend the administrator configures the notification on the
   SavVol usage. Refer to Using eNAS SnapSure document on `EMC support
   site <http://support.emc.com>`_ for more information.

-  eNAS has limitations on the overall numbers of Virtual Data Movers,
   filesystems, shares, and checkpoints. Virtual Data Mover(VDM) is
   created by the eNAS driver on the eNAS to serve as the Shared File
   Systems service share server. Similarly, the filesystem is created,
   mounted, and exported from the VDM over CIFS or NFS protocol to serve
   as the Shared File Systems service share. The eNAS checkpoint serves
   as the Shared File Systems service share snapshot. Refer to the NAS
   Support Matrix document on `EMC support
   site <http://support.emc.com>`_ for the limitations and configure the
   quotas accordingly.


Other Remarks
~~~~~~~~~~~~~

-  eNAS ``nas_quotas`` should not be confused with OpenStack manila quotas.
   The former edits quotas for mounted file systems, and displays a
   listing of quotas and disk usage at the file system level (by the user,
   group, or tree), or at the quota-tree level (by the user or group).
   ``nas_quotas`` also turns quotas on and off, and clears quotas records
   for a file system, quota tree, or a Data Mover. Refer to VMAX eNAS CLI
   Reference guide on `EMC support site <http://support.emc.com>`_ for
   additional information.
   ``OpenStack manila quotas`` delimit the number of shares, snapshots etc.
   a user can create.

   .. code-block:: console

      $ manila quota-show --tenant <project_id> --user <user_id>
      +-----------------------+-------+
      | Property              | Value |
      +-----------------------+-------+
      | share_groups          | 50    |
      | gigabytes             | 1000  |
      | snapshot_gigabytes    | 1000  |
      | share_group_snapshots | 50    |
      | snapshots             | 50    |
      | shares                | 50    |
      | share_networks        | 10    |
      +-----------------------+-------+


Driver options
~~~~~~~~~~~~~~

Configuration options specific to this driver:

.. include:: ../../tables/manila-vmax.inc
