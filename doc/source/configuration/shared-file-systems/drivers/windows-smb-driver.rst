.. _windows_smb_driver:

Windows SMB driver
==================

While the generic driver only supports Linux instances, you may use the
Windows SMB driver when Windows VMs are preferred.

This driver extends the generic one in order to provide Windows instance
support. It can integrate with Active Directory domains through the Manila
security service feature, which can ease access control.

Although Samba is a great SMB share server, Windows instances may provide
improved SMB 3 support.

Limitations
-----------
- ip access rules are not supported at the moment, only user based ACLs
  may be used
- SMB (also known as CIFS) is the only supported share protocol
- although it can handle Windows VMs, Manila cannot run on Windows at the
  moment. The VMs on the other hand may very well run on Hyper-V, KVM or any
  other hypervisor supported by Nova.

Prerequisites
-------------

This driver requires a Windows Server image having cloudbase-init installed.
Cloudbase-init is the de-facto standard tool for initializing Windows VMs
running on OpenStack. The driver relies on it to do tasks such as:

- configuring WinRM access using password or certificate based
  authentication
- network configuration
- setting the host name

.. note::

    This driver was initially developed with Windows Nano Server in mind.
    Unfortunately, Microsoft no longer supports running Nano Servers on bare
    metal or virtual machines, for which reason you may want to use Windows
    Server Core images.

Configuring
-----------

Below is a config sample that enables the Windows SMB driver.

.. code-block:: ini

    [DEFAULT]
    manila_service_keypair_name = manila-service
    enabled_share_backends = windows_smb
    enabled_share_protocols = CIFS

    [windows_smb]
    service_net_name_or_ip = private
    tenant_net_name_or_ip = private

    share_mount_path = C:/shares
    # The driver can either create share servers by itself
    # or use existing ones.
    driver_handles_share_servers = True
    service_instance_user = Admin
    service_image_name = ws2016

    # nova get-password may be used to retrieve passwords generated
    # by cloudbase-init and encrypted with the public key.
    path_to_private_key = /etc/manila/ssh/id_rsa
    path_to_public_key = /etc/manila/ssh/id_rsa.pub
    winrm_cert_pem_path = /etc/manila/ssl/winrm_client_cert.pem
    winrm_cert_key_pem_path = /etc/manila/ssl/winrm_client_cert.key
    # If really needed, you can use password based authentication as well.
    winrm_use_cert_based_auth = True
    winrm_conn_timeout = 40
    max_time_to_build_instance = 900

    share_backend_name = windows_smb
    share_driver = manila.share.drivers.windows.windows_smb_driver.WindowsSMBDriver
    service_instance_flavor_id = 100
