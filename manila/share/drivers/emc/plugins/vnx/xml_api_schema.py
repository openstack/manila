# Copyright (c) 2014 EMC Corporation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from xml.dom import minidom


class ReqElement(minidom.Element):
    """A base class that has a few bonus helper methods."""

    def __init__(self, name):
        minidom.Element.__init__(self, name)

    def set_name(self, name):
        """Set the NAME attribute of the element."""
        self.setAttribute('NAME', name)

    def set_optional_attribute(self, name, value):
        """Set an attribute if the value parameter is not None."""
        if value is not None:
            self.setAttribute(name, value)

    def append_optional_child(self, child):
        """Append a child element which can be None."""
        if child is not None:
            self.appendChild(child)

    def append_children(self, children):
        """Append a list or tuple of children."""
        [self.appendChild(child) for child in children]


class RequestPacket(ReqElement):
    def __init__(self, request, namespace=None):
        ReqElement.__init__(self, 'RequestPacket')

        if namespace is None:
            namespace = 'http://www.emc.com/schemas/celerra/xml_api'

        self.setAttribute('xmlns', namespace)
        self.appendChild(request)


class Request(ReqElement):
    def __init__(self, sub_element):
        ReqElement.__init__(self, 'Request')
        self.appendChild(sub_element)


class Query(ReqElement):
    def __init__(self, sub_element):
        ReqElement.__init__(self, 'Query')
        self.appendChild(sub_element)


class StoragePoolQueryParams(ReqElement):
    def __init__(self, storage_pool=None, storage_system=None):
        """Create a StoragePoolQueryParams element.

        :param storage_pool: ID of the pool.
        :param storage_system: ID of storage system.
        """
        ReqElement.__init__(self, 'StoragePoolQueryParams')
        self.set_optional_attribute('storagePool', storage_pool)
        self.set_optional_attribute('storageSystem', storage_system)


class MoverQueryParams(ReqElement):
    def __init__(self, aspect_selection, mover=None):
        """Create a MoverQueryParams element.

        :param mover: ID of data mover. If this attribute is not specified,
            retrieve specified aspects for all movers.
        :param aspect_selection: Reference to AspectSelectionMover. Specifies
            the retrieved aspects of mover objects.
        """
        ReqElement.__init__(self, 'MoverQueryParams')
        self.set_optional_attribute('mover', mover)
        self.appendChild(aspect_selection)


class AspectSelectionMover(ReqElement):
    def __init__(self,
                 mover_deduplication_settings='false',
                 mover_dns_domains='false',
                 mover_interfaces="false",
                 mover_network_devices="false",
                 mover_nis_domains="false",
                 mover_routes="false",
                 movers="true",
                 mover_statuses="false"):
        """Create a AspectSelectionMover element.

        :param mover_deduplication_settings:
            If true, retrieve MoverDeduplicationSettings objects.
        :param mover_dns_domains: If true, retrieve MoverDnsDomain objects.
        :param mover_interfaces: If true, retrieve MoverInterface objects.
        :param mover_network_devices:
            If true, retrieve LogicalNetworkDevice objects.
        :param mover_nis_domains: If true, retrieve MoverNisDomain objects.
        :param mover_routes: If true, retrieve MoverRoute objects.
        :param movers: If true, retrieve Mover objects.
        :param mover_statuses: If true, retrieve MoverStatus objects.
        """
        minidom.Element.__init__(self, 'AspectSelection')
        self.set_optional_attribute('moverDeduplicationSettings',
                                    mover_deduplication_settings)
        self.set_optional_attribute('moverDnsDomains', mover_dns_domains)
        self.set_optional_attribute('moverInterfaces', mover_interfaces)
        self.set_optional_attribute('moverNetworkDevices',
                                    mover_network_devices)
        self.set_optional_attribute('moverNisDomains', mover_nis_domains)
        self.set_optional_attribute('moverRoutes', mover_routes)
        self.set_optional_attribute('movers', movers)
        self.set_optional_attribute('moverStatuses', mover_statuses)


class FileSystemQueryParams(ReqElement):
    def __init__(self, aspect_selection, sub_element=None):
        """Create a FileSystemQueryParams element.

        :param aspect_selection: Specifies the retrieved aspects
            of file systems.
        :param sub_element: It would be one of the following elements:
            FileSystemRef
            MoverRef
            VdmRef
            FileSystemAlias
        """
        ReqElement.__init__(self, 'FileSystemQueryParams')
        self.appendChild(aspect_selection)
        self.append_optional_child(sub_element)


class AspectSelectionFileSystem(ReqElement):
    def __init__(self,
                 file_systems='true',
                 file_system_checkpoint_info='false',
                 file_system_capacity_info="false",
                 file_system_capabilities="false",
                 file_system_dhsm_info='false',
                 file_system_rde_info='false'):
        """Create a AspectSelectionFileSystem element.

        :param file_systems: If true, retrieve all instances of FileSystem
        :param file_system_checkpoint_info:
            If true, retrieve FileSystemCheckpointInfo objects (elements)
            for the selected file systems. If the object does not exist,
            there is no error, and the response will not contain the object.
        :param file_system_capacity_info:
            If true, retrieve FileSystemCapacityInfo objects for the
            selected file systems. If the object does not exist, there is
            no error, and the response will not contain the object.
        :param file_system_capabilities:
            If true, retrieve FileSystemCapabilities objects for the selected
            file systems. If the object does not exist, there is no error,
            and the response will not contain the object.
        :param file_system_dhsm_info:
            If true, retrieve FileSystemDhsmInfo objects for the selected
            file systems. otherwise, the FileSystemDhsmInfo objects
            are not retrieved.
        :param file_system_rde_info:
            If specified as true, retrieves FileSystemRdeInfo objects for the
            selected file systems. If not specified, the FileSystemRdeInfo
            objects are not retrieved.
        """
        ReqElement.__init__(self, 'AspectSelection')
        self.set_optional_attribute('fileSystems', file_systems)
        self.set_optional_attribute(
            'fileSystemCheckpointInfos', file_system_checkpoint_info)
        self.set_optional_attribute(
            'fileSystemCapacityInfos', file_system_capacity_info)
        self.set_optional_attribute(
            'fileSystemCapabilities', file_system_capabilities)
        self.set_optional_attribute('fileSystemDhsmInfos',
                                    file_system_dhsm_info)
        self.set_optional_attribute('fileSystemRdeInfos', file_system_rde_info)


class FileSystemRef(ReqElement):
    def __init__(self, file_system):
        """Create a FileSystemRef element.

        :param file_system: ID of the file system.
        """
        ReqElement.__init__(self, 'FileSystem')
        self.setAttribute('fileSystem', file_system)


class MoverRef(ReqElement):
    def __init__(self, mover):
        """Create a MoverRef element.

        :param mover: ID of the mover.
        """
        ReqElement.__init__(self, 'Mover')
        self.setAttribute('mover', mover)


class VdmRef(ReqElement):
    def __init__(self, vdm):
        """Create a VdmRef element.

        :param vdm: ID of the VDM.
        """
        ReqElement.__init__(self, 'Vdm')
        self.setAttribute('vdm', vdm)


class FileSystemAlias(ReqElement):
    def __init__(self, name):
        """Create a FileSystemAlias element.

        :param name: file system name.
        """
        ReqElement.__init__(self, 'Alias')
        self.setAttribute('name', name)


class NfsExportQueryParams(ReqElement):
    def __init__(self, mover=None, path=None):
        """Create a NfsExportQueryParams element.

        :param mover: ID of the mover.
        :param path: the exported mount point path.
        """
        ReqElement.__init__(self, 'NfsExportQueryParams')
        self.set_optional_attribute('mover', mover)
        self.set_optional_attribute('path', path)


class CifsShareQueryParams(ReqElement):
    def __init__(self, cifs_server=None, name=None, mover_or_vdm_ref=None):
        """Create a CifsShareQueryParams element.

        :param cifs_server: Specifies a CIFS server NETBIOS name.
            If not specified, all shares for the specified mover or VDM
            are retrieved.
        :param name: Specifies a share name. If not specified, all shares
            on the specified mover/CIFS server are retrieved.
        :param mover_or_vdm_ref: Reference to MoverOrVdmRef. Specifies a
            mover or a VDM. If this element occurs, filter out shares
            that reside on this mover or VDM.
        """
        ReqElement.__init__(self, 'CifsShareQueryParams')
        self.set_optional_attribute('cifsServer', cifs_server)
        self.set_optional_attribute('name', name)
        self.append_optional_child(mover_or_vdm_ref)


class MoverOrVdmRef(ReqElement):
    def __init__(self, mover, is_vdm=None):
        """Create a MoverOrVdmRef element.

        :param mover: ID of a mover or a VDM.
        :param is_vdm: If true, the attribute 'mover' refers to a VDM,
            otherwise it refers to a mover.
        """
        ReqElement.__init__(self, 'MoverOrVdm')
        self.setAttribute('mover', mover)
        self.set_optional_attribute('moverIdIsVdm', is_vdm)


class CheckpointQueryParams(ReqElement):
    def __init__(self, sub_element):
        """Create a CheckpointQueryParams element.

        :param sub_element: It would be one of the following elements:
            CheckpointRef
            MoverRef
            VdmRef
            FileSystemAlias
        """
        ReqElement.__init__(self, 'CheckpointQueryParams')
        self.appendChild(sub_element)


class CheckpointRef(ReqElement):
    def __init__(self, checkpoint):
        """Create a CheckpointRef element.

        :param checkpoint: ID of the checkpoint.
        """
        ReqElement.__init__(self, 'Checkpoint')
        self.setAttribute('checkpoint', checkpoint)


class MountQueryParams(ReqElement):
    def __init__(self, path=None, mover_or_vdm=None):
        """Create a MountQueryParams element.

        :param path: Mount point path. If not specified, all mounts on the
            specified mover are retrieved.
        :param mover_or_vdm: MoverOrVdmRef Reference to a mover or a VDM to
            which this mount point belongs.
        """
        ReqElement.__init__(self, 'MountQueryParams')
        self.set_optional_attribute('path', path)
        self.append_optional_child(mover_or_vdm)


class VolumeQueryParams(ReqElement):
    def __init__(self,
                 has_available_space=None,
                 storage_system=None,
                 volume=None):
        """Create a VolumeQueryParams element.

        :param has_available_space: If true, retrieve only volumes that have
            available space.
        :param storage_system: storage system ID. Retrieves only volumes that
            are allocated on this storage system.
        :param volume: volume ID. Retrieves only the volume with the
            specified ID.
        """
        ReqElement.__init__(self, 'VolumeQueryParams')
        self.set_optional_attribute('hasAvailableSpace', has_available_space)
        self.set_optional_attribute('storageSystem', storage_system)
        self.set_optional_attribute('volume', volume)


class StartTask(ReqElement):
    def __init__(self, sub_element, timeout="300"):
        ReqElement.__init__(self, 'StartTask')
        self.setAttribute('timeout', timeout)
        self.appendChild(sub_element)


class NewFileSystem(ReqElement):
    def __init__(self, name, mover, destination,
                 type='uxfs',
                 cworm_state='off',
                 mount=None, ):
        """Create a NewFileSystem element.

        :param name: Name of the file system.
        :param mover: Reference to a mover or VDM. It would be one of the
            following elements: MoverRef, VdmRef.
        :param destination: Reference to a volume or storage pool. It would be
            one of the following elements:
                VolumeRef
                StoragePool
        :param mount: Specifies the custom mount point and access policy for
            mounting the file system on it. If not specified, the system
            chooses the mount point and mounts the file system in
            the "read-write" mode.
        :param type: Specifies the type of the file system to be created.
            Currently only "uxfs" type file systems are allowed.
        :param cworm_state: Specifies the "write-once-read-many" state.
        """
        ReqElement.__init__(self, 'NewFileSystem')
        self.setAttribute('name', name)
        self.set_optional_attribute('type', type)
        self.set_optional_attribute('cwormState', cworm_state)
        self.appendChild(mover)
        self.appendChild(destination)
        self.append_optional_child(mount)


class ExtendFileSystem(ReqElement):
    def __init__(self, filesystem, destination):
        """Create a ExtendFileSystem element.

        :param filesystem: ID of the file system.
        :param destination: Reference to a volume or storage pool. It would be
            one of the following elements:
                VolumeRef
                StoragePool
        """
        ReqElement.__init__(self, 'ExtendFileSystem')
        self.setAttribute('fileSystem', filesystem)
        self.appendChild(destination)


class Mount(ReqElement):
    def __init__(self, path, access=None):
        """Create a Mount element.

        :param path: The mount point path.
        :param access: Access policy.
        """
        ReqElement.__init__(self, 'Mount')
        self.setAttribute('path', path)
        self.set_optional_attribute('access', access)


class VolumeRef(ReqElement):
    def __init__(self, volume):
        """Create a VolumeRef element.

        :param volume: ID of the volume.
        """
        ReqElement.__init__(self, 'Volume')
        self.setAttribute('volume', volume)


class StoragePool(ReqElement):
    def __init__(self, pool,
                 enabler_auto_ext=None,
                 size=None,
                 virtual_provisioning=None,
                 may_contain_slices=None,
                 storage=None):
        """Create a StoragePool element.

        :param pool: ID of the pool.
        :param size:
        :param virtual_provisioning: Specify Thin/Thick pool.
        :param may_contain_slices:
        :param storage: Storage system ID.
        :param enabler_auto_ext:
            Reference to EnablerAutoExt to enable pool auto extension.
        """
        ReqElement.__init__(self, 'StoragePool')
        self.setAttribute('pool', pool)
        self.set_optional_attribute('size', size)
        self.set_optional_attribute('virtualProvisioning',
                                    virtual_provisioning)
        self.set_optional_attribute('mayContainSlices', may_contain_slices)
        self.set_optional_attribute('storage', storage)
        self.append_optional_child(enabler_auto_ext)


class EnablerAutoExt(ReqElement):
    def __init__(self, auto_extension_max_size, high_water_mark):
        """Create a EnablerAutoExt element.

        :param auto_extension_max_size:
        :param high_water_mark:
        """
        ReqElement.__init__(self, 'EnablerAutoExt')
        self.set_optional_attribute('autoExtensionMaxSize',
                                    auto_extension_max_size)
        self.set_optional_attribute('highWaterMark', high_water_mark)


class NewMount(ReqElement):
    def __init__(self, file_system, path,
                 nt_credential=None,
                 sub_element=None):
        """Create a NewMount element.

        :param file_system: ID of the file system being mounted.
        :param path: mount point path.
        :param nt_credential: if true, that the system matches a UID/GID
            to a SID during an access request to create one common credential
            called the NT credential.
        :param sub_element: Reference to MoverOrVdmRef.
        """
        ReqElement.__init__(self, 'NewMount')
        self.setAttribute('fileSystem', file_system)
        self.setAttribute('path', path)
        self.set_optional_attribute('ntCredential', nt_credential)
        self.appendChild(sub_element)


class DeleteMount(ReqElement):
    def __init__(self, mover, path=None, is_vdm="false"):
        """Create a DeleteMount element.

        :param mover: ID of a mover or a VDM.
        :param path: Mount point path.
        :param is_vdm: If true, the attribute 'mover' refers to a VDM,
            otherwise it refers to a mover.
        """
        ReqElement.__init__(self, 'DeleteMount')
        self.setAttribute('mover', mover)
        self.setAttribute('path', path)
        self.set_optional_attribute('moverIdIsVdm', is_vdm)


class DeleteFileSystem(ReqElement):
    def __init__(self, filesystem):
        """Create a DeleteFileSystem element.

        :param filesystem: ID of the file system.
        """
        ReqElement.__init__(self, 'DeleteFileSystem')
        self.setAttribute('fileSystem', filesystem)


class NewCifsShare(ReqElement):
    def __init__(self, name, path,
                 mover_or_vdm, cifs_servers,
                 max_users=None, comment=None):
        """Create a NewCifsShare element.

        :param name: Share name. There is a 12 character limit on share name.
            If the international character set support has been enabled,
            the limit is 255 characters.
        :param path: The path to the exported directory
        :param max_users: Maximum number of simultaneous users permitted for
            a share. If not specified, the number of users is unlimited.
        :param comment: User comment.
        :param mover_or_vdm: Reference to MoverOrVDM.
        :param cifs_servers: Reference to CifsServers.
        """
        ReqElement.__init__(self, 'NewCifsShare')
        self.setAttribute('name', name)
        self.setAttribute('path', path)
        self.set_optional_attribute('maxUsers', max_users)
        self.set_optional_attribute('comment', comment)
        self.appendChild(mover_or_vdm)
        self.appendChild(cifs_servers)


class CifsServers(ReqElement):
    def __init__(self, lis=None):
        """Create a CifsServers element.

        :param lis: A list of NetBiosName.
        """
        ReqElement.__init__(self, 'CifsServers')
        if not isinstance(lis, list):
            lis = [lis]
        for li in lis:
            self.appendChild(li)


class Li(ReqElement):
    def __init__(self, sub_element=None):
        """Create a List element<li>.

        :param sub_element: child element.
        """
        ReqElement.__init__(self, 'li')
        self.appendChild(sub_element)


class NetBiosName(minidom.Text):
    def __init__(self, net_bios_name=None):
        self.data = net_bios_name


class NameList(minidom.Text):
    def __init__(self, name_list=None):
        self.data = name_list


class DeleteCifsShare(ReqElement):
    def __init__(self, name, mover,
                 cifs_servers, is_vdm='false'):
        """Create a DeleteCifsShare element.

        :param name: The name of the share.
        :param mover: ID of a mover or a VDM.
        :param cifs_servers: Reference to CifsServers. Specifies the list
            of CIFS server NETBIOS names.
        :param is_vdm: If true, the attribute 'mover' refers to a VDM,
            otherwise it refers to a mover.
        """
        ReqElement.__init__(self, 'DeleteCifsShare')
        self.setAttribute('mover', mover)
        self.setAttribute('name', name)
        self.set_optional_attribute('moverIdIsVdm', is_vdm)
        self.appendChild(cifs_servers)


class CifsServerQueryParams(ReqElement):
    def __init__(self, name=None, mover_or_vdm=None):
        """Create a CifsServerQueryParams element.

        :param name: Specifies a CIFS server NETBIOS name. If not specified,
            all server objects for the specified mover or VDM are retrieved.
        :param mover_or_vdm: Reference to MoverOrVdmRef. Specifies a mover
            or a VDM.
        """
        ReqElement.__init__(self, 'CifsServerQueryParams')
        self.set_optional_attribute('name', name)
        self.append_optional_child(mover_or_vdm)


class NewCheckpoint(ReqElement):
    def __init__(self, checkpoint_of,
                 sub_element,
                 name=None):
        """Create a NewCheckpoint element.

        :param checkpoint_of: ID of the production (source) file system.
        :param name: The name of the checkpoint. If this attribute is missing,
            the system chooses the checkpoint name. If the BaselineCheckpoint
            element is present in the request then this attribute refers to
            the writeable checkpoint name.
        :param sub_element: It would be one of the following elements:
            SpaceAllocationMethod BaselineCheckpoint.
        """
        ReqElement.__init__(self, 'NewCheckpoint')
        self.setAttribute('checkpointOf', checkpoint_of)
        self.set_optional_attribute('name', name)
        self.appendChild(sub_element)


class SpaceAllocationMethod(ReqElement):
    def __init__(self, sub_element):
        """Create a SpaceAllocationMethod element.

        :param sub_element: It would be one of the following elements:
            StoragePool
            StorageSystem
            VolumeRef
        """
        ReqElement.__init__(self, 'SpaceAllocationMethod')
        self.appendChild(sub_element)


class StorageSystem(ReqElement):
    def __init__(self, storage, size=None):
        """Create a StorageSystem element.

        :param storage (Required): ID of storage system.
        :param size: Specifies the size of the 'savVol'. The default
            value for size depends on the size of the source production
            file system being checkpointed. If the file system is less
            than 20000 MB, the size of the 'savVol' is equal to the size of
            the file system. Otherwise, the default size is 20000MB.
            The minimum size allowed is 64 MB.
        """
        ReqElement.__init__(self, 'StorageSystem')
        self.setAttribute('storage', storage)
        self.set_optional_attribute('size', size)


class BaselineCheckpoint(ReqElement):
    def __init__(self, baseline_checkpoint=None, baseline_name=None):
        """Create a BaselineCheckpoint element.

        :param baseline_checkpoint: ID of baseline checkpoint.
        :param baseline_name: the baseline name of the checkpoint. If this
            parameter is specified in the absence of the baseline checkpoint
            id it is assumed that the user is trying to create both the
            baseline and the writeable checkpoint in a single request.
            Both the baseline name and the writeable checkpoint name in this
            case should be unique. When baseline checkpoint id is specified
            in the request the baseline name, if present, is ignored.
        """
        ReqElement.__init__(self, 'BaselineCheckpoint')
        self.set_optional_attribute('baselineCheckpoint', baseline_checkpoint)
        self.set_optional_attribute('baselineName', baseline_name)


class DeleteCheckpoint(ReqElement):
    def __init__(self, checkpoint, force='false'):
        """Create a DeleteCheckpoint element.

        :param checkpoint: ID of checkpoint.
        :param force: Specifies that cascading delete is to be performed
            if the checkpoint has a writeable checkpoint associated with it.
        """
        ReqElement.__init__(self, 'DeleteCheckpoint')
        self.setAttribute('checkpoint', checkpoint)
        self.set_optional_attribute('force', force)


class ModifyFileSystem(ReqElement):
    def __init__(self, file_system,
                 access_time=None,
                 backup_data_high_watermark=None,
                 case_sensitive=None,
                 cifs_compression_enabled=None,
                 duplicate_detection_method=None,
                 file_extension_exclude_list=None,
                 maximum_size=None,
                 minimum_scan_interval=None,
                 minimum_size=None,
                 modification_time=None,
                 new_name=None,
                 path_name_exclude_list=None,
                 rde_state=None,
                 sav_vol_high_watermark=None,
                 virtual_provisioning=None,
                 auto_extend=None):
        """Create a ModifyFileSystem element.

        :param file_system: ID of the file system
        :param access_time:
            the minimum required file age (in days) based on read access
            time. The default value is 15 days, setting this value to 0
            disables this test. Files that have been read within these
            number of days will not be deduplicated. This parameter will
            not apply to files with an FLR state other than CLEAN or when
            set to 0. Changing this value will take effect on the next scan
            operation but will not affect files that were deduplicated in
            previous scans.
        :param backup_data_high_watermark:
            Specifies the percentage full value that a deduplicate file
            has to be below of, in order to trigger the space reduced
            backups for NDMP. The default is 90 meaning that any
            deduplicated file that has 90 or more of its blocks will
            simply backup the file data instead of attempting to back it
            up in a spaced reduced format. Setting this parameter to 0 will
            effectively disable space reduced backups. The range of this
            setting is between 0 and 200 inclusive.
        :param case_sensitive:
            Specifies whether case-sensitive or case-insensitive string
            comparisons will be used during scans in the NFS namespace.
            By default case insensitive comparisons will be done to be
            consistent with Windows syntax. If set to 1 then file extension
            exclude list and directory path exclude list will be treated as
            a case sensitive comparison in the file system using the NFS
            name space. If 0 then it will treat it as case insensitive
            in the CIFS name space.
        :param cifs_compression_enabled:
            Specifies whether or not CIFS compression and display are
            allowed, by default it is enabled. In order to enable CIFS
            compression and display, this setting has to be set 'true'
            and the deduplication state of the file system must either be
            enabled or suspended. If the deduplication state is either off
            or in the process of being turned off then CIFS compression is
            not allowed. The latter restriction is to prevent deduplication
            when the administrator intends to turn it off. If this
            parameter is off but the deduplication state is enabled then
            you will achieve the same behavior as the first release of
            deduplication.
        :param duplicate_detection_method:
            Specifies the method used to detect duplicate data for Celerra.
            sha1 - This hash is used to detect the duplicate data. It is
            faster than a byte comparison and statistically unlikely to
            produce false duplicates. This is the default method.
            byte - This will use a byte-by-byte comparison to detect
            the duplicate data. This adds considerable overhead especially
            for large files.
            off - This means that the duplicate data detection is off.
            With this setting every deduplicated file is considered unique
            and the only space savings made are accomplished with the
            compression.
        :param file_extension_exclude_list:
            Specifies a colon delimited list of filename extensions to be
            excluded from deduplication. Each extension must include the
            leading dot. For example, using either *.doc:*.pdf or .doc:.pdf
            will skip any file with a pdf or doc extension. This comparison
            is case insensitive by default but may be overridden by the
            parameter dedupe.caseSensitive, and it is UTF-8 encoded. This
            does not support pattern matching. The value between the dot
            and the next colon must be an exact match and only the
            extension is checked. Changing this value will take effect on
            the next scan operation but will not affect files that were
            deduplicated in previous scans.
        :param maximum_size:
            Specifies the deduplication maximum size. Files larger than
            this size in MB will not be deduplicated. The default value is
            8TB, setting this value to 0 disables this test.
            Set this value to the size (in MB) of the largest file to be
            processed for deduplication. Setting this value too high may
            affect system write performance as the first write operation
            reduplicates the file in its entirety. For example, a value of
            200 indicates that the file should be less than or equal to
            200 MB. Changing this value will take effect on the next scan
            operation but will not affect files there were deduplicated in
            previous scans.
        :param minimum_scan_interval:
            Specifies the minimum number of days between scans for a
            filesystem. The default value is 7. This is the number of days
            after completing one scan before the Celerra will scan the same
            file system again. The actual number of days before the next
            scan may be longer if the Celerra is busy scanning other
            file systems. Use a lower value to scan a file system more
            frequently, or a larger value to scan a file system less
            frequently. Changing this value will take effect after the
            next scan operation.
        :param minimum_size:
            Specifies the minimum deduplication size. Files less than or
            equal to this size in KB will not be deduplicated. The default
            value is 24KB,setting this parameter to 0 disables this test.
            This value should not be set lower than 24 KB. Changing this
            value will take effect on the next scan operation but will not
            affect files there were deduplicated in the previous scans.
        :param modification_time:
            Specifies the minimum required file age (in days) based on
            modification time. The default value is 15, setting this
            parameter to 0 disables this test. Files updated within the
            specified number of days will not be deduplicated. Changing
            this value will take effect on the next scan operation but
            will not affect files that were deduplicated in
            previous scans.
        :param new_name:
            Specifies the new file system name.
        :param path_name_exclude_list:
            Any directory located below a path name that includes this
            setting will be excluded from deduplication. This is a colon
            separated list of path names. There is a limit of 10 path names
            and each one can be up to 1024 bytes. This is in UTF-8 format.
            A backslash can be used to allow the colon to be part of a path
            name rather than be a delimiter. This only makes sense for NFS
            style lookups when case sensitive is set to 1. This does not
            support regular expressions.
        :param rde_state:
            Specifies the F-RDE state for De-duplication.
        :param sav_vol_high_watermark:
            Specifies the percentage of SavVol space that can be used
            during the deduplication. Once this amount of SavVol is used,
            then deduplication will stop on this file system. The default
            value is 90. If it is 0 then any limit based on the SavVol is
            not enforced. If it is not 0 then it is a percent of the
            configured SavVol auto extension threshold. By default,
            this parameter is 90 and the SavVol auto-extension is also 90;
            this parameter will apply when the SavVol is 81 full
            (90 * 90%). Setting this parameter will take effect immediately.
        :param virtual_provisioning:
            Specifies whether virtual provisioning should be enabled or
            disabled for the file system. If this attribute is not set,
            the virtual provision setting will not be modified.
        :param auto_extend:
            Refer to AutoExtend.
        """
        ReqElement.__init__(self, 'ModifyFileSystem')
        self.setAttribute('fileSystem', file_system)
        self.set_optional_attribute('accessTime',
                                    access_time)
        self.set_optional_attribute('backupDataHighWatermark',
                                    backup_data_high_watermark)
        self.set_optional_attribute('caseSensitive', case_sensitive)
        self.set_optional_attribute('cifsCompressionEnabled',
                                    cifs_compression_enabled)
        self.set_optional_attribute('duplicateDetectionMethod',
                                    duplicate_detection_method)
        self.set_optional_attribute('fileExtensionExcludeList',
                                    file_extension_exclude_list)
        self.set_optional_attribute('maximumSize', maximum_size)
        self.set_optional_attribute('minimumScanInterval',
                                    minimum_scan_interval)
        self.set_optional_attribute('minimumSize', minimum_size)
        self.set_optional_attribute('modificationTime', modification_time)
        self.set_optional_attribute('newName', new_name)
        self.set_optional_attribute('pathNameExcludeList',
                                    path_name_exclude_list)
        self.set_optional_attribute('rdeState', rde_state)
        self.set_optional_attribute('savVolHighWatermark',
                                    sav_vol_high_watermark)
        self.set_optional_attribute('virtualProvisioning',
                                    virtual_provisioning)
        self.append_optional_child(auto_extend)


class AutoExtend(ReqElement):
    def __init__(self,
                 auto_extension_max_size=None,
                 enable_auto_extension=None,
                 high_water_mark=None):
        """Create a AutoExtend element.

        :param auto_extension_max_size:
            Specifies the maximum size of the file system to which it can
            be extended. If this attribute is not set, the maximum size is
            not modified. Maximum size cannot be modified if auto
            extension is not on.
        :param enable_auto_extension:
            Specifies whether auto extension should be enabled/disabled on
            the file system. When set to true, auto extension on the file
            system will be enabled and high water mark will default to 90%.
            If set to false, auto extension will be disabled on the file
            system.
        :param high_water_mark:
            Specifies the setting of percentage threshold for the space
            used that triggers the extension. If this attribute is not set,
            the high watermark is not modified. If this property is not set
            when turning auto extension on high water mark will default to
            90%.
        """
        ReqElement.__init__(self, 'AutoExtend')
        self.set_optional_attribute('autoExtensionMaxSize',
                                    auto_extension_max_size)
        self.set_optional_attribute('enableAutoExtension',
                                    enable_auto_extension)
        self.set_optional_attribute('highWaterMark', high_water_mark)


class NewVdm(ReqElement):
    def __init__(self,
                 name,
                 mover,
                 storage_pool=None):
        """Create a NewVdm element.

        :param name: Name of the VDM.
        :param mover: The mover that hosts this VDM.
        :param storage_pool: The storage pool on which the root filesystem
            for the vdm should be created.
        """
        ReqElement.__init__(self, 'NewVdm')
        self.setAttribute('mover', mover)
        self.setAttribute('name', name)
        self.set_optional_attribute('storagePool', storage_pool)


class DeleteVdm(ReqElement):
    def __init__(self, vdm):
        """Create a DeleteVdm element.

        :param vdm: ID of the VDM.
        """
        ReqElement.__init__(self, 'DeleteVdm')
        self.setAttribute('vdm', vdm)


class VdmQueryParams(ReqElement):
    def __init__(self, vdm=None):
        """Create a VdmQueryParams element.

        :param vdm: ID of the VDM. If this attribute is not specified,
            retrieve specified aspects for all VDMs.
        """
        ReqElement.__init__(self, 'VdmQueryParams')
        self.set_optional_attribute('vdm', vdm)


class NewW2KCifsServer(ReqElement):
    def __init__(self, comp_name, domain, name,
                 mover_or_vdm,
                 aliases,
                 interfaces=None,
                 local_admin_password=None,
                 join_domain=None):
        """Create a NewW2KCifsServer element.

        :param comp_name: The computer name
        :param domain: A fully qualified domain name.
        :param name: NETBIOS name of the CIFS server
        :param interfaces:
            Specifies the list of interface addresses on which this server
            is available. For movers, the default CIFS server is created
            when no interfaces are specified for the server.
            For VDMs, at least one interface needs to be specified.
        :param local_admin_password:
            Specifies the password for the local administrator.
            Local user support allows the creation of a limited number of
            local user accounts on the CIFS server.
            This attribute is optional if local user support is not needed.
        :param mover_or_vdm:
            Reference to MoverOrVdmRef. Specifies a mover or a VDM.
        :param aliases:
            Refer to Aliases. Specifies a list of NETBIOS aliases
            associated with this server.
        :param join_domain:
            Refer to JoinDomain. Specifies the domain authentication info.
            If this element occurs, there is an attempt to join the domain.
        """
        ReqElement.__init__(self, 'NewW2KCifsServer')
        self.setAttribute('compName', comp_name)
        self.setAttribute('domain', domain)
        self.setAttribute('name', name)
        self.set_optional_attribute('interfaces', interfaces)
        self.set_optional_attribute('localAdminPassword', local_admin_password)
        self.appendChild(mover_or_vdm)
        self.appendChild(aliases)
        self.append_optional_child(join_domain)


class Aliases(ReqElement):
    def __init__(self, *args, **kwargs):
        """Create a Aliases element.

        :param args: Specifies a list of NETBIOS aliases associated with this
            server.
        :param kwargs:
        """
        ReqElement.__init__(self, 'Aliases')
        self.append_children(*args)


class JoinDomain(ReqElement):
    def __init__(self, user_name, password):
        """Create a JoinDomain element.

        :param user_name: User name under which the domain is joined.
        :param password: Password associated with the user name.
        """
        ReqElement.__init__(self, 'JoinDomain')
        self.setAttribute('userName', user_name)
        self.setAttribute('password', password)


class DeleteCifsServer(ReqElement):
    def __init__(self, name, mover, is_vdm='false'):
        """Create a DeleteCifsServer element.

        :param name: The name of the share.
        :param mover: ID of a mover or a VDM.
        :param is_vdm: If true, the attribute 'mover' refers to a VDM,
            otherwise it refers to a mover
        """
        ReqElement.__init__(self, 'DeleteCifsServer')
        self.setAttribute('mover', mover)
        self.setAttribute('name', name)
        self.set_optional_attribute('moverIdIsVdm', is_vdm)


class ModifyW2KCifsServer(ReqElement):
    def __init__(self, name, mover, is_vdm='false',
                 sub_element=None):
        """Create a ModifyW2KCifsServer element.

        :param name: The name of the share.
        :param mover: ID of a mover or a VDM.
        :param is_vdm: If true, the attribute 'mover' refers to a VDM,
            otherwise it refers to a mover.
        :param sub_element: Reference to LocalAdmin or DomainSetting.
        """
        ReqElement.__init__(self, 'ModifyW2KCifsServer')
        self.setAttribute('mover', mover)
        self.setAttribute('name', name)
        self.set_optional_attribute('moverIdIsVdm', is_vdm)
        self.append_optional_child(sub_element)


class LocalAdmin(ReqElement):
    def __init__(self, enabled, password):
        """Create a LocalAdmin element.

        :param password: The local admin password.
        :param enabled: Switches local admin on or off. Switching off local
            admin on a standalone server is rejected.
        """
        ReqElement.__init__(self, 'LocalAdmin')
        self.setAttribute('enabled', enabled)
        self.setAttribute('password', password)


class DomainSetting(ReqElement):
    def __init__(self, join_domain, user_name, password):
        """Create a DomainSetting element.

        :param user_name:
        :param password:
        :param join_domain: True for joining the domain, false for unjoining.
        """
        ReqElement.__init__(self, 'DomainSetting')
        self.setAttribute('userName', user_name)
        self.setAttribute('password', password)
        self.setAttribute('joinDomain', join_domain)


class NewMoverInterface(ReqElement):
    def __init__(self, device, ip_address, mover, net_mask,
                 vlan_id='-1', name=None, mtu='1500', ip_version='IPv4'):
        """Create a NewMoverInterface element.

        :param device: Device name on the mover with which this interface is
            associated.
        :param ip_address: IP address of the interface.
        :param mover: mover ID.
        :param net_mask: IPv4 subnet mask or IPv6 subnet prefix length.
        :param vlan_id: VLAN ID for this interface; this attribute appears on
            gigabit devices only. When the value is -1, it means that
            VLAN is not set.
        :param name: The interface name. If not specified, the system derives
            the interface name from the IP address.
        :param mtu: MAC transfer unit size.
        :param ip_version: Specifies whether the IP address is IPv4 or IPv6
            on this Control Station. Default is IPv4.
        """
        ReqElement.__init__(self, 'NewMoverInterface')
        self.setAttribute('device', device)
        self.setAttribute('ipAddress', ip_address)
        self.setAttribute('mover', mover)
        self.setAttribute('netMask', net_mask)
        self.set_optional_attribute('vlanid', vlan_id)
        self.set_optional_attribute('name', name)
        self.set_optional_attribute('mtu', mtu)
        self.set_optional_attribute('ipVersion', ip_version)


class DeleteMoverInterface(ReqElement):
    def __init__(self, ip_address, mover):
        """Create a DeleteMoverInterface element.

        :param ip_address: IP address of the interface.
        :param mover: mover ID.
        """
        ReqElement.__init__(self, 'DeleteMoverInterface')
        self.setAttribute('ipAddress', ip_address)
        self.setAttribute('mover', mover)


class NewMoverDnsDomain(ReqElement):
    def __init__(self, mover, name, servers, protocol='udp'):
        """Create a NewMoverDnsDomain element.

        :param mover: mover ID.
        :param name: The domain name.
        :param servers: The list of IP addresses of DNS servers.
            The number of servers can not be more than 3.
        :param protocol: The network protocol used.
        """
        ReqElement.__init__(self, 'NewMoverDnsDomain')
        self.setAttribute('mover', mover)
        self.setAttribute('name', name)
        self.setAttribute('servers', servers)
        self.set_optional_attribute('protocol', protocol)


class DeleteMoverDnsDomain(ReqElement):
    def __init__(self, mover, name):
        """Create a DeleteMoverDnsDomain element.

        :param mover: mover ID.
        :param name: The domain name.
        """
        ReqElement.__init__(self, 'DeleteMoverDnsDomain')
        self.setAttribute('mover', mover)
        self.setAttribute('name', name)


def build_query_package(body):
    return RequestPacket(
        Request(
            Query(body)
        )
    )


def build_task_package(body):
    return RequestPacket(
        Request(
            StartTask(body)
        )
    )
