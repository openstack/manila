# Copyright (c) 2015 Cloudbase Solutions SRL
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

import re

from oslo_log import log

from manila.i18n import _LI

LOG = log.getLogger(__name__)


class WindowsUtils(object):
    def __init__(self, remote_execute):
        self._remote_exec = remote_execute
        self._fsutil_total_space_regex = re.compile('of bytes *: ([0-9]*)')
        self._fsutil_free_space_regex = re.compile(
            'of avail free bytes *: ([0-9]*)')

    def initialize_disk(self, server, disk_number):
        cmd = ["Initialize-Disk", "-Number", disk_number]
        self._remote_exec(server, cmd)

    def create_partition(self, server, disk_number):
        cmd = ["New-Partition", "-DiskNumber", disk_number, "-UseMaximumSize"]
        self._remote_exec(server, cmd)

    def format_partition(self, server, disk_number, partition_number):
        cmd = ("Get-Partition -DiskNumber %(disk_number)s "
               "-PartitionNumber %(partition_number)s | "
               "Format-Volume -FileSystem NTFS -Force -Confirm:$false" % {
                   'disk_number': disk_number,
                   'partition_number': partition_number,
               })
        self._remote_exec(server, cmd)

    def add_access_path(self, server, mount_path, disk_number,
                        partition_number):
        cmd = ["Add-PartitionAccessPath", "-DiskNumber", disk_number,
               "-PartitionNumber", partition_number,
               "-AccessPath", self.quote_string(mount_path)]
        self._remote_exec(server, cmd)

    def resize_partition(self, server, size_bytes, disk_number,
                         partition_number):
        cmd = ['Resize-Partition', '-DiskNumber', disk_number,
               '-PartitionNumber', partition_number,
               '-Size', size_bytes]
        self._remote_exec(server, cmd)

    def get_disk_number_by_serial_number(self, server, serial_number):
        pattern = "%s*" % serial_number[:15]
        cmd = ("Get-Disk | "
               "Where-Object {$_.SerialNumber -like '%s'} | "
               "Select-Object -ExpandProperty Number" % pattern)
        (out, err) = self._remote_exec(server, cmd)
        return int(out) if (len(out) > 0) else None

    def get_disk_number_by_mount_path(self, server, mount_path):
        cmd = ('Get-Partition | '
               'Where-Object {$_.AccessPaths -contains "%s"} | '
               'Select-Object -ExpandProperty DiskNumber' %
               (mount_path + "\\"))
        (out, err) = self._remote_exec(server, cmd)
        return int(out) if (len(out) > 0) else None

    def get_volume_path_by_mount_path(self, server, mount_path):
        cmd = ('Get-Partition | '
               'Where-Object {$_.AccessPaths -contains "%s"} | '
               'Get-Volume | '
               'Select-Object -ExpandProperty Path' %
               (mount_path + "\\"))
        (out, err) = self._remote_exec(server, cmd)
        return out.strip()

    def get_disk_space_by_path(self, server, mount_path):
        cmd = ["fsutil", "volume", "diskfree",
               self.quote_string(mount_path)]
        (out, err) = self._remote_exec(server, cmd)

        total_bytes = int(self._fsutil_total_space_regex.findall(out)[0])
        free_bytes = int(self._fsutil_free_space_regex.findall(out)[0])
        return total_bytes, free_bytes

    def get_partition_maximum_size(self, server, disk_number,
                                   partition_number):
        cmd = ('Get-PartitionSupportedSize -DiskNumber %(disk_number)s '
               '-PartitionNumber %(partition_number)s | '
               'Select-Object -ExpandProperty SizeMax' %
               dict(disk_number=disk_number,
                    partition_number=partition_number))
        (out, err) = self._remote_exec(server, cmd)

        max_bytes = int(out)
        return max_bytes

    def set_disk_online_status(self, server, disk_number, online=True):
        is_offline = int(not online)
        cmd = ["Set-Disk", "-Number", disk_number, "-IsOffline", is_offline]
        self._remote_exec(server, cmd)

    def set_disk_readonly_status(self, server, disk_number, readonly=False):
        cmd = ["Set-Disk", "-Number", disk_number,
               "-IsReadOnly", int(readonly)]
        self._remote_exec(server, cmd)

    def update_disk(self, server, disk_number):
        """Updates cached disk information."""
        cmd = ["Update-Disk", disk_number]
        self._remote_exec(server, cmd)

    def join_domain(self, server, domain, admin_username, admin_password):
        # NOTE(lpetrut): An instance reboot is needed but this will be
        # performed using Nova so that the instance state can be
        # retrieved easier.
        LOG.info(_LI("Joining server %(ip)s to Active Directory "
                     "domain %(domain)s"), dict(ip=server['ip'],
                                                domain=domain))
        cmds = [
            ('$password = "%s" | '
             'ConvertTo-SecureString -asPlainText -Force' % admin_password),
            ('$credential = '
             'New-Object System.Management.Automation.PSCredential('
             '"%s", $password)' % admin_username),
            ('Add-Computer -DomainName "%s" -Credential $credential' %
             domain)]

        cmd = ";".join(cmds)
        self._remote_exec(server, cmd)

    def unjoin_domain(self, server, admin_username, admin_password,
                      reboot=False):
        cmds = [
            ('$password = "%s" | '
             'ConvertTo-SecureString -asPlainText -Force' % admin_password),
            ('$credential = '
             'New-Object System.Management.Automation.PSCredential('
             '"%s", $password)' % admin_username),
            ('Remove-Computer -UnjoinDomaincredential $credential '
             '-Passthru -Verbose -Force')]

        cmd = ";".join(cmds)
        self._remote_exec(server, cmd)

    def get_current_domain(self, server):
        cmd = "(Get-WmiObject Win32_ComputerSystem).Domain"
        (out, err) = self._remote_exec(server, cmd)
        return out.strip()

    def ensure_directory_exists(self, server, path):
        cmd = ["New-Item", "-ItemType", "Directory",
               "-Force", "-Path", self.quote_string(path)]
        self._remote_exec(server, cmd)

    def remove(self, server, path, force=True, recurse=False,
               is_junction=False):
        if self.path_exists(server, path):
            if is_junction:
                cmd = ('[System.IO.Directory]::Delete('
                       '%(path)s, %(recurse)d)'
                       % dict(path=self.quote_string(path),
                              recurse=recurse))
            else:
                cmd = ["Remove-Item", "-Confirm:$false",
                       "-Path", self.quote_string(path)]
                if force:
                    cmd += ['-Force']
                if recurse:
                    cmd += ['-Recurse']
            self._remote_exec(server, cmd)
        else:
            LOG.debug("Skipping deleting path %s as it does "
                      "not exist.", path)

    def path_exists(self, server, path):
        cmd = ["Test-Path", path]
        (out, _) = self._remote_exec(server, cmd)
        return out.strip() == "True"

    def normalize_path(self, path):
        return path.replace('/', '\\')

    def get_interface_index_by_ip(self, server, ip):
        cmd = ('Get-NetIPAddress | '
               'Where-Object {$_.IPAddress -eq "%(ip)s"} | '
               'Select-Object -ExpandProperty InterfaceIndex' %
               dict(ip=ip))

        (out, err) = self._remote_exec(server, cmd)
        if_index = int(out)
        return if_index

    def set_dns_client_search_list(self, server, search_list):
        src_list = ",".join(["'%s'" % domain for domain in search_list])

        cmd = ["Set-DnsClientGlobalSetting",
               "-SuffixSearchList", "@(%s)" % src_list]
        self._remote_exec(server, cmd)

    def set_dns_client_server_addresses(self, server, if_index, dns_servers):
        dns_sv_list = ",".join(["'%s'" % dns_sv for dns_sv in dns_servers])
        cmd = ["Set-DnsClientServerAddress",
               "-InterfaceIndex", if_index,
               "-ServerAddresses", "(%s)" % dns_sv_list]
        self._remote_exec(server, cmd)

    def set_win_reg_value(self, server, path, key, value):
        cmd = ['Set-ItemProperty', '-Path', self.quote_string(path),
               '-Name', key, '-Value', value]
        self._remote_exec(server, cmd)

    def get_win_reg_value(self, server, path, name=None):
        cmd = "Get-ItemProperty -Path %s" % self.quote_string(path)
        if name:
            cmd += " | Select-Object -ExpandProperty %s" % name
        return self._remote_exec(server, cmd, retry=False)[0]

    def quote_string(self, string):
        return '"%s"' % string
