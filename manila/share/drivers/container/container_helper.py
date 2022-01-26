# Copyright (c) 2016 Mirantis, Inc.
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
import uuid

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import excutils

from manila import exception
from manila.i18n import _
from manila.share import driver


LOG = log.getLogger(__name__)


class DockerExecHelper(driver.ExecuteMixin):
    def __init__(self, *args, **kwargs):
        self.configuration = kwargs.pop("configuration", None)
        super(DockerExecHelper, self).__init__(*args, **kwargs)
        self.init_execute_mixin()

    def create_container(self, name=None):
        name = name or "".join(["manila_cifs_docker_container",
                                str(uuid.uuid1()).replace("-", "_")])
        image_name = self.configuration.container_image_name
        LOG.debug("Starting container from image %s.", image_name)
        # (aovchinnikov): --privileged is required for both samba and
        # nfs-ganesha to actually allow access to shared folders.
        #
        # (aovchinnikov): To actually make docker container mount a
        # logical volume created after container start-up to some location
        # inside it, we must share entire /dev with it. While seemingly
        # dangerous it is not and moreover this is apparently the only sane
        # way to do it. The reason is when a logical volume gets created
        # several new things appear in /dev: a new /dev/dm-X and a symlink
        # in /dev/volume_group_name pointing to /dev/dm-X. But to be able
        # to interact with /dev/dm-X, it must be already present inside
        # the container's /dev i.e. it must have been -v shared during
        # container start-up. So we should either precreate an unknown
        # number of /dev/dm-Xs (one per LV), share them all and hope
        # for the best or share the entire /dev and hope for the best.
        #
        # The risk of allowing a container having access to entire host's
        # /dev is not as big as it seems: as long as actual share providers
        # are invulnerable this does not pose any extra risks. If, however,
        # share providers contain vulnerabilities then the driver does not
        # provide any more possibilities for an exploitation than other
        # first-party drivers.
        path = "{0}:/shares".format(
            self.configuration.container_volume_mount_path)
        cmd = ["docker", "container", "create", "--name=%s" % name,
               "--privileged", "-v", "/dev:/dev", "-v", path, image_name]
        try:
            result = self._inner_execute(cmd)
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Container %s failed to be created." % name)

        self.disconnect_network("bridge", name)
        LOG.info("A container has been successfully created! Its id is %s.",
                 result[0].rstrip("\n"))

    def start_container(self, name):
        cmd = ["docker", "container", "start", name]

        try:
            self._inner_execute(cmd)
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Container %s has failed to start." % name)

        LOG.info("Container %s successfully started!", name)

    def stop_container(self, name):
        LOG.debug("Stopping container %s.", name)
        try:
            self._inner_execute(["docker", "stop", name])
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Container %s has failed to stop properly." % name)
        LOG.info("Container %s is successfully stopped.", name)

    def execute(self, name=None, cmd=None, ignore_errors=False):
        if name is None:
            raise exception.ManilaException(_("Container name not specified."))
        if cmd is None or (type(cmd) is not list):
            raise exception.ManilaException(_("Missing or malformed command."))
        LOG.debug("Executing inside a container %s.", name)
        cmd = ["docker", "exec", "-i", name] + cmd
        result = self._inner_execute(cmd, ignore_errors=ignore_errors)
        return result

    def _inner_execute(self, cmd, ignore_errors=False):
        LOG.debug("Executing command: %s.", " ".join(cmd))
        try:
            result = self._execute(*cmd, run_as_root=True)
        except (exception.ProcessExecutionError, OSError) as e:
            with excutils.save_and_reraise_exception(
                    reraise=not ignore_errors):
                LOG.warning("Failed to run command %(cmd)s due to "
                            "%(reason)s.", {'cmd': cmd, 'reason': e})
        else:
            LOG.debug("Execution result: %s.", result)
            return result

    def fetch_container_addresses(self, name, address_family="inet6"):
        addresses = []
        interfaces = self.fetch_container_interfaces(name)

        for interface in interfaces:
            result = self.execute(
                name,
                ["ip", "-oneline",
                 "-family", address_family,
                 "address", "show", "scope", "global", "dev", interface],
            )
            address_w_prefix = result[0].split()[3]
            addresses.append(address_w_prefix.split("/")[0])

        return addresses

    def fetch_container_interfaces(self, name):
        interfaces = []
        links = self.execute(name, ["ip", "-o", "link", "show"])
        links = links[0].rstrip().split("\n")
        links = [link for link in links if link.split()[1].startswith("eth")]

        for link in links:
            interface = re.search(" (.+?)@", link).group(1)
            interfaces.append(interface)

        return interfaces

    def rename_container(self, name, new_name):
        veth_names = self.get_container_veths(name)
        if not veth_names:
            raise exception.ManilaException(
                _("Could not find OVS information related to "
                  "container %s.") % name)

        try:
            self._inner_execute(["docker", "rename", name, new_name])
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Could not rename container %s." % name)

        for veth_name in veth_names:
            cmd = ["ovs-vsctl", "set", "interface", veth_name,
                   "external-ids:manila-container=%s" % new_name]
            try:
                self._inner_execute(cmd)
            except (exception.ProcessExecutionError, OSError):
                try:
                    self._inner_execute(["docker", "rename", new_name, name])
                except (exception.ProcessExecutionError, OSError):
                    msg = _("Could not rename back container %s.") % name
                    LOG.exception(msg)
                raise exception.ShareBackendException(
                    msg="Could not update OVS information %s." % name)

        LOG.info("Container %s has been successfully renamed.", name)

    def container_exists(self, name):

        result = self._execute("docker", "ps", "--no-trunc",
                               "--format='{{.Names}}'", run_as_root=True)[0]
        for line in result.split('\n'):
            if name == line.strip("'"):
                return True
        return False

    def create_network(self, network_name):
        cmd = ["docker", "network", "create", network_name]
        LOG.debug("Creating the %s Docker network.", network_name)

        try:
            result = self._inner_execute(cmd)
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Docker network %s could not be created." % network_name)

        LOG.info("The Docker network has been successfully created! Its id is "
                 "%s.", result[0].rstrip("\n"))

    def remove_network(self, network_name):
        cmd = ["docker", "network", "remove", network_name]
        LOG.debug("Removing the %s Docker network.", network_name)

        try:
            result = self._inner_execute(cmd)
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Docker network %s could not be removed. One or more "
                    "containers are probably still using it." % network_name)

        LOG.info("The %s Docker network has been successfully removed!",
                 result[0].rstrip("\n"))

    def connect_network(self, network_name, container_name):
        cmd = ["docker", "network", "connect", network_name, container_name]

        try:
            self._inner_execute(cmd)
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Could not connect the Docker network %s to container %s."
                    % (network_name, container_name))

        LOG.info("Docker network %s has been successfully connected to "
                 "container %s!", network_name, container_name)

    def disconnect_network(self, network_name, container_name):
        cmd = ["docker", "network", "disconnect", network_name, container_name]

        try:
            self._inner_execute(cmd)
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Could not disconnect the Docker network %s from "
                    "container %s." % (network_name, container_name))

        LOG.debug("Docker network %s has been successfully disconnected from "
                  "container %s!", network_name, container_name)

    def get_container_networks(self, container_name):
        cmd = ["docker", "container", "inspect", "-f",
               "'{{json .NetworkSettings.Networks}}'", container_name]

        try:
            result = self._inner_execute(cmd)
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Could not find any networks associated with the %s "
                    "container." % container_name)

        # NOTE(ecsantos): The stdout from _inner_execute comes with extra
        # single quotes.
        networks = list(jsonutils.loads(result[0].strip("\n'")))
        return networks

    def get_container_veths(self, container_name):
        veths = []
        cmd = ["bash", "-c", "cat /sys/class/net/eth*/iflink"]
        eths_iflinks = self.execute(container_name, cmd)

        for eth_iflink in eths_iflinks[0].rstrip().split("\n"):
            veth = self._execute("bash", "-c", "grep -l %s "
                                 "/sys/class/net/veth*/ifindex" % eth_iflink)
            veth = re.search("t/(.+?)/i", veth[0]).group(1)
            veths.append(veth)

        return veths

    def get_network_bridge(self, network_name):
        cmd = ["docker", "network", "inspect", "-f", "{{.Id}}", network_name]

        try:
            network_id = self._inner_execute(cmd)
        except (exception.ProcessExecutionError, OSError):
            raise exception.ShareBackendException(
                msg="Could not find the ID of the %s Docker network."
                    % network_name)

        # The name of the bridge associated with a given Docker network is
        # always "br-" followed by the first 12 digits of that network's ID.
        return "br-" + network_id[0][0:12]

    def get_veth_from_bridge(self, bridge):
        veth = self._execute("ip", "link", "show", "master", bridge)
        veth = re.search(" (.+?)@", veth[0]).group(1)
        return veth
