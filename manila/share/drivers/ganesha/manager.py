# Copyright (c) 2014 Red Hat, Inc.
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

import os
import pipes
import re
import sys

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import importutils
import six

from manila import exception
from manila.i18n import _
from manila.share.drivers.ganesha import utils as ganesha_utils
from manila import utils

LOG = log.getLogger(__name__)
IWIDTH = 4


def _conf2json(conf):
    """Convert Ganesha config to JSON."""

    # tokenize config string
    token_list = [six.StringIO()]
    state = {
        'in_quote': False,
        'in_comment': False,
        'escape': False,
    }

    cbk = []
    for char in conf:
        if state['in_quote']:
            if not state['escape']:
                if char == '"':
                    state['in_quote'] = False
                    cbk.append(lambda: token_list.append(six.StringIO()))
                elif char == '\\':
                    cbk.append(lambda: state.update({'escape': True}))
        else:
            if char == "#":
                state['in_comment'] = True
            if state['in_comment']:
                if char == "\n":
                    state['in_comment'] = False
            else:
                if char == '"':
                    token_list.append(six.StringIO())
                    state['in_quote'] = True
        state['escape'] = False
        if not state['in_comment']:
            token_list[-1].write(char)
        while cbk:
            cbk.pop(0)()

    if state['in_quote']:
        raise RuntimeError("Unterminated quoted string")

    # jsonify tokens
    js_token_list = ["{"]
    for tok in token_list:
        tok = tok.getvalue()

        if tok[0] == '"':
            js_token_list.append(tok)
            continue

        for pat, s in [
                # add omitted "=" signs to block openings
                ('([^=\s])\s*{', '\\1={'),
                # delete trailing semicolons in blocks
                (';\s*}', '}'),
                # add omitted semicolons after blocks
                ('}\s*([^}\s])', '};\\1'),
                # separate syntactically significant characters
                ('([;{}=])', ' \\1 ')]:
            tok = re.sub(pat, s, tok)

        # map tokens to JSON equivalents
        for word in tok.split():
            if word == "=":
                word = ":"
            elif word == ";":
                word = ','
            elif (word in ['{', '}'] or
                  re.search('\A-?[1-9]\d*(\.\d+)?\Z', word)):
                pass
            else:
                word = jsonutils.dumps(word)
            js_token_list.append(word)
    js_token_list.append("}")

    # group quoted strings
    token_grp_list = []
    for tok in js_token_list:
        if tok[0] == '"':
            if not (token_grp_list and isinstance(token_grp_list[-1], list)):
                token_grp_list.append([])
            token_grp_list[-1].append(tok)
        else:
            token_grp_list.append(tok)

    # process quoted string groups by joining them
    js_token_list2 = []
    for x in token_grp_list:
        if isinstance(x, list):
            x = ''.join(['"'] + [tok[1:-1] for tok in x] + ['"'])
        js_token_list2.append(x)

    return ''.join(js_token_list2)


def _dump_to_conf(confdict, out=sys.stdout, indent=0):
    """Output confdict in Ganesha config format."""
    if isinstance(confdict, dict):
        for k, v in confdict.items():
            if v is None:
                continue
            if isinstance(v, dict):
                out.write(' ' * (indent * IWIDTH) + k + ' ')
                out.write("{\n")
                _dump_to_conf(v, out, indent + 1)
                out.write(' ' * (indent * IWIDTH) + '}')
            elif isinstance(v, list):
                for item in v:
                    out.write(' ' * (indent * IWIDTH) + k + ' ')
                    out.write("{\n")
                    _dump_to_conf(item, out, indent + 1)
                    out.write(' ' * (indent * IWIDTH) + '}\n')
            # The 'CLIENTS' Ganesha string option is an exception in that it's
            # string value can't be enclosed within quotes as can be done for
            # other string options in a valid Ganesha conf file.
            elif k.upper() == 'CLIENTS':
                out.write(' ' * (indent * IWIDTH) + k + ' = ' + v + ';')
            else:
                out.write(' ' * (indent * IWIDTH) + k + ' ')
                out.write('= ')
                _dump_to_conf(v, out, indent)
                out.write(';')
            out.write('\n')
    else:
        dj = jsonutils.dumps(confdict)
        out.write(dj)


def parseconf(conf):
    """Parse Ganesha config.

    Both native format and JSON are supported.

    Convert config to a (nested) dictionary.
    """
    def list_to_dict(l):
        # Convert a list of key-value pairs stored as tuples to a dict.
        # For tuples with identical keys, preserve all the values in a
        # list. e.g., argument [('k', 'v1'), ('k', 'v2')] to function
        # returns {'k': ['v1', 'v2']}.
        d = {}
        for i in l:
            if isinstance(i, tuple):
                k, v = i
                if isinstance(v, list):
                    v = list_to_dict(v)
                if k in d:
                    d[k] = [d[k]]
                    d[k].append(v)
                else:
                    d[k] = v
        return d

    try:
        # allow config to be specified in JSON --
        # for sake of people who might feel Ganesha config foreign.
        d = jsonutils.loads(conf)
    except ValueError:
        # Customize JSON decoder to convert Ganesha config to a list
        # of key-value pairs stored as tuples. This allows multiple
        # occurrences of a config block to be later converted to a
        # dict key-value pair, with block name being the key and a
        # list of block contents being the value.
        l = jsonutils.loads(_conf2json(conf), object_pairs_hook=lambda x: x)
        d = list_to_dict(l)
    return d


def mkconf(confdict):
    """Create Ganesha config string from confdict."""
    s = six.StringIO()
    _dump_to_conf(confdict, s)
    return s.getvalue()


rados = None


def setup_rados():
    global rados
    if not rados:
        try:
            rados = importutils.import_module('rados')
        except ImportError:
            raise exception.ShareBackendException(
                _("python-rados is not installed"))


class GaneshaManager(object):
    """Ganesha instrumentation class."""

    def __init__(self, execute, tag, **kwargs):
        self.confrx = re.compile('\.conf\Z')
        self.ganesha_config_path = kwargs['ganesha_config_path']
        self.tag = tag

        def _execute(*args, **kwargs):
            msg = kwargs.pop('message', args[0])
            makelog = kwargs.pop('makelog', True)
            try:
                return execute(*args, **kwargs)
            except exception.ProcessExecutionError as e:
                if makelog:
                    LOG.error(
                        ("Error while executing management command on "
                         "Ganesha node %(tag)s: %(msg)s."),
                        {'tag': tag, 'msg': msg})
                raise exception.GaneshaCommandFailure(
                    stdout=e.stdout, stderr=e.stderr, exit_code=e.exit_code,
                    cmd=e.cmd)
        self.execute = _execute
        self.ganesha_service = kwargs['ganesha_service_name']
        self.ganesha_export_dir = kwargs['ganesha_export_dir']
        self.execute('mkdir', '-p', self.ganesha_export_dir)

        self.ganesha_rados_store_enable = kwargs.get(
            'ganesha_rados_store_enable')
        if self.ganesha_rados_store_enable:
            setup_rados()
            self.ganesha_rados_store_pool_name = (
                kwargs['ganesha_rados_store_pool_name'])
            self.ganesha_rados_export_counter = (
                kwargs['ganesha_rados_export_counter'])
            self.ganesha_rados_export_index = (
                kwargs['ganesha_rados_export_index'])
            self.ceph_vol_client = (
                kwargs['ceph_vol_client'])
            try:
                self._get_rados_object(self.ganesha_rados_export_counter)
            except rados.ObjectNotFound:
                self._put_rados_object(self.ganesha_rados_export_counter,
                                       six.text_type(1000))
        else:
            self.ganesha_db_path = kwargs['ganesha_db_path']
            self.execute('mkdir', '-p', os.path.dirname(self.ganesha_db_path))
            # Here we are to make sure that an SQLite database of the
            # required scheme exists at self.ganesha_db_path.
            # The following command gets us there -- provided the file
            # does not yet exist (otherwise it just fails). However,
            # we don't care about this condition, we just execute the
            # command unconditionally (ignoring failure). Instead we
            # directly query the db right after, to check its validity.
            self.execute(
                "sqlite3", self.ganesha_db_path,
                'create table ganesha(key varchar(20) primary key, '
                'value int); insert into ganesha values("exportid", '
                '100);', run_as_root=False, check_exit_code=False)
            self.get_export_id(bump=False)

    def _getpath(self, name):
        """Get the path of config file for name."""
        return os.path.join(self.ganesha_export_dir, name + ".conf")

    @staticmethod
    def _get_export_rados_object_name(name):
        return 'ganesha-export-' + name

    def _write_tmp_conf_file(self, path, data):
        """Write data to tmp conf file."""
        dirpath, fname = (getattr(os.path, q + "name")(path) for q in
                          ("dir", "base"))
        tmpf = self.execute('mktemp', '-p', dirpath, "-t",
                            fname + ".XXXXXX")[0][:-1]
        self.execute(
            'sh', '-c',
            'echo %s > %s' % (pipes.quote(data), pipes.quote(tmpf)),
            message='writing ' + tmpf)
        return tmpf

    def _write_conf_file(self, name, data):
        """Write data to config file for name atomically."""
        path = self._getpath(name)
        tmpf = self._write_tmp_conf_file(path, data)
        try:
            self.execute('mv', tmpf, path)
        except exception.ProcessExecutionError as e:
            LOG.error('mv temp file ({0}) to {1} failed.'.format(tmpf, path))
            self.execute('rm', tmpf)
            raise exception.GaneshaCommandFailure(
                stdout=e.stdout, stderr=e.stderr, exit_code=e.exit_code,
                cmd=e.cmd)

        return path

    def _mkindex(self):
        """Generate the index file for current exports."""
        @utils.synchronized("ganesha-index-" + self.tag, external=True)
        def _mkindex():
            files = filter(lambda f: self.confrx.search(f) and
                           f != "INDEX.conf",
                           self.execute('ls', self.ganesha_export_dir,
                                        run_as_root=False)[0].split("\n"))
            index = "".join(map(lambda f: "%include " + os.path.join(
                    self.ganesha_export_dir, f) + "\n", files))
            self._write_conf_file("INDEX", index)
        _mkindex()

    def _read_export_rados_object(self, name):
        return parseconf(self._get_rados_object(
            self._get_export_rados_object_name(name)))

    def _read_export_file(self, name):
        return parseconf(self.execute("cat", self._getpath(name),
                                      message='reading export ' + name)[0])

    def _read_export(self, name):
        """Return the dict of the export identified by name."""
        if self.ganesha_rados_store_enable:
            return self._read_export_rados_object(name)
        else:
            return self._read_export_file(name)

    def _check_export_rados_object_exists(self, name):
        try:
            self._get_rados_object(
                self._get_export_rados_object_name(name))
            return True
        except rados.ObjectNotFound:
            return False

    def _check_file_exists(self, path):
        try:
            self.execute('test', '-f', path, makelog=False,
                         run_as_root=False)
            return True
        except exception.GaneshaCommandFailure as e:
            if e.exit_code == 1:
                return False
            else:
                raise exception.GaneshaCommandFailure(
                    stdout=e.stdout, stderr=e.stderr, exit_code=e.exit_code,
                    cmd=e.cmd)

    def _check_export_file_exists(self, name):
        return self._check_file_exists(self._getpath(name))

    def check_export_exists(self, name):
        """Check whether export exists."""
        if self.ganesha_rados_store_enable:
            return self._check_export_rados_object_exists(name)
        else:
            return self._check_export_file_exists(name)

    def _write_export_rados_object(self, name, data):
        """Write confdict to the export RADOS object of name."""
        self._put_rados_object(self._get_export_rados_object_name(name),
                               data)
        # temp export config file required for DBus calls
        return self._write_tmp_conf_file(self._getpath(name), data)

    def _write_export(self, name, confdict):
        """Write confdict to the export file or RADOS object of name."""
        for k, v in ganesha_utils.walk(confdict):
            # values in the export block template that need to be
            # filled in by Manila are pre-fixed by '@'
            if isinstance(v, six.string_types) and v[0] == '@':
                msg = _("Incomplete export block: value %(val)s of attribute "
                        "%(key)s is a stub.") % {'key': k, 'val': v}
                raise exception.InvalidParameterValue(err=msg)
        if self.ganesha_rados_store_enable:
            return self._write_export_rados_object(name, mkconf(confdict))
        else:
            return self._write_conf_file(name, mkconf(confdict))

    def _rm_file(self, path):
        self.execute("rm", "-f", path)

    def _rm_export_file(self, name):
        """Remove export file of name."""
        self._rm_file(self._getpath(name))

    def _rm_export_rados_object(self, name):
        """Remove export object of name."""
        self._delete_rados_object(self._get_export_rados_object_name(name))

    def _dbus_send_ganesha(self, method, *args, **kwargs):
        """Send a message to Ganesha via dbus."""
        service = kwargs.pop("service", "exportmgr")
        self.execute("dbus-send", "--print-reply", "--system",
                     "--dest=org.ganesha.nfsd", "/org/ganesha/nfsd/ExportMgr",
                     "org.ganesha.nfsd.%s.%s" % (service, method), *args,
                     message='dbus call %s.%s' % (service, method), **kwargs)

    def _remove_export_dbus(self, xid):
        """Remove an export from Ganesha runtime with given export id."""
        self._dbus_send_ganesha("RemoveExport", "uint16:%d" % xid)

    def _add_rados_object_url_to_index(self, name):
        """Add an export RADOS object's URL to the RADOS URL index."""

        # TODO(rraja): Ensure that the export index object's update is atomic,
        # e.g., retry object update until the object version between the 'get'
        # and 'put' operations remains the same.
        index_data = self._get_rados_object(self.ganesha_rados_export_index)

        want_url = "%url rados://{0}/{1}".format(
            self.ganesha_rados_store_pool_name,
            self._get_export_rados_object_name(name))

        if index_data:
            self._put_rados_object(
                self.ganesha_rados_export_index,
                '\n'.join([index_data, want_url])
            )
        else:
            self._put_rados_object(self.ganesha_rados_export_index, want_url)

    def _remove_rados_object_url_from_index(self, name):
        """Remove an export RADOS object's URL from the RADOS URL index."""

        # TODO(rraja): Ensure that the export index object's update is atomic,
        # e.g., retry object update until the object version between the 'get'
        # and 'put' operations remains the same.
        index_data = self._get_rados_object(self.ganesha_rados_export_index)
        if not index_data:
            return

        unwanted_url = "%url rados://{0}/{1}".format(
            self.ganesha_rados_store_pool_name,
            self._get_export_rados_object_name(name))

        rados_urls = index_data.split('\n')
        new_rados_urls = [url for url in rados_urls if url != unwanted_url]

        self._put_rados_object(self.ganesha_rados_export_index,
                               '\n'.join(new_rados_urls))

    def add_export(self, name, confdict):
        """Add an export to Ganesha specified by confdict."""
        xid = confdict["EXPORT"]["Export_Id"]
        undos = []
        _mkindex_called = False
        try:
            path = self._write_export(name, confdict)
            if self.ganesha_rados_store_enable:
                undos.append(lambda: self._rm_export_rados_object(name))
                undos.append(lambda: self._rm_file(path))
            else:
                undos.append(lambda: self._rm_export_file(name))

            self._dbus_send_ganesha("AddExport", "string:" + path,
                                    "string:EXPORT(Export_Id=%d)" % xid)
            undos.append(lambda: self._remove_export_dbus(xid))

            if self.ganesha_rados_store_enable:
                # Clean up temp export file used for the DBus call
                self._rm_file(path)
                self._add_rados_object_url_to_index(name)
            else:
                _mkindex_called = True
                self._mkindex()
        except Exception as e:
            for u in undos:
                u()
            if not self.ganesha_rados_store_enable and not _mkindex_called:
                self._mkindex()
            raise exception.GaneshaCommandFailure(
                stdout=e.stdout, stderr=e.stderr, exit_code=e.exit_code,
                cmd=e.cmd)

    def update_export(self, name, confdict):
        """Update an export to Ganesha specified by confdict."""
        xid = confdict["EXPORT"]["Export_Id"]
        old_confdict = self._read_export(name)

        path = self._write_export(name, confdict)
        try:
            self._dbus_send_ganesha("UpdateExport", "string:" + path,
                                    "string:EXPORT(Export_Id=%d)" % xid)
        except Exception as e:
            # Revert the export update.
            self._write_export(name, old_confdict)
            raise exception.GaneshaCommandFailure(
                stdout=e.stdout, stderr=e.stderr, exit_code=e.exit_code,
                cmd=e.cmd)
        finally:
            if self.ganesha_rados_store_enable:
                # Clean up temp export file used for the DBus update call
                self._rm_file(path)

    def remove_export(self, name):
        """Remove an export from Ganesha."""
        try:
            confdict = self._read_export(name)
            self._remove_export_dbus(confdict["EXPORT"]["Export_Id"])
        finally:
            if self.ganesha_rados_store_enable:
                self._delete_rados_object(
                    self._get_export_rados_object_name(name))
                self._remove_rados_object_url_from_index(name)
            else:
                self._rm_export_file(name)
                self._mkindex()

    def _get_rados_object(self, obj_name):
        """Get data stored in Ceph RADOS object as a text string."""
        return self.ceph_vol_client.get_object(
            self.ganesha_rados_store_pool_name, obj_name).decode('utf-8')

    def _put_rados_object(self, obj_name, data):
        """Put data as a byte string in a Ceph RADOS object."""
        return self.ceph_vol_client.put_object(
            self.ganesha_rados_store_pool_name,
            obj_name,
            data.encode('utf-8'))

    def _delete_rados_object(self, obj_name):
        return self.ceph_vol_client.delete_object(
            self.ganesha_rados_store_pool_name,
            obj_name)

    def get_export_id(self, bump=True):
        """Get a new export id."""
        # XXX overflowing the export id (16 bit unsigned integer)
        # is not handled
        if self.ganesha_rados_store_enable:
            # TODO(rraja): Ensure that the export counter object's update is
            # atomic, e.g., retry object update until the object version
            # between the 'get' and 'put' operations remains the same.
            export_id = int(
                self._get_rados_object(self.ganesha_rados_export_counter))
            if not bump:
                return export_id
            export_id += 1
            self._put_rados_object(self.ganesha_rados_export_counter,
                                   str(export_id))
            return export_id
        else:
            if bump:
                bumpcode = 'update ganesha set value = value + 1;'
            else:
                bumpcode = ''
            out = self.execute(
                "sqlite3", self.ganesha_db_path,
                bumpcode + 'select * from ganesha where key = "exportid";',
                run_as_root=False)[0]
            match = re.search('\Aexportid\|(\d+)$', out)
            if not match:
                LOG.error("Invalid export database on "
                          "Ganesha node %(tag)s: %(db)s.",
                          {'tag': self.tag, 'db': self.ganesha_db_path})
                raise exception.InvalidSqliteDB()
            return int(match.groups()[0])

    def restart_service(self):
        """Restart the Ganesha service."""
        self.execute("service", self.ganesha_service, "restart")

    def reset_exports(self):
        """Delete all export files."""
        self.execute('sh', '-c',
                     'rm -f %s/*.conf' % pipes.quote(self.ganesha_export_dir))
        self._mkindex()
