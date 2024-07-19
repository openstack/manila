# Copyright 2024 VAST Data Inc.
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
import ipaddress
import types

from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils


CONF = cfg.CONF
LOG = log.getLogger(__name__)


class Bunch(dict):
    # from https://github.com/real-easypy/easypy

    __slots__ = ("__stop_recursing__",)

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            if name[0] == "_" and name[1:].isdigit():
                return self[name[1:]]
            raise AttributeError(
                "%s has no attribute %r" % (self.__class__, name)
            )

    def __getitem__(self, key):
        try:
            return super(Bunch, self).__getitem__(key)
        except KeyError:
            from numbers import Integral

            if isinstance(key, Integral):
                return self[str(key)]
            raise

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        try:
            del self[name]
        except KeyError:
            raise AttributeError(
                "%s has no attribute %r" % (self.__class__, name)
            )

    def __getstate__(self):
        return self

    def __setstate__(self, dict):
        self.update(dict)

    def __repr__(self):
        if getattr(self, "__stop_recursing__", False):
            items = sorted(
                "%s" % k for k in self
                if isinstance(k, str) and not k.startswith("__")
            )
            attrs = ", ".join(items)
        else:
            dict.__setattr__(self, "__stop_recursing__", True)
            try:
                attrs = self.render()
            finally:
                dict.__delattr__(self, "__stop_recursing__")
        return "%s(%s)" % (self.__class__.__name__, attrs)

    def render(self):
        items = sorted(
            "%s=%r" % (k, v)
            for k, v in self.items()
            if isinstance(k, str) and not k.startswith("__")
        )
        return ", ".join(items)

    def to_dict(self):
        return unbunchify(self)

    def to_json(self):
        import json

        return json.dumps(self.to_dict())

    def copy(self, deep=False):
        if deep:
            return _convert(self, self.__class__)
        else:
            return self.__class__(self)

    @classmethod
    def from_dict(cls, d):
        return _convert(d, cls)

    @classmethod
    def from_json(cls, d):
        import json

        return cls.from_dict(json.loads(d))

    def __dir__(self):
        members = set(
            k
            for k in self
            if isinstance(k, str)
            and (k[0] == "_" or k.replace("_", "").isalnum())
        )
        members.update(dict.__dir__(self))
        return sorted(members)

    def without(self, *keys):
        "Return a shallow copy of the bunch without the specified keys"
        return Bunch((k, v) for k, v in self.items() if k not in keys)

    def but_with(self, **kw):
        "Return a shallow copy of the bunch with the specified keys"
        return Bunch(self, **kw)


def _convert(d, typ):
    if isinstance(d, dict):
        return typ({str(k): _convert(v, typ) for k, v in d.items()})
    elif isinstance(d, (tuple, list, set)):
        return type(d)(_convert(e, typ) for e in d)
    else:
        return d


def unbunchify(d):
    """Recursively convert Bunches in `d` to a regular dicts."""
    return _convert(d, dict)


def bunchify(d=None, **kw):
    """Recursively convert dicts in `d` to Bunches.

    If `kw` given, recursively convert dicts in
    it to Bunches and update `d` with it.
    If `d` is None, an empty Bunch is made.
    """

    d = _convert(d, Bunch) if d is not None else Bunch()
    if kw:
        d.update(bunchify(kw))
    return d


def generate_ip_range(ip_ranges):
    """Generate list of ips from provided ip ranges.

    `ip_ranges` should be list of ranges where fist
    ip in range represents start ip and second is end ip
    eg: [["15.0.0.1", "15.0.0.4"], ["10.0.0.27", "10.0.0.30"]]
    """
    return [
        ip.compressed
        for start_ip, end_ip in ip_ranges
        for net in ipaddress.summarize_address_range(
            ipaddress.ip_address(start_ip),
            ipaddress.ip_address(end_ip)
        )
        for ip in net
    ]


def decorate_methods_with(dec):
    if not CONF.debug:
        return lambda cls: cls

    def inner(cls):
        for attr_name, attr_val in cls.__dict__.items():
            if (isinstance(attr_val, types.FunctionType) and
                    not attr_name.startswith("_")):
                setattr(cls, attr_name, dec(attr_val))
        return cls

    return inner


def verbose_driver_trace(fn):
    if not CONF.debug:
        return fn

    def inner(self, *args, **kwargs):
        start = timeutils.utcnow()
        LOG.debug(f"[{fn.__name__}] >>>")
        res = fn(self, *args, **kwargs)
        end = timeutils.utcnow()
        LOG.debug(
            f"Spent {timeutils.delta_seconds(start, end)} sec. "
            f"Return {res}.\n"
            f"<<< [{fn.__name__}]"
        )
        return res

    return inner
