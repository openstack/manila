============
Healthchecks
============

The health of a the Shared File Systems API service can be determined with
the help of a "healthcheck" middleware. This middleware is enabled by
default with the `api-paste`_ file that is packaged with the software. There
is hence a ``/healthcheck`` endpoint that responds to GET requests with HTTP
200 "OK" as the body if the API service is functional. If the API service is
not functional, the response is HTTP 503 "Service Unavailable".

This ``/healthcheck`` endpoint can be polled by load balancers to determine
service availability. The end point behaves very similar to `mod_status`
in apache. A sample configuration that can be added to the `api-paste`_ file
is as follows.

.. _api-paste: ../configuration/shared-file-systems/samples/api-paste.ini.html

.. code-block::

    [app:healthcheck]
    paste.app_factory = oslo_middleware:Healthcheck.app_factory
    backends = disable_by_file
    disable_by_file_path = /etc/manila/healthcheck_disable
    detailed = False

Example healthcheck requests and responses:

.. code-block::

    $ curl -i -X GET http://203.0.113.30/share/healthcheck
    HTTP/1.1 200 OK
    Date: Wed, 20 Mar 2024 23:00:19 GMT
    Server: Apache/2.4.52 (Ubuntu)
    Content-Type: text/plain; charset=UTF-8
    Content-Length: 2
    Connection: close
    Vary: Accept-Encoding

    OK

    $ curl -i -X GET http://203.0.113.30/share/healthcheck -H "Accept: application/json"
    HTTP/1.1 200 OK
    Date: Wed, 20 Mar 2024 23:01:08 GMT
    Server: Apache/2.4.52 (Ubuntu)
    Content-Type: application/json
    Content-Length: 62
    Connection: close

    {
        "detailed": false,
        "reasons": [
            "OK"
        ]
    }

   $ curl -i -X GET http://203.0.113.30/share/healthcheck -H "Accept: text/html"
    HTTP/1.1 200 OK
    Date: Wed, 20 Mar 2024 23:02:27 GMT
    Server: Apache/2.4.52 (Ubuntu)
    Content-Type: text/html; charset=UTF-8
    Content-Length: 239
    Connection: close
    Vary: Accept-Encoding

    <HTML>
    <HEAD><TITLE>Healthcheck Status</TITLE></HEAD>
    <BODY>

    <H2>Result of 1 checks:</H2>
    <TABLE bgcolor="#ffffff" border="1">
    <TBODY>
    <TR>

    <TH>
    Reason
    </TH>
    </TR>
    <TR>

        <TD>OK</TD>

    </TR>
    </TBODY>
    </TABLE>
    <HR></HR>

    </BODY>
    </HTML>

A "detail" response can be sought if ``detailed`` is set to ``True`` in the
``[app:healthcheck]`` section of the api paste configuration file. This
is not done by default.

.. code-block::

    $ curl -i -X GET http://203.0.113.30/share/healthcheck -H "Accept: application/json"
    HTTP/1.1 200 OK
    Date: Wed, 20 Mar 2024 23:06:19 GMT
    Server: Apache/2.4.52 (Ubuntu)
    Content-Type: application/json
    Content-Length: 4177
    Connection: close

    {
        "detailed": true,
        "gc": {
            "counts": [
                400,
                5,
                0
            ],
            "threshold": [
                700,
                10,
                10
            ]
        },
        "greenthreads": [
            "  File \"/opt/stack/data/venv/lib/python3.10/site-packages/paste/urlmap.py\", line 216, in __call__\n    return app(environ, start_response)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/webob/dec.py\", line 129, in __call__\n    resp = self.call_func(req, *args, **kw)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/webob/dec.py\", line 193, in call_func\n    return self.func(req, *args, **kwargs)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/oslo_middleware/base.py\", line 121, in __call__\n    response = self.process_request(req)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/webob/dec.py\", line 146, in __call__\n    return self.call_func(req, *args, **kw)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/webob/dec.py\", line 193, in call_func\n    return self.func(req, *args, **kwargs)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/oslo_middleware/healthcheck/__init__.py\", line 582, in process_request\n    body, content_type = functor(results, healthy)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/oslo_middleware/healthcheck/__init__.py\", line 510, in _make_json_response\n    body['greenthreads'] = self._get_greenstacks()\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/oslo_middleware/healthcheck/__init__.py\", line 464, in _get_greenstacks\n    traceback.print_stack(gt.gr_frame, file=buf)\n"
        ],
        "now": "2024-03-20 23:06:19.907279",
        "platform": "Linux-5.15.0-91-generic-x86_64-with-glibc2.35",
        "python_version": "3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]",
        "reasons": [
            {
                "class": "HealthcheckResult",
                "details": "Path '/etc/manila/healthcheck_disable' was not found",
                "reason": "OK"
            }
        ],
        "threads": [
            "  File \"/usr/lib/python3.10/threading.py\", line 973, in _bootstrap\n    self._bootstrap_inner()\n  File \"/usr/lib/python3.10/threading.py\", line 1016, in _bootstrap_inner\n    self.run()\n  File \"/usr/lib/python3.10/threading.py\", line 953, in run\n    self._target(*self._args, **self._kwargs)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/tooz/coordination.py\", line 208, in _beat_forever_until_stopped\n    self._dead.wait(has_to_sleep_for / 2.0)\n  File \"/usr/lib/python3.10/threading.py\", line 607, in wait\n    signaled = self._cond.wait(timeout)\n  File \"/usr/lib/python3.10/threading.py\", line 324, in wait\n    gotit = waiter.acquire(True, timeout)\n",
            "  File \"/opt/stack/data/venv/lib/python3.10/site-packages/paste/urlmap.py\", line 216, in __call__\n    return app(environ, start_response)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/webob/dec.py\", line 129, in __call__\n    resp = self.call_func(req, *args, **kw)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/webob/dec.py\", line 193, in call_func\n    return self.func(req, *args, **kwargs)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/oslo_middleware/base.py\", line 121, in __call__\n    response = self.process_request(req)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/webob/dec.py\", line 146, in __call__\n    return self.call_func(req, *args, **kw)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/webob/dec.py\", line 193, in call_func\n    return self.func(req, *args, **kwargs)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/oslo_middleware/healthcheck/__init__.py\", line 582, in process_request\n    body, content_type = functor(results, healthy)\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/oslo_middleware/healthcheck/__init__.py\", line 511, in _make_json_response\n    body['threads'] = self._get_threadstacks()\n  File \"/opt/stack/data/venv/lib/python3.10/site-packages/oslo_middleware/healthcheck/__init__.py\", line 452, in _get_threadstacks\n    traceback.print_stack(stack, file=buf)\n"
        ]
    }

You may disable the healthcheck endpoint dynamically by creating a file called
``/etc/manila/healthcheck_disable``. The name of this file can be customized
with the configuration option ``disable_by_file_path`` in the
``[app:healthcheck]`` section of the api paste configuration file.
