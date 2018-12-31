CLI Reference
======================

.. automodule:: cert_human_cli
    :members:

Help
----

.. code-block:: console

    bash-3.2$ ./cert_human_cli.py cyborg --help
    usage: cert_human_cli.py [-h] [--port PORT] [--method {requests,socket}]
                             [--chain] [--print_mode {info,key,extensions,all}]
                             [--write_path WRITE_PATH] [--overwrite]
                             [--verify VERIFY]
                             HOST

    Request a URL and get the server cert and server cert chain.

    positional arguments:
      HOST                  Host to get cert and cert chain from

    optional arguments:
      -h, --help            show this help message and exit
      --port PORT           Port on host to connect to (default: 443)
      --method {requests,socket}
                            Use 'requests' to use requests.get or 'socket' to use
                            an SSL socket. (default: requests)
      --chain               Print/write the cert chain instead of the cert.
                            (default: False)
      --print_mode {info,key,extensions,all}
                            When no --write_path specified, print this type of
                            information for the cert. (default: info)
      --write_path WRITE_PATH
                            Write server certificate to this file (default: )
      --overwrite           When writing to --write_path and file exists,
                            overwrite. (default: False)
      --verify VERIFY       PEM file to verify host, empty will disable verify,
                            for --method requests. (default: )
