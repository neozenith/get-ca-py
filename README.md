[![Maintenance yes](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/lifehackjim/cert_human/graphs/commit-activity) [![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/) [![Open Source? Yes!](https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github)](https://github.com/lifehackjim/cert_human) [![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)

Cert Human: SSL Certificates for Humans
=======================================

Description
-----------

Somebody said something about over-engineering. So I obviously had to chime in.

No, but seriously, I was in the midst of rewriting [another project of mine](https://github.com/tanium/pytan), and I wanted to incorporate a method to get an SSL certificate from a server, show the user the same kind of information as you'd see in a browser, prompt them for validity, then write it to disk for use in all [requests](http://docs.python-requests.org/en/master/) to a server.

I was unable to find any great / easy ways that incorporated all of these concepts into one neat thing. So I made a thing.

Originally this was based off of yet another lovely over-engineered solution in [get-ca-py](https://github.com/neozenith/get-ca-py) by [Josh Peak](https://github.com/neozenith).


Installation
------------

To install Cert Human, use pip / pipenv:

``` {.sourceCode .bash}
$ pip install cert_human
```


Documentation
-------------

Available [here](https://cert-human.readthedocs.io/en/latest/)
