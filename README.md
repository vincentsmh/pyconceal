This is a python code protection project.

Release binary package
======================

```bash
$ make release

...
...
Release package: pyconceal-v0.3.tar.gz
```

The binary package is archieved in `pyconceal-v0.3.tar.gz`.

How to Use
==========

Assume your python source codes are located in /path/your/codes
Go into the pyconceal folder and do

```bash
$ ./obfuscator [path to source folder | file]
```

Configuration
=============

`obfuscator.config` in pyconceal is the configuration file which allowes you to
skip obfuscation on some names. In current version, pyconceal supports:

  - skip_class
  - skip_function
  - skip_variable
