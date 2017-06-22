# pytsugi

This is an emergent implementation of the Python Tsugi library.

See also the pytsugi-web2py repository for a sample of this use

Soon this will be in pypi but for now, do this:

    git checkout https://github.com/tsugiproject/pytsugi
    cd pytsugi
    python setup.py develop

You may need `sudo` in front of the python.  This sets up a soft link
so you can go a `git pull` in pytsugi and not have to rerun `setup.py`

Releasing
---------

Undo the developer mode (sudo as needed):

    python setup.py develop --uninstall

    python setup.py sdist

    ... Still researching this.


References
----------

* https://ewencp.org/blog/a-brief-introduction-to-packaging-python/


