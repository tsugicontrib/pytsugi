# pytsugi

This is an emergent implementation of the Python Tsugi library.

See also the pytsugi-web2py repository for a sample of this use

If you want to use this:

    pip install pytsugi

Use sudo as necessary.

Developing and Testing Locally
------------------------------

If you want to change source code and develop pytsugi, do the following:

    pip uninstall pytsugi

    git checkout https://github.com/tsugiproject/pytsugi
    cd pytsugi
    python setup.py develop

Usie sudo as necessary.  This sets up a soft link so you can go
a `git pull` in pytsugi and not have to rerun `setup.py`.

Of course if you are using Web2Py (I don't know about other
frameworks) it caches module loads so you need to restart Web2Py
when you change pytsugi code.

To go back to the released version:

    python setup.py develop --uninstall
    pip install pytsugi

Releasing
---------

To release you first must have a pypi account and have permission to upload
a new version.

Also you should tag a release the git repo for the version in `setup.py`
in case you want to go back.

Undo the developer mode if you have done it (sudo as needed):

    python setup.py develop --uninstall
    rm -r pytsugi.egg-info/

    python setup.py sdist
    python setup.py register
    python setup.py sdist upload  (Requires pypi account)

Check on pypi to see if it made it.

    https://pypi.python.org/pypi/pytsugi/

After you do the release, increment the version number in the setup.py file since
you can only do one release per version.  That is the next "working version" until
you send it up to `pypi`.

References
----------

* https://ewencp.org/blog/a-brief-introduction-to-packaging-python/


