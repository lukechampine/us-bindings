Python bindings
==========

Requires Cython. To build the shared library run:

```
make
```

Two examples are included. filesystem.py uses the existing high level meta
architecture in `us` for file storage. lowlevel.py exposes lower level actions
in `us` including the ability to form contracts and upload/download individual
sectors to the Sia network.
