C bindings
==========

To build a shared library and accompanying header file, run:

```
go build -o us.so -buildmode=c-shared bindings.go
```

You can then compile the example program:

```
cc -o example example/example.c ./us.so
```

The API is currently too unstable to bother writing docs for; please refer to
the example program instead.