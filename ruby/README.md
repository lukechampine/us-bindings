Ruby bindings
=============

First build the C bindings to generate `us.so`:

```
go build -o us.so -buildmode=c-shared ../c/bindings.go
```

You can then run the example program:

```
ruby example/example.rb
```

The API is currently too unstable to bother writing docs for; please refer to
the example program instead.