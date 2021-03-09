Ruby bindings
=============

First build the C bindings to generate `us.so`:

```
cd ../c
go build -o ../ruby/us.so -buildmode=c-shared .
```

You can then run the example program:

```
ruby example/example.rb
```

The API is currently too unstable to bother writing docs for; please refer to
the example program instead.