gomobile bindings
=================

### iOS

```
go get -u lukechampine.com/us-bindings/gomobile
go get golang.org/x/mobile/cmd/gomobile
gomobile bind -target=ios lukechampine.com/us-bindings/gomobile
```

This will produce a framework, `Us.framework`, which you can import into Xcode.

### Android

See https://github.com/golang/go/wiki/Mobile#building-and-deploying-to-android-1
