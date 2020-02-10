default: pyus

pyus: setup.py pyus.pyx libus.a
	python3 setup.py build_ext --inplace && rm -f pyus.c && rm -rf build

libus.a:
	go build -o libus.a -buildmode=c-archive bindings.go

clean:
	-@rm -rf *.so *.a *.c *.h || true
