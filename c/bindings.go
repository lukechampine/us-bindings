package main

/*
#include <unistd.h>
#include <stdint.h>
typedef struct contract_t {
	uint8_t hostKey[32];
	uint8_t id[32];
	uint8_t renterKey[32];
} contract_t;
*/
import "C"
import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renter/renterutil"
)

// cgo doesn't let us pass Go pointers to C code. This is annoying, because it
// means we can't write constructors like NewHostSet in the "obvious" way
// (return some opaque object, and provide C-style "methods" that take the
// object as their first argument).
//
// Instead, we use a hack: when we construct an object like a HostSet, we stick
// the actual object in a big global table managed by the Go runtime, and return
// an index into this table as our "opaque object." Then, to simulate a "method
// call", the C code passes this index to a Go function, which looks it up in
// the table and calls the appropriate method. We make the API slightly nicer by
// using unsafe.Pointer as our index, which gives us 'nil/null' semantics, but
// in reality it's just an integer.
var (
	ptrtab   = make(map[uintptr]interface{})
	ptrIndex uintptr
	ptrMu    sync.Mutex
)

func storePtr(v interface{}) unsafe.Pointer {
	ptrMu.Lock()
	defer ptrMu.Unlock()
	if v == nil {
		return nil
	}
	ptrIndex++
	ptrtab[ptrIndex] = v
	return unsafe.Pointer(ptrIndex) // go vet complains about this, but it's fine
}

func loadPtr(p unsafe.Pointer) interface{} {
	ptrMu.Lock()
	defer ptrMu.Unlock()
	if p == nil {
		return nil
	}
	return ptrtab[uintptr(p)]
}

func freePtr(p unsafe.Pointer) {
	ptrMu.Lock()
	defer ptrMu.Unlock()
	if p != nil {
		delete(ptrtab, uintptr(p))
	}
}

// It's also not easy to pass errors to C code, so we store a global error on
// the Go side and make it accessible via a function. All functions that would
// normally return an error return a 'falsey' value instead; the C code can then
// call us_error to access the corresponding error.
var (
	us_err error
	errMu  sync.Mutex
)

func setError(err error) bool {
	if err != nil {
		// get calling function name
		pc, _, _, _ := runtime.Caller(1)
		fnName := strings.TrimPrefix(runtime.FuncForPC(pc).Name(), "main.")
		err = fmt.Errorf("%v: %v", fnName, err)
	}
	errMu.Lock()
	defer errMu.Unlock()
	us_err = err
	return us_err != nil
}

//export us_error
func us_error() *C.char {
	errMu.Lock()
	defer errMu.Unlock()
	if us_err == nil {
		return nil
	}
	return C.CString(us_err.Error())
}

// goBytes is like C.GoBytes, but directly aliases the C memory instead of
// making a copy.
func goBytes(ptr unsafe.Pointer, n int) []byte {
	return *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(ptr),
		Len:  n,
		Cap:  n,
	}))
}

// helper type to satisfy proto.ContractEditor without touching disk
type ephemeralEditor struct {
	rev proto.ContractRevision
	key ed25519.PrivateKey
}

func (e *ephemeralEditor) Revision() proto.ContractRevision             { return e.rev }
func (e *ephemeralEditor) SetRevision(rev proto.ContractRevision) error { e.rev = rev; return nil }
func (e *ephemeralEditor) Key() ed25519.PrivateKey                      { return e.key }

//export us_contract_init
func us_contract_init(contract *C.struct_contract_t, data *C.char) {
	b := goBytes(unsafe.Pointer(data), 96)
	copy(goBytes(unsafe.Pointer(&contract.hostKey), 32), b[:32])
	copy(goBytes(unsafe.Pointer(&contract.id), 32), b[32:64])
	copy(goBytes(unsafe.Pointer(&contract.renterKey), 32), b[64:96])
}

//export us_hostset_init
func us_hostset_init(srv *C.char) unsafe.Pointer {
	shard := renterutil.NewSHARDClient(C.GoString(srv))
	currentHeight, err := shard.ChainHeight()
	if setError(err) {
		return nil
	}
	hs := renterutil.NewHostSet(shard, currentHeight)
	return storePtr(hs)
}

//export us_hostset_add
func us_hostset_add(hostset_p unsafe.Pointer, contract *C.struct_contract_t) bool {
	hs := loadPtr(hostset_p).(*renterutil.HostSet)
	var rev proto.ContractRevision
	copy(rev.Revision.ParentID[:], C.GoBytes(unsafe.Pointer(&contract.id), 32))
	renterKey := ed25519.NewKeyFromSeed(C.GoBytes(unsafe.Pointer(&contract.renterKey), 32))
	rpk := hostdb.HostKeyFromPublicKey(renterKey.PublicKey()).SiaPublicKey()
	hpk := hostdb.HostKeyFromPublicKey(C.GoBytes(unsafe.Pointer(&contract.hostKey), 32)).SiaPublicKey()
	rev.Revision.UnlockConditions.PublicKeys = append(rev.Revision.UnlockConditions.PublicKeys, rpk, hpk)
	err := hs.AddHost(&ephemeralEditor{rev, renterKey})
	return !setError(err)
}

//export us_fs_init
func us_fs_init(root *C.char, hs unsafe.Pointer) unsafe.Pointer {
	pfs := renterutil.NewFileSystem(C.GoString(root), loadPtr(hs).(*renterutil.HostSet))
	return storePtr(pfs)
}

//export us_fs_close
func us_fs_close(fs_p unsafe.Pointer) bool {
	if loadPtr(fs_p) == nil {
		return true
	}
	pfs := loadPtr(fs_p).(*renterutil.PseudoFS)
	freePtr(fs_p)
	return !setError(pfs.Close())
}

//export us_fs_create
func us_fs_create(fs_p unsafe.Pointer, name *C.char, minHosts int) unsafe.Pointer {
	pfs := loadPtr(fs_p).(*renterutil.PseudoFS)
	pf, err := pfs.Create(C.GoString(name), minHosts)
	if setError(err) {
		return nil
	}
	return storePtr(pf)
}

//export us_fs_open
func us_fs_open(fs_p unsafe.Pointer, name *C.char) unsafe.Pointer {
	pfs := loadPtr(fs_p).(*renterutil.PseudoFS)
	pf, err := pfs.Open(C.GoString(name))
	if setError(err) {
		return nil
	}
	return storePtr(pf)
}

//export us_file_read
func us_file_read(file_p unsafe.Pointer, buf unsafe.Pointer, count C.size_t) C.ssize_t {
	pf := loadPtr(file_p).(*renterutil.PseudoFile)
	n, err := pf.Read(goBytes(buf, int(count)))
	if setError(err) {
		return -1
	}
	return C.ssize_t(n)
}

//export us_file_write
func us_file_write(file_p unsafe.Pointer, buf unsafe.Pointer, count C.size_t) C.ssize_t {
	pf := loadPtr(file_p).(*renterutil.PseudoFile)
	n, err := pf.Write(goBytes(buf, int(count)))
	if setError(err) {
		return -1
	}
	return C.ssize_t(n)
}

//export us_file_seek
func us_file_seek(file_p unsafe.Pointer, offset C.long, whence C.int) C.int {
	pf := loadPtr(file_p).(*renterutil.PseudoFile)
	n, err := pf.Seek(int64(offset), int(whence))
	if setError(err) {
		return -1
	}
	return C.int(n)
}

//export us_file_close
func us_file_close(file_p unsafe.Pointer) bool {
	if loadPtr(file_p) == nil {
		return true
	}
	pf := loadPtr(file_p).(*renterutil.PseudoFile)
	freePtr(file_p)
	return !setError(pf.Close())
}

func main() {}
