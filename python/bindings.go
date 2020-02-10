package main

/*
#cgo pkg-config: python-3.6
#include <Python.h>
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
    "context"
    "time"
    "math/big"
    "bufio"
    "bytes"

    "github.com/pkg/errors"
    "gitlab.com/NebulousLabs/Sia/crypto"
    "gitlab.com/NebulousLabs/Sia/types"
    "lukechampine.com/us/ed25519"
    "lukechampine.com/us/hostdb"
    "lukechampine.com/us/merkle"
    "lukechampine.com/us/renter"
    "lukechampine.com/us/renter/proto"
    "lukechampine.com/us/renter/renterutil"
    "lukechampine.com/us/renterhost"
    // "lukechampine.co/shard"
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

var (
    clientMu  sync.Mutex
)

// It's also not easy to pass errors to C code, so we store a global error on
// the Go side and make it accessible via a function. All functions that would
// normally return an error return a 'falsey' value instead; the C code can then
// call us_error to access the corresponding error.
var (
    us_err = make(map[uintptr]error)
    errMu  sync.Mutex
)

func setError(id unsafe.Pointer, err error) bool {
    if err != nil {
        // get calling function name
        pc, _, _, _ := runtime.Caller(1)
        fnName := strings.TrimPrefix(runtime.FuncForPC(pc).Name(), "main.")
        err = fmt.Errorf("%v: %v", fnName, err)
    }
    errMu.Lock()
    defer errMu.Unlock()
    us_err[uintptr(id)] = err
    return us_err[uintptr(id)] != nil
}

//export us_error
func us_error(id unsafe.Pointer) *C.char {
    errMu.Lock()
    defer errMu.Unlock()
    if us_err[uintptr(id)] == nil {
        return nil
    }
    return C.CString(us_err[uintptr(id)].Error())
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

func scanCurrency(s string) (types.Currency, error) {
    var hastings string
    if strings.HasSuffix(s, "H") {
        hastings = strings.TrimSuffix(s, "H")
    } else {
        units := []string{"pS", "nS", "uS", "mS", "SC", "KS", "MS", "GS", "TS"}
        for i, unit := range units {
            if strings.HasSuffix(s, unit) {
                // scan into big.Rat
                r, ok := new(big.Rat).SetString(strings.TrimSuffix(s, unit))
                if !ok {
                    return types.Currency{}, errors.New("Malformed currency value")
                }
                // convert units
                exp := 24 + 3*(int64(i)-4)
                mag := new(big.Int).Exp(big.NewInt(10), big.NewInt(exp), nil)
                r.Mul(r, new(big.Rat).SetInt(mag))
                // r must be an integer at this point
                if !r.IsInt() {
                    return types.Currency{}, errors.New("Non-integer number of hastings")
                }
                hastings = r.RatString()
                break
            }
        }
    }
    if hastings == "" {
        return types.Currency{}, errors.New("Currency value is missing units")
    }
    var c types.Currency
    _, err := fmt.Sscan(hastings, &c)
    if err != nil {
      return types.Currency{}, errors.Wrap(err, "Could not scan currency value")
    }
    return c, nil
}

//export us_ll_client_init
func us_ll_client_init(addr *C.char, pw *C.char) unsafe.Pointer {
    siadAddr := C.GoString(addr)
    siadPassword := C.GoString(pw)
    siadClient := renterutil.NewSiadClient(siadAddr, siadPassword)
    return storePtr(siadClient)
}

//export us_ll_form_contract
func us_ll_form_contract(id unsafe.Pointer, client_p unsafe.Pointer, host_str *C.char, key_ptr unsafe.Pointer, total_funds *C.char, duration C.uint) unsafe.Pointer {
    clientMu.Lock()
    defer clientMu.Unlock()
    siad := loadPtr(client_p).(*renterutil.SiadClient)
    hostKeyPrefix := C.GoString(host_str)
    totalFunds := C.GoString(total_funds)

    hostKey, err := siad.LookupHost(hostKeyPrefix)
    if setError(id, err) {
        return nil
    }
    addr, err := siad.ResolveHostKey(hostKey)
    if setError(id, err) {
        return nil
    }
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    host, err := hostdb.Scan(ctx, addr, hostKey)
    if setError(id, err) {
        return nil
    }

    currentHeight, err := siad.ChainHeight()
    if setError(id, err) {
        return nil
    }

    key := ed25519.NewKeyFromSeed(goBytes(key_ptr, 32))
    funds, err := scanCurrency(totalFunds)
    if setError(id, err) {
        return nil
    }
    contract, _, err := proto.FormContract(siad, siad, key, host, funds, currentHeight, currentHeight+types.BlockHeight(duration))
    if setError(id, err) {
        return nil
    }
    buf := make([]byte, C.sizeof_struct_contract_t)
    copy(buf[0:32], contract.HostKey().Ed25519())
    copy(buf[32:64], contract.Revision.ParentID[:])
    copy(buf[64:96], key[:ed25519.SeedSize])
    return C.CBytes(buf)
}

//export us_ll_new_session
func us_ll_new_session(id unsafe.Pointer, client_p unsafe.Pointer, host_str *C.char, contract *C.struct_contract_t) unsafe.Pointer {
    clientMu.Lock()
    defer clientMu.Unlock()
    siad := loadPtr(client_p).(*renterutil.SiadClient)
    hostKeyPrefix := C.GoString(host_str)

    hostKey, err := siad.LookupHost(hostKeyPrefix)
    if setError(id, err) {
        return nil
    }
    addr, err := siad.ResolveHostKey(hostKey)
    if setError(id, err) {
        return nil
    }
    currentHeight, err := siad.ChainHeight()
    if setError(id, err) {
        return nil
    }

    var c renter.Contract
    copy(c.ID[:], C.GoBytes(unsafe.Pointer(&contract.id), 32))
    c.HostKey = hostdb.HostKeyFromPublicKey(C.GoBytes(unsafe.Pointer(&contract.hostKey), 32))
    c.RenterKey = ed25519.NewKeyFromSeed(C.GoBytes(unsafe.Pointer(&contract.renterKey), 32))
    session, err := proto.NewSession(addr, hostKey, c.ID, c.RenterKey, currentHeight)
    if setError(id, err) {
        return nil
    }
    return storePtr(session)
}

//export us_ll_upload
func us_ll_upload(id unsafe.Pointer, session_p unsafe.Pointer, buf unsafe.Pointer) unsafe.Pointer {
    session := loadPtr(session_p).(*proto.Session)
    var sector [renterhost.SectorSize]byte
    copy(sector[:], goBytes(buf, renterhost.SectorSize))
    err := session.Write([]renterhost.RPCWriteAction{{
              Type: renterhost.RPCWriteActionAppend,
              Data: sector[:],
    }})
    if setError(id, err) {
        return nil
    }
    MerkleRoot := merkle.SectorRoot(&sector)
    return C.CBytes(MerkleRoot[:])
}

//export us_ll_download
func us_ll_download(id unsafe.Pointer, session_p unsafe.Pointer, root unsafe.Pointer, buf unsafe.Pointer, offset C.uint, length C.uint) C.ssize_t {
    session := loadPtr(session_p).(*proto.Session)
    var sectorMerkleRoot crypto.Hash
    copy(sectorMerkleRoot[:], goBytes(root, crypto.HashSize))
    var b bytes.Buffer
    dst := bufio.NewWriter(&b)
    err := session.Read(dst, []renterhost.RPCReadRequestSection{{
              MerkleRoot: sectorMerkleRoot,
              Offset:     uint32(offset),
              Length:     uint32(length),
    }})
    if setError(id, err) {
        return -1
    }
    dst.Flush()
    copy(goBytes(buf, int(length)), b.Bytes())
    return C.ssize_t(length)
}

//export us_ll_session_close
func us_ll_session_close(id unsafe.Pointer, session_p unsafe.Pointer) bool {
    session := loadPtr(session_p).(*proto.Session)
    session.Close()
    freePtr(session_p)
    return true
}

//export us_hostset_init
func us_hostset_init(id unsafe.Pointer, addr *C.char, pw *C.char) unsafe.Pointer {
    siadAddr := C.GoString(addr)
    siadPassword := C.GoString(pw)
    siadClient := renterutil.NewSiadClient(siadAddr, siadPassword)
    currentHeight, err := siadClient.ChainHeight()
    if setError(id, err) {
        return nil
    }
    hs := renterutil.NewHostSet(siadClient, currentHeight)
    return storePtr(hs)
}

//export us_hostset_add
func us_hostset_add(id unsafe.Pointer, hostset_p unsafe.Pointer, contract *C.struct_contract_t) bool {
    hs := loadPtr(hostset_p).(*renterutil.HostSet)
    var c renter.Contract
    copy(c.ID[:], C.GoBytes(unsafe.Pointer(&contract.id), 32))
    c.HostKey = hostdb.HostKeyFromPublicKey(C.GoBytes(unsafe.Pointer(&contract.hostKey), 32))
    c.RenterKey = ed25519.NewKeyFromSeed(C.GoBytes(unsafe.Pointer(&contract.renterKey), 32))
    hs.AddHost(c)
    return true
}

//export us_fs_init
func us_fs_init(id unsafe.Pointer, root *C.char, hs unsafe.Pointer) unsafe.Pointer {
    pfs := renterutil.NewFileSystem(C.GoString(root), loadPtr(hs).(*renterutil.HostSet))
    return storePtr(pfs)
}

//export us_fs_close
func us_fs_close(id unsafe.Pointer, fs_p unsafe.Pointer) bool {
    if loadPtr(fs_p) == nil {
        return true
    }
    pfs := loadPtr(fs_p).(*renterutil.PseudoFS)
    freePtr(fs_p)
    return !setError(id, pfs.Close())
}

//export us_fs_create
func us_fs_create(id unsafe.Pointer, fs_p unsafe.Pointer, name *C.char, minHosts int) unsafe.Pointer {
    pfs := loadPtr(fs_p).(*renterutil.PseudoFS)
    pf, err := pfs.Create(C.GoString(name), minHosts)
    if setError(id, err) {
        return nil
    }
    return storePtr(pf)
}

//export us_fs_open
func us_fs_open(id unsafe.Pointer, fs_p unsafe.Pointer, name *C.char) unsafe.Pointer {
    pfs := loadPtr(fs_p).(*renterutil.PseudoFS)
    pf, err := pfs.Open(C.GoString(name))
    if setError(id, err) {
        return nil
    }
    return storePtr(pf)
}

//export us_file_read
func us_file_read(id unsafe.Pointer, file_p unsafe.Pointer, buf unsafe.Pointer, count C.size_t) C.ssize_t {
    pf := loadPtr(file_p).(*renterutil.PseudoFile)
    n, err := pf.Read(goBytes(buf, int(count)))
    if setError(id, err) {
        return -1
    }
    return C.ssize_t(n)
}

//export us_file_write
func us_file_write(id unsafe.Pointer, file_p unsafe.Pointer, buf unsafe.Pointer, count C.size_t) C.ssize_t {
    pf := loadPtr(file_p).(*renterutil.PseudoFile)
    n, err := pf.Write(goBytes(buf, int(count)))
    if setError(id, err) {
        return -1
    }
    return C.ssize_t(n)
}

//export us_file_seek
func us_file_seek(id unsafe.Pointer, file_p unsafe.Pointer, offset C.long, whence C.int) C.int {
    pf := loadPtr(file_p).(*renterutil.PseudoFile)
    n, err := pf.Seek(int64(offset), int(whence))
    if setError(id, err) {
        return -1
    }
    return C.int(n)
}

//export us_file_close
func us_file_close(id unsafe.Pointer, file_p unsafe.Pointer) bool {
    if loadPtr(file_p) == nil {
        return true
    }
    pf := loadPtr(file_p).(*renterutil.PseudoFile)
    freePtr(file_p)
    return !setError(id, pf.Close())
}

func main() {}
