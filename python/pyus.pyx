#cython: language_level=3
import cython
from libc.stdlib cimport free

cdef extern from "libus.h":
    ctypedef signed char GoInt8
    ctypedef unsigned char GoUint8
    ctypedef short GoInt16
    ctypedef unsigned short GoUint16
    ctypedef int GoInt32
    ctypedef unsigned int GoUint32
    ctypedef long long GoInt64
    ctypedef unsigned long long GoUint64
    ctypedef GoInt64 GoInt
    ctypedef GoUint64 GoUint
    ctypedef float GoFloat32
    ctypedef double GoFloat64
    ctypedef struct contract_t:
        unsigned char hostKey[32]
        unsigned char id[32]
        unsigned char renterKey[32]

    extern char* us_error(void* p0) nogil
    extern void* us_ll_client_init(void* p0, char* p1, char* p2) nogil
    extern void* us_ll_form_contract(void* p0, void* p1, char* p2, void* p3, char* p4, unsigned int p5) nogil
    extern void* us_ll_new_session(void* p0, void* p1, void* p2, char* p3, contract_t* p4) nogil
    extern void* us_ll_upload(void* p0, void* p1, void* p2) nogil
    extern ssize_t us_ll_download(void* p0, void* p1, void* p2, void* p3, unsigned int p4, unsigned int p5) nogil
    extern GoUint8 us_ll_session_close(void* p0, void* p1)
    extern GoUint8 us_ll_client_close(void* p0)
    extern void* us_hostset_init(void* p0, char* p1, char* p2);
    extern GoUint8 us_hostset_add(void* p0, void* p1, contract_t* p2);
    extern void* us_fs_init(void* p0, char* p1, void* p2);
    extern GoUint8 us_fs_close(void* p0, void* p1);
    extern void* us_fs_create(void* p0, void* p1, char* p2, GoInt p3);
    extern void* us_fs_open(void* p0, void* p1, char* p2);
    extern ssize_t us_file_read(void* p0, void* p1, void* p2, size_t p3);
    extern ssize_t us_file_write(void* p0, void* p1, void* p2, size_t p3);
    extern int us_file_seek(void* p0, void* p1, long int p2, int p3);
    extern GoUint8 us_file_close(void* p0, void* p1);

SECTOR_SIZE = 1 << 22
HASH_LEN = 32

cdef class Client:
    cdef unsigned int _siad

    def __init__(self, host='127.0.0.1', port=9980, api_password=''):
        addr = host.encode() + b':' + str(port).encode()
        pw = api_password.encode()

        self._siad = <unsigned int>us_ll_client_init(<void*>self, addr, pw)
        if not self._siad:
            raise RuntimeError(self.error())

    def error(self):
        cdef char *e = us_error(<void*>self)
        try:
            return e.decode()
        finally:
            free(e)

    def form_contract(self, host, key, total_funds, duration):
        host = host.encode()
        total_funds = total_funds.encode()
        cdef unsigned char[:] key_view = bytearray(key)

        cdef char *contract = <char*>us_ll_form_contract(<void*>self, <void*>self._siad, host, <void*>&key_view[0], total_funds, duration)
        if not contract:
            raise RuntimeError(self.error())

        c = bytearray(contract[:sizeof(contract_t)])
        free(contract)
        return c

    def new_session(self, pubkey, contract):
        return Session(self, pubkey, contract)

    @property
    def siad(self):
        return self._siad

    def __dealloc__(self):
        us_ll_client_close(<void*>self)


cdef class Session:
    cdef unsigned int sess

    def __init__(self, client, pubkey, contract):
        host = pubkey.encode()
        cdef contract_t c
        c.hostKey = contract[:32]
        c.id = contract[32:64]
        c.renterKey = contract[64:96]

        cdef unsigned int siad = client.siad
        session = <unsigned int>us_ll_new_session(<void*>self, <void*>client, <void*>siad, host, &c)
        if not session:
            raise RuntimeError(self.error())

        self.sess = session

    def error(self):
        cdef char *e = us_error(<void*>self)
        try:
            return e.decode()
        finally:
            free(e)

    def upload(self, sector):
        sector = bytearray(sector)

        rem = SECTOR_SIZE - len(sector)
        sector.extend(rem * b'\x00')

        cdef unsigned char[:] sector_view = sector
        cdef char *root

        with cython.boundscheck(False):
            with nogil:
                root = <char*>us_ll_upload(<void*>self, <void*>self.sess, <void*>&sector_view[0])
        if not root:
            raise RuntimeError(self.error())

        h = bytearray(root[:HASH_LEN])
        free(root)
        return h

    def download(self, root, offset=0, length=SECTOR_SIZE):
        cdef unsigned char[:] data = bytearray(length)
        cdef unsigned char[:] root_view = bytearray(root)
        cdef unsigned int o = offset
        cdef unsigned int l = length

        with cython.boundscheck(False):
            with nogil:
                ret = us_ll_download(<void*>self, <void*>self.sess, <void*>&root_view[0], <void*>&data[0], o, l)
        if ret < 0:
            raise RuntimeError(self.error())

        return bytearray(data)

    def __dealloc__(self):
        if self.sess:
            us_ll_session_close(<void*>self, <void*>self.sess)


cdef class Filesystem:
    cdef unsigned int hs
    cdef unsigned int fs

    def __init__(self, host='127.0.0.1', port=9980, api_password=''):
        addr = host.encode() + b':' + str(port).encode()
        pw = api_password.encode()

        self.hs = <unsigned int>us_hostset_init(<void*>self, addr, pw)
        if not self.hs:
            raise RuntimeError(self.error())

    def error(self):
        cdef char *e = us_error(<void*>self)
        try:
            return e.decode()
        finally:
            free(e)

    def hostset_add(self, contract):
        cdef contract_t c
        c.hostKey = contract[:32]
        c.id = contract[32:64]
        c.renterKey = contract[64:96]
        us_hostset_add(<void*>self, <void*>self.hs, &c)

    def fs_init(self, root):
        root = root.encode()

        self.fs = <unsigned int>us_fs_init(<void*>self, root, <void*>self.hs)

    def fs_create(self, filename, min_hosts):
        filename = filename.encode()

        cdef unsigned int f

        f = <unsigned int>us_fs_create(<void*>self, <void*>self.fs, filename, min_hosts)
        if not f:
            raise RuntimeError(self.error())

        return f

    def fs_open(self, filename):
        filename = filename.encode()

        cdef unsigned int f

        f = <unsigned int>us_fs_open(<void*>self, <void*>self.fs, filename)
        if not f:
            raise RuntimeError(self.error())

        return f

    def file_read(self, f, length):
        cdef unsigned char[:] data = bytearray(length)

        n = us_file_read(<void*>self, <void*><unsigned int>f, <void*>&data[0], length)
        if n < 0:
            raise RuntimeError(self.error())

        return bytearray(data[:n])

    def file_write(self, f, data):
        length = len(data)

        cdef unsigned char[:] view = bytearray(data)

        n = us_file_write(<void*>self, <void*><unsigned int>f, <void*>&view[0], length)
        if n < 0:
            raise RuntimeError(self.error())

        return n

    def file_seek(self, f, offset, whence=0):
        n = us_file_seek(<void*>self, <void*><unsigned int>f, offset, whence)
        if n < 0:
            raise RuntimeError(self.error())

        return n

    def file_close(self, f):
        ok = us_file_close(<void*>self, <void*><unsigned int>f)
        if not ok:
            raise RuntimeError(self.error())

        return ok

    def fs_close(self):
        ok = us_fs_close(<void*>self, <void*>self.fs)
        if not ok:
            raise RuntimeError(self.error())

        return ok
