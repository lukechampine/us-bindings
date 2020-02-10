import os
import binascii
import pyus

# load contract

# fill in this string with a hex-encoded contract; it should be 192 bytes.
# You can turn an existing contract into a hex string with the following
# command:
#      xxd -ps -s 12 -l 96 my.contract | tr -d '\n'
c_hex = b'<hex contract string>'
c = binascii.unhexlify(c_hex)

# create host set with contract

# args for a siad instance. Eventually this can include support for shard servers
client = pyus.Filesystem(host='127.0.0.1', port=9980)
client.hostset_add(c)

# create filesystem
try:
    os.mkdir("meta")
except FileExistsError:
    pass

client.fs_init("meta")

# create a file
f = client.fs_create("foo.txt", 1)

# write (upload) some data
data = b"Hello from Python!"
client.file_write(f, data)
print("Uploaded:", data)

# close the file
client.file_close(f)

# reopen and read (download) the data
f = client.fs_open("foo.txt")
buf = client.file_read(f, 18)
print("Downloaded:", buf)

# close the filesystem
client.fs_close()

