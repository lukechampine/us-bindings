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
hs = pyus.HostSet(host='127.0.0.1', port=9980)
hs.add_host(c)

# create filesystem
try:
    os.mkdir("meta")
except FileExistsError:
    pass

with pyus.FileSystem("meta", hs) as fs:
    # create a file
    with fs.create("foo.txt", 1) as f:

        # write (upload) some data
        data = b"Hello from Python!"
        f.write(data)
        print("Uploaded:", data)

    # reopen and read (download) the data
    with fs.open("foo.txt") as f:
        buf = f.read(18)
        print("Downloaded:", buf)

