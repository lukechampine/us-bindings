import os
import binascii
import pyus


# args for a siad instance. Eventually this can include support for walrus+shard servers
client = pyus.Client(api_password='3b70ee9c24decf07bb4066849e2c0571')

# form a new contract with a host, first 4 bytes of the pubkey is sufficient for lookup
c = client.form_contract('feedface', os.urandom(32), '10mS', 288)

# create a new session with the newly formed contract
session = client.new_session('feedface', c)

# Upload some data, gets padded upto the SectorSize
h = session.upload(b'A'*64 + b'B'*64)

# Download it back with a partial read (multiple of SegmentSize)
z = session.download(h, offset=64, length=64)

print(z)

