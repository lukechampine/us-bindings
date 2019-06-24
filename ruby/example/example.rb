require_relative '../us.rb'

# Create a host set. Fill in this string with the address of any shard server.
hs = Us::HostSet.new("<shard server address>")

# Load a contract into the host set.
#
# Fill in this string with a hex-encoded contract. It should be 192 bytes.
# You can turn an existing contract into a hex string with the following
# command:
#     xxd -ps -s 12 -l 96 my.contract | tr -d '\n'
hs.add_host(Us::Contract.new("<hex contract string>"))

# create a filesystem rooted at "meta". The filesystem will be closed
# automatically at the end of the block.
Us::FileSystem.new("meta", hs) do |fs|
    # Create a file called "foo.txt". 'minHosts' determines the minimum number
    # of hosts required to retrieve the file. As with the filesystem, the file
    # will be closed at the end of the block.
    fs.create("foo.txt", minHosts: 1) do |f|
        str = "Hello from Ruby!"
        f.write(str)
        puts "Uploaded:   " + str
    end
    # Open the file we just created and read its contents.
    fs.open("foo.txt") do |f|
        puts "Downloaded: " + f.read(16)
    end
end
