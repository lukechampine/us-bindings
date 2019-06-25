require 'ffi'

module Us
    extend FFI::Library

    ffi_lib './us.so'
    attach_function :us_error, [], :string
    attach_function :us_contract_init, [:pointer, :pointer], :void
    attach_function :us_hostset_init, [:string], :pointer
    attach_function :us_hostset_add, [:pointer, :pointer], :bool
    attach_function :us_fs_init, [:string, :pointer], :pointer
    attach_function :us_fs_create, [:pointer, :string, :int], :pointer
    attach_function :us_fs_open, [:pointer, :string], :pointer
    attach_function :us_fs_close, [:pointer], :bool
    attach_function :us_file_read, [:pointer, :pointer, :int], :int
    attach_function :us_file_write, [:pointer, :pointer, :int], :int
    attach_function :us_file_close, [:pointer], :bool

    class Contract < FFI::Struct
        layout :hostKey,   :pointer,
               :id,        :pointer,
               :renterKey, :pointer

        def initialize(hex)
            bin = hex.scan(/../).map { |x| x.hex.chr }.join # decode hex
            raise 'contract hex string must be 192 bytes' unless bin.length == 96
            contract = FFI::MemoryPointer.new(:char, 96)
            Us.us_contract_init(contract, bin)
            super(contract)
        end
    end

    class HostSet < FFI::Pointer
        def add_host(contract)
            if !Us.us_hostset_add(self, contract)
                raise Us.us_error()
            end
        end

        def initialize(shard_addr)
            hs = Us.us_hostset_init(shard_addr)
            raise Us.us_error() unless hs != nil
            super(hs)
        end
    end

    class FileSystem < FFI::Pointer
        def create(name, minHosts:)
            f = File.new(Us.us_fs_create(self, name, minHosts))
            if f == nil
                raise Us.us_error()
            end
            return f unless block_given?
            yield(f)
            f.close
        end
        def open(name)
            f = File.new(Us.us_fs_open(self, name))
            if f == nil
                raise Us.us_error()
            end
            return f unless block_given?
            yield(f)
            f.close
        end
        def close()
            if Us.us_fs_close(self) == false
                raise Us.us_error()
            end
        end
        def initialize(root, hostset)
            fs = super(Us.us_fs_init(root, hostset))
            return fs unless block_given?
            yield(fs)
            fs.close
        end
    end

    class File < FFI::Pointer
        def read(n)
            str = ""
            FFI::MemoryPointer.new(:char, n) do |buf|
                if Us.us_file_read(self, buf, n) == -1
                    raise Us.us_error()
                end
                str = buf.read_string_to_null
            end
            str
        end
        def write(str)
            if Us.us_file_write(self, str, str.length) == -1
                raise Us.us_error()
            end
        end
        def close()
            if !Us.us_file_close(self)
                raise Us.us_error()
            end
        end
    end
end
