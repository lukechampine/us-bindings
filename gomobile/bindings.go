package us

import (
	"errors"
	"io/ioutil"

	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renter/renterutil"
)

// A Contract is a file contract formed with a Sia host.
type Contract struct {
	hostKey   hostdb.HostPublicKey
	id        types.FileContractID
	renterKey ed25519.PrivateKey
}

// DecodeContract parses a binary-encoded contract.
func DecodeContract(b []byte) (Contract, error) {
	if len(b) != 96 {
		return Contract{}, errors.New("invalid contract")
	}
	var pk [32]byte
	copy(pk[:], b[:32])
	var c Contract
	c.hostKey = hostdb.HostPublicKey(types.Ed25519PublicKey(pk).String())
	copy(c.id[:], b[32:64])
	c.renterKey = ed25519.NewKeyFromSeed(b[64:96])
	return c, nil
}

// A FileSystem supports I/O operations on Sia files.
type FileSystem struct {
	pfs *renterutil.PseudoFS
}

// Upload creates a file with the given name, data, and redundancy.
func (fs *FileSystem) Upload(name string, data []byte, minHosts int) error {
	pf, err := fs.pfs.Create(name, minHosts)
	if err != nil {
		return err
	}
	if _, err := pf.Write(data); err != nil {
		return err
	}
	if err := pf.Close(); err != nil {
		return err
	}
	return nil
}

// Download retrieves the contents of the named file.
func (fs *FileSystem) Download(name string) ([]byte, error) {
	pf, err := fs.pfs.Open(name)
	if err != nil {
		return nil, err
	}
	defer pf.Close()
	return ioutil.ReadAll(pf)
}

// Close shuts down the filesystem, flushing any uncommitted writes.
func (fs *FileSystem) Close() error {
	return fs.pfs.Close()
}

// NewFileSystem returns a filesystem rooted at root, using the provided shard
// server and contract set.
func NewFileSystem(root string, shardSrv string, contracts []Contract) (*FileSystem, error) {
	shard := renterutil.NewSHARDClient(shardSrv)
	currentHeight, err := shard.ChainHeight()
	if err != nil {
		return nil, err
	}
	hs := renterutil.NewHostSet(shard, currentHeight)
	for _, c := range contracts {
		var rev proto.ContractRevision
		rev.Revision.ParentID = c.id
		rev.Revision.UnlockConditions = types.UnlockConditions{
			PublicKeys: []types.SiaPublicKey{{}, c.hostKey.SiaPublicKey()},
		}
		hs.AddHost(&ephemeralEditor{c, rev})
	}
	pfs := renterutil.NewFileSystem(root, hs)
	return &FileSystem{
		pfs: pfs,
	}, nil
}

type ephemeralEditor struct {
	c   Contract
	rev proto.ContractRevision
}

func (e *ephemeralEditor) Revision() proto.ContractRevision {
	return e.rev
}

func (e *ephemeralEditor) SetRevision(rev proto.ContractRevision) error {
	e.rev = rev
	return nil
}

func (e *ephemeralEditor) Key() ed25519.PrivateKey {
	return e.c.renterKey
}
