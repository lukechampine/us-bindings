package us // import "lukechampine.com/us-bindings/gomobile"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"

	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/ed25519"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter/proto"
	"lukechampine.com/us/renter/renterutil"
	"lukechampine.com/us/wallet"
)

// A Contract is a file contract formed with a Sia host.
type Contract struct {
	hostKey   hostdb.HostPublicKey
	id        types.FileContractID
	renterKey ed25519.PrivateKey
}

// NewContract parses a binary-encoded contract.
func NewContract(b []byte) (*Contract, error) {
	if len(b) != 96 {
		return nil, errors.New("invalid contract")
	}
	var pk [32]byte
	copy(pk[:], b[:32])
	c := &Contract{
		hostKey:   hostdb.HostPublicKey(types.Ed25519PublicKey(pk).String()),
		renterKey: ed25519.NewKeyFromSeed(b[64:96]),
	}
	copy(c.id[:], b[32:64])
	return c, nil
}

type ephemeralEditor struct {
	c   *Contract
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

// A HostSet is a set of Sia hosts that can be used for uploading and
// downloading.
type HostSet struct {
	set *renterutil.HostSet
}

// AddHost adds a host to the set.
func (hs *HostSet) AddHost(c *Contract) {
	var rev proto.ContractRevision
	rev.Revision.ParentID = c.id
	rev.Revision.UnlockConditions = types.UnlockConditions{
		PublicKeys: []types.SiaPublicKey{{}, c.hostKey.SiaPublicKey()},
	}
	hs.set.AddHost(&ephemeralEditor{c, rev})
}

// NewHostSet returns an empty HostSet, using the provided shard server to
// resolve public keys to network addresses.
func NewHostSet(shardSrv string) (*HostSet, error) {
	shard := renterutil.NewSHARDClient(shardSrv)
	currentHeight, err := shard.ChainHeight()
	if err != nil {
		return nil, err
	}
	return &HostSet{
		set: renterutil.NewHostSet(shard, currentHeight),
	}, nil
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

// NewFileSystem returns a filesystem rooted at root using the provided hosts.
func NewFileSystem(root string, hs *HostSet) (*FileSystem, error) {
	pfs := renterutil.NewFileSystem(root, hs.set)
	return &FileSystem{
		pfs: pfs,
	}, nil
}

type Seed struct {
	seed wallet.Seed
}

// NewSeed returns a new random wallet seed.
func NewSeed() *Seed {
	return &Seed{wallet.NewSeed()}
}

// ToPhrase encodes a seed as a 12-word mnemonic phrase.
func (s *Seed) ToPhrase() string {
	return s.seed.String()
}

// PublicKey derives the specified public key.
func (s *Seed) PublicKey(index int) string {
	return s.seed.PublicKey(uint64(index)).String()
}

// SignTransaction derives the specified key and uses it to sign the
// specified SigHash of the JSON-encoded transaction.
func (s *Seed) SignTransaction(txnJSON string, sigIndex int, keyIndex int) string {
	var txn types.Transaction
	if err := json.Unmarshal([]byte(txnJSON), &txn); err != nil {
		panic("invalid transaction: " + err.Error())
	}
	sig := s.seed.SecretKey(uint64(keyIndex)).SignHash(txn.SigHash(sigIndex, types.ASICHardforkHeight+1))
	return base64.StdEncoding.EncodeToString(sig)
}
