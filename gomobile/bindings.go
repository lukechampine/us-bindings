package us // import "lukechampine.com/us-bindings/gomobile"

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	"gitlab.com/NebulousLabs/Sia/crypto"
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

// SeedFromPhrase returns the seed derived from the supplied phrase.
func SeedFromPhrase(phrase string) (*Seed, error) {
	s, err := wallet.SeedFromPhrase(phrase)
	return &Seed{s}, err
}

func parseAddr(addr string) types.UnlockHash {
	var uh types.UnlockHash
	if err := uh.LoadString(addr); err != nil {
		panic(err)
	}
	return uh
}

func parseAmount(value string) types.Currency {
	var c types.Currency
	if _, err := fmt.Sscan(value, &c); err != nil {
		panic(err)
	}
	return c
}

type Transaction struct {
	txn        types.Transaction
	feePerByte types.Currency
	inputSum   types.Currency
	outputSum  types.Currency
	sigs       map[crypto.Hash]uint64
}

func NewTransaction(feePerByte string) *Transaction {
	return &Transaction{
		feePerByte: parseAmount(feePerByte),
		sigs:       make(map[crypto.Hash]uint64),
	}
}

func (t *Transaction) AddOutput(addr string, amount string) {
	t.txn.SiacoinOutputs = append(t.txn.SiacoinOutputs, types.SiacoinOutput{
		UnlockHash: parseAddr(addr),
		Value:      parseAmount(amount),
	})
	t.outputSum = t.outputSum.Add(parseAmount(amount))
}

func (t *Transaction) calcFee() types.Currency {
	size := t.txn.MarshalSiaSize() + 100*len(t.txn.SiacoinInputs)
	return t.feePerByte.Mul64(uint64(size))
}

func (t *Transaction) AddInput(id string, value string, publicKey string, keyIndex int) bool {
	var scoid crypto.Hash
	if err := scoid.LoadString(id); err != nil {
		panic(err)
	}
	var pk types.SiaPublicKey
	if pk.LoadString(publicKey); pk.Algorithm != types.SignatureEd25519 {
		panic("invalid public key")
	}
	t.txn.SiacoinInputs = append(t.txn.SiacoinInputs, types.SiacoinInput{
		ParentID:         types.SiacoinOutputID(scoid),
		UnlockConditions: wallet.StandardUnlockConditions(pk),
	})
	t.sigs[crypto.Hash(scoid)] = uint64(keyIndex)

	t.inputSum = t.inputSum.Add(parseAmount(value))
	return t.inputSum.Cmp(t.outputSum.Add(t.calcFee())) >= 0
}

func (t *Transaction) Finalize(changeAddr string) {
	if t.inputSum.Cmp(t.outputSum) < 0 {
		panic("insufficient inputs")
	}
	fee := t.calcFee()
	change := t.inputSum.Sub(t.outputSum)
	if change.Cmp(fee) < 0 {
		fee = change
	}
	change = change.Sub(fee)
	t.txn.MinerFees = []types.Currency{fee}
	if !change.IsZero() {
		t.AddOutput(changeAddr, change.String())
	}
}

func (t *Transaction) Sign(s *Seed) {
	for id, keyIndex := range t.sigs {
		wallet.AppendTransactionSignature(&t.txn, wallet.StandardTransactionSignature(id), s.seed.SecretKey(keyIndex))
	}
}

func (t *Transaction) AsJSON() string {
	js, _ := json.Marshal(t.txn)
	return string(js)
}

// ValidateAddress returns true if addr is a valid Sia address.
func ValidateAddress(addr string) bool {
	return new(types.UnlockHash).LoadString(addr) == nil
}
