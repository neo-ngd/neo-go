package block

import (
	"encoding/json"
	"errors"
	"math"

	"github.com/Workiva/go-datastructures/queue"
	"github.com/nspcc-dev/neo-go/pkg/config/netmode"
	"github.com/nspcc-dev/neo-go/pkg/core/transaction"
	"github.com/nspcc-dev/neo-go/pkg/crypto/hash"
	"github.com/nspcc-dev/neo-go/pkg/io"
	"github.com/nspcc-dev/neo-go/pkg/util"
)

const (
	// MaxContentsPerBlock is the maximum number of contents (transactions + consensus data) per block.
	MaxContentsPerBlock = math.MaxUint16
	// MaxTransactionsPerBlock is the maximum number of transactions per block.
	MaxTransactionsPerBlock = MaxContentsPerBlock
)

// ErrMaxContentsPerBlock is returned when the maximum number of contents per block is reached.
var ErrMaxContentsPerBlock = errors.New("the number of contents exceeds the maximum number of contents per block")

// Block represents one block in the chain.
type Block struct {
	// The base of the block.
	Base

	// Transaction list.
	Transactions []*transaction.Transaction

	// True if this block is created from trimmed data.
	Trimmed bool
}

// auxBlockOut is used for JSON i/o.
type auxBlockOut struct {
	Transactions []*transaction.Transaction `json:"tx"`
}

// auxBlockIn is used for JSON i/o.
type auxBlockIn struct {
	Transactions []json.RawMessage `json:"tx"`
}

// Header returns the Header of the Block.
func (b *Block) Header() *Header {
	return &Header{
		Base: b.Base,
	}
}

// ComputeMerkleRoot computes Merkle tree root hash based on actual block's data.
func (b *Block) ComputeMerkleRoot() util.Uint256 {
	hashes := make([]util.Uint256, len(b.Transactions))
	for i, tx := range b.Transactions {
		hashes[i] = tx.Hash()
	}

	return hash.CalcMerkleRoot(hashes)
}

// RebuildMerkleRoot rebuilds the merkleroot of the block.
func (b *Block) RebuildMerkleRoot() {
	b.MerkleRoot = b.ComputeMerkleRoot()
}

// NewBlockFromTrimmedBytes returns a new block from trimmed data.
// This is commonly used to create a block from stored data.
// Blocks created from trimmed data will have their Trimmed field
// set to true.
func NewBlockFromTrimmedBytes(network netmode.Magic, stateRootEnabled bool, b []byte) (*Block, error) {
	block := &Block{
		Base: Base{
			Network:          network,
			StateRootEnabled: stateRootEnabled,
		},
		Trimmed: true,
	}

	br := io.NewBinReaderFromBuf(b)
	block.decodeHashableFields(br)

	_ = br.ReadB()

	block.Script.DecodeBinary(br)

	lenHashes := br.ReadVarUint()
	if lenHashes > MaxContentsPerBlock {
		return nil, ErrMaxContentsPerBlock
	}
	if lenHashes > 0 {
		block.Transactions = make([]*transaction.Transaction, lenHashes)
		for i := 0; i < int(lenHashes); i++ {
			var hash util.Uint256
			hash.DecodeBinary(br)
			block.Transactions[i] = transaction.NewTrimmedTX(hash)
		}
	}

	return block, br.Err
}

// New creates a new blank block tied to the specific network.
func New(network netmode.Magic, stateRootEnabled bool) *Block {
	return &Block{
		Base: Base{
			Network:          network,
			StateRootEnabled: stateRootEnabled,
		},
	}
}

// Trim returns a subset of the block data to save up space
// in storage.
// Notice that only the hashes of the transactions are stored.
func (b *Block) Trim() ([]byte, error) {
	buf := io.NewBufBinWriter()
	b.encodeHashableFields(buf.BinWriter)
	buf.WriteB(1)
	b.Script.EncodeBinary(buf.BinWriter)

	buf.WriteVarUint(uint64(len(b.Transactions)))
	for _, tx := range b.Transactions {
		h := tx.Hash()
		h.EncodeBinary(buf.BinWriter)
	}

	if buf.Err != nil {
		return nil, buf.Err
	}

	return buf.Bytes(), nil
}

// DecodeBinary decodes the block from the given BinReader, implementing
// Serializable interface.
func (b *Block) DecodeBinary(br *io.BinReader) {
	b.Base.DecodeBinary(br)
	contentsCount := br.ReadVarUint()
	if contentsCount > MaxContentsPerBlock {
		br.Err = ErrMaxContentsPerBlock
		return
	}
	txes := make([]*transaction.Transaction, contentsCount)
	for i := 0; i < int(contentsCount); i++ {
		tx := &transaction.Transaction{Network: b.Network}
		tx.DecodeBinary(br)
		txes[i] = tx
	}
	b.Transactions = txes
	if br.Err != nil {
		return
	}
}

// EncodeBinary encodes the block to the given BinWriter, implementing
// Serializable interface.
func (b *Block) EncodeBinary(bw *io.BinWriter) {
	b.Base.EncodeBinary(bw)
	bw.WriteVarUint(uint64(len(b.Transactions)))
	for i := 0; i < len(b.Transactions); i++ {
		b.Transactions[i].EncodeBinary(bw)
	}
}

// Compare implements the queue Item interface.
func (b *Block) Compare(item queue.Item) int {
	other := item.(*Block)
	switch {
	case b.Index > other.Index:
		return 1
	case b.Index == other.Index:
		return 0
	default:
		return -1
	}
}

// MarshalJSON implements json.Marshaler interface.
func (b Block) MarshalJSON() ([]byte, error) {
	auxb, err := json.Marshal(auxBlockOut{
		Transactions: b.Transactions,
	})
	if err != nil {
		return nil, err
	}
	baseBytes, err := json.Marshal(b.Base)
	if err != nil {
		return nil, err
	}

	// Stitch them together.
	if baseBytes[len(baseBytes)-1] != '}' || auxb[0] != '{' {
		return nil, errors.New("can't merge internal jsons")
	}
	baseBytes[len(baseBytes)-1] = ','
	baseBytes = append(baseBytes, auxb[1:]...)
	return baseBytes, nil
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (b *Block) UnmarshalJSON(data []byte) error {
	// As Base and auxb are at the same level in json,
	// do unmarshalling separately for both structs.
	auxb := new(auxBlockIn)
	err := json.Unmarshal(data, auxb)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &b.Base)
	if err != nil {
		return err
	}
	if len(auxb.Transactions) != 0 {
		b.Transactions = make([]*transaction.Transaction, 0, len(auxb.Transactions))
		for _, txBytes := range auxb.Transactions {
			tx := &transaction.Transaction{Network: b.Network}
			err = tx.UnmarshalJSON(txBytes)
			if err != nil {
				return err
			}
			b.Transactions = append(b.Transactions, tx)
		}
	}
	return nil
}
