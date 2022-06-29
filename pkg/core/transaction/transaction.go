package transaction

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"sync/atomic"

	"github.com/ZhangTao1596/neo-go/pkg/crypto/hash"
	"github.com/ZhangTao1596/neo-go/pkg/io"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	EthLegacyTxType     = byte(0)
	NeoTxType           = byte(1)
	SignatureLength     = 64
	MaxScriptLength     = math.MaxUint16
	MaxTransactionSize  = 102400
	EthLegacyBaseLength = 100
)

var (
	ErrUnsupportType = errors.New("unsupport tx type")
)

type Transaction struct {
	Type     byte
	LegacyTx *types.LegacyTx
	NeoTx    *NeoTx

	Trimmed bool
	EthSize int
	EthFrom common.Address
	hash    atomic.Value
	size    atomic.Value
}

func NewTrimmedTX(hash common.Hash) *Transaction {
	t := &Transaction{
		Trimmed: true,
	}
	t.hash.Store(hash)
	return t
}

func NewTx(t interface{}) *Transaction {
	tx := &Transaction{}
	switch v := t.(type) {
	case *NeoTx:
		tx.Type = NeoTxType
		tx.NeoTx = v
	case *types.LegacyTx:
		tx.Type = EthLegacyTxType
		tx.LegacyTx = v
	default:
		panic("unsupport tx")
	}
	return tx
}

func NewTransactionFromBytes(b []byte) (*Transaction, error) {
	tx := &Transaction{}
	err := io.FromByteArray(tx, b)
	if err != nil {
		return nil, err
	}
	return tx, err
}

func (t *Transaction) Nonce() uint64 {
	switch t.Type {
	case EthLegacyTxType:
		return t.LegacyTx.Nonce
	case NeoTxType:
		return t.NeoTx.Nonce
	default:
		panic(ErrUnsupportType)
	}
}

func (t *Transaction) To() *common.Address {
	switch t.Type {
	case EthLegacyTxType:
		return t.LegacyTx.To
	case NeoTxType:
		return t.NeoTx.To
	default:
		panic(ErrUnsupportType)
	}
}

func (t *Transaction) Gas() uint64 {
	switch t.Type {
	case EthLegacyTxType:
		return t.LegacyTx.Gas
	case NeoTxType:
		return t.NeoTx.Gas
	default:
		panic(ErrUnsupportType)
	}
}

func (t *Transaction) GasPrice() *big.Int {
	switch t.Type {
	case EthLegacyTxType:
		return t.LegacyTx.GasPrice
	case NeoTxType:
		return t.NeoTx.GasPrice
	default:
		panic(ErrUnsupportType)
	}
}

func (t Transaction) Cost() *big.Int {
	cost := big.NewInt(0).Mul(big.NewInt(int64(t.Gas())), t.GasPrice())
	return big.NewInt(0).Add(t.Value(), cost)
}

func (t *Transaction) Value() *big.Int {
	switch t.Type {
	case EthLegacyTxType:
		return t.LegacyTx.Value
	case NeoTxType:
		return t.NeoTx.Value
	default:
		panic(ErrUnsupportType)
	}
}

func (t *Transaction) Data() []byte {
	switch t.Type {
	case EthLegacyTxType:
		return t.LegacyTx.Data
	case NeoTxType:
		return t.NeoTx.Data
	default:
		panic(ErrUnsupportType)
	}
}

func (t *Transaction) Size() int {
	if size := t.size.Load(); size != nil {
		return size.(int)
	}
	var size int
	switch t.Type {
	case EthLegacyTxType:
		size = RlpSize(t.LegacyTx)
	case NeoTxType:
		size = t.NeoTx.Size()
	default:
		panic(ErrUnsupportType)
	}
	t.size.Store(size)
	return size
}

func (t *Transaction) From() common.Address {
	switch t.Type {
	case EthLegacyTxType:
		return t.EthFrom
	case NeoTxType:
		return t.NeoTx.From
	default:
		panic(ErrUnsupportType)
	}
}

func (t *Transaction) Hash() common.Hash {
	if hash := t.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	var h common.Hash
	if t.Type == EthLegacyTxType {
		h = hash.RlpHash(t.LegacyTx)
	} else {
		h = t.NeoTx.Hash()
	}
	t.hash.Store(h)
	return h
}

func (t Transaction) SignHash(chainId uint64) common.Hash {
	if t.Type == EthLegacyTxType {
		signer := types.NewEIP2930Signer(big.NewInt(int64(chainId)))
		return signer.Hash(types.NewTx(t.LegacyTx))
	} else {
		return t.Hash()
	}
}

func (t *Transaction) Bytes() ([]byte, error) {
	return io.ToByteArray(t)
}

func (t Transaction) FeePerByte() uint64 {
	return t.Gas() / uint64(t.Size())
}

func (t *Transaction) EncodeBinary(w *io.BinWriter) {
	w.WriteB(t.Type)
	switch t.Type {
	case EthLegacyTxType:
		b, err := rlp.EncodeToBytes(t.LegacyTx)
		if err != nil {
			w.Err = err
			return
		}
		w.WriteVarBytes(b)
	case NeoTxType:
		t.NeoTx.EncodeBinary(w)
	default:
		w.Err = ErrUnsupportType
	}
}

func (t *Transaction) DecodeBinary(r *io.BinReader) {
	t.Type = r.ReadB()
	switch t.Type {
	case EthLegacyTxType:
		inner := new(types.LegacyTx)
		b := r.ReadVarBytes()
		err := rlp.DecodeBytes(b, inner)
		r.Err = err
		t.LegacyTx = inner
	case NeoTxType:
		inner := new(NeoTx)
		inner.DecodeBinary(r)
		t.NeoTx = inner
	default:
		r.Err = ErrUnsupportType
	}
}

func (t *Transaction) Verify(chainId uint64) error {
	switch t.Type {
	case EthLegacyTxType:
		signer := types.NewEIP2930Signer(big.NewInt(int64(chainId)))
		from, err := signer.Sender(types.NewTx(t.LegacyTx))
		if err != nil {
			return err
		}
		t.EthFrom = from
		return nil
	case NeoTxType:
		return t.NeoTx.Witness.VerifyHashable(chainId, t.NeoTx)
	default:
		return ErrUnsupportType
	}
}

func (t *Transaction) WithSignature(chainId uint64, sig []byte) error {
	switch t.Type {
	case EthLegacyTxType:
		signer := types.NewEIP2930Signer(big.NewInt(int64(chainId)))
		r, s, v, err := signer.SignatureValues(types.NewTx(t.LegacyTx), sig)
		if err != nil {
			return err
		}
		t.LegacyTx.V, t.LegacyTx.R, t.LegacyTx.S = v, r, s
		return nil
	default:
		return ErrUnsupportType
	}
}

func (t *Transaction) WithWitness(witness Witness) error {
	if t.Type != NeoTxType {
		return ErrUnsupportType
	}
	t.NeoTx.Witness = witness
	return nil
}

func (t *Transaction) UnmarshalJSON(b []byte) error {
	if t.Type == EthLegacyTxType {
		tx := new(types.LegacyTx)
		err := unmarshalJSON(b, tx)
		if err != nil {
			return err
		}
		t.LegacyTx = tx
		return nil
	} else if t.Type == NeoTxType {
		tx := new(NeoTx)
		err := json.Unmarshal(b, tx)
		if err != nil {
			return err
		}
		t.NeoTx = tx
		return nil
	} else {
		return ErrUnsupportType
	}
}

func (t *Transaction) MarshalJSON() ([]byte, error) {
	if t.Trimmed {
		return json.Marshal(t.Hash())
	}
	switch t.Type {
	case EthLegacyTxType:
		return marshlJSON(t.LegacyTx)
	case NeoTxType:
		return json.Marshal(t.NeoTx)
	default:
		return nil, ErrUnsupportType
	}
}

var (
	ErrInvalidTxType = errors.New("invalid tx type")
)

func (t Transaction) IsValid() error {
	switch t.Type {
	case EthLegacyTxType:
		if t.LegacyTx.Value.Sign() < 0 {
			return ErrNegativeValue
		}
		return nil
	case NeoTxType:
		return t.NeoTx.isValid()
	default:
		return ErrInvalidTxType
	}
}
