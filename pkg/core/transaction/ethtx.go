package transaction

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/neo-ngd/neo-go/pkg/io"
)

var (
	ErrInvalidChainID = errors.New("invalid chainId")
)

type EthTx struct {
	types.LegacyTx
	ChainID uint64
	Sender  common.Address
}

func NewEthTx(lt *types.LegacyTx) (*EthTx, error) {
	t := &EthTx{
		LegacyTx: *lt,
	}
	var err error
	t.ChainID, t.Sender, err = deriveSigned(lt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func NewEthTxFromBytes(data []byte) (*EthTx, error) {
	lt := new(types.LegacyTx)
	err := rlp.DecodeBytes(data, lt)
	if err != nil {
		return nil, err
	}
	return NewEthTx(lt)
}

func (t *EthTx) WithSignature(chainId uint64, sig []byte) error {
	signer := types.NewEIP155Signer(big.NewInt(int64(chainId)))
	r, s, v, err := signer.SignatureValues(types.NewTx(&t.LegacyTx), sig)
	if err != nil {
		return err
	}
	t.V, t.R, t.S = v, r, s
	return nil
}

func (t *EthTx) IsValid() error {
	if t.Value.Sign() < 0 {
		return ErrNegativeValue
	}
	return nil
}

func (t *EthTx) Verify(chainId uint64) (err error) {
	if t.ChainID == 0 && t.Sender == (common.Address{}) {
		t.ChainID, t.Sender, err = deriveSigned(&t.LegacyTx)
		if err != nil {
			return
		}
	}
	if t.ChainID != chainId {
		return ErrInvalidChainID
	}
	return nil
}

func (t *EthTx) EncodeBinary(w *io.BinWriter) {
	err := rlp.Encode(w, t.LegacyTx)
	w.Err = err
}

func (t *EthTx) DecodeBinary(r *io.BinReader) {
	var err error
	defer func() {
		r.Err = err
	}()
	inner := new(types.LegacyTx)
	err = rlp.Decode(r, inner)
	if err != nil {
		return
	}
	t.ChainID, t.Sender, err = deriveSigned(inner)
	if err != nil {
		return
	}
	t.LegacyTx = *inner
}

func (t *EthTx) MarshalJSON() ([]byte, error) {
	tx := &ethTxJson{
		Nonce:    hexutil.Uint64(t.Nonce),
		GasPrice: hexutil.Big(*t.GasPrice),
		Gas:      hexutil.Uint64(t.Gas),
		To:       t.To,
		Value:    hexutil.Big(*t.Value),
		Data:     hexutil.Bytes(t.Data),
		V:        hexutil.Big(*t.V),
		R:        hexutil.Big(*t.R),
		S:        hexutil.Big(*t.S),
		ChainID:  hexutil.Uint(t.ChainID),
		Sender:   t.Sender,
	}
	return json.Marshal(tx)
}

func (t *EthTx) UnmarshalJSON(data []byte) error {
	tx := new(ethTxJson)
	err := json.Unmarshal(data, tx)
	if err != nil {
		return err
	}
	t.Nonce = uint64(tx.Nonce)
	t.GasPrice = (*big.Int)(&tx.GasPrice)
	t.Gas = uint64(t.Gas)
	t.To = tx.To
	t.Value = (*big.Int)(&tx.Value)
	t.Data = []byte(tx.Data)
	t.V = (*big.Int)(&tx.V)
	t.R = (*big.Int)(&tx.R)
	t.S = (*big.Int)(&tx.S)
	t.ChainID = uint64(tx.ChainID)
	t.Sender = tx.Sender
	return nil
}

func deriveSigned(t *types.LegacyTx) (chainId uint64, sender common.Address, err error) {
	bigChainId := deriveChainId(t.V)
	if !bigChainId.IsUint64() {
		err = errors.New("ChainId is not uint64")
		return
	}
	chainId = bigChainId.Uint64()
	sender, err = deriveSender(t, chainId)
	if err != nil {
		return
	}
	return
}

func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35))
	return v.Div(v, big.NewInt(2))
}

func deriveSender(t *types.LegacyTx, chainId uint64) (common.Address, error) {
	signer := types.NewEIP155Signer(big.NewInt(int64(chainId)))
	return signer.Sender(types.NewTx(t))
}

type ethTxJson struct {
	Nonce    hexutil.Uint64  `json:"nonce"`
	GasPrice hexutil.Big     `json:"gasPrice"`
	Gas      hexutil.Uint64  `json:"gas"`
	To       *common.Address `json:"to,omitempty"`
	Value    hexutil.Big     `json:"value"`
	Data     hexutil.Bytes   `json:"data"`
	V        hexutil.Big     `json:"V"`
	R        hexutil.Big     `json:"R"`
	S        hexutil.Big     `json:"S"`
	ChainID  hexutil.Uint    `json:"chainId"`
	Sender   common.Address  `json:"sender"`
}
