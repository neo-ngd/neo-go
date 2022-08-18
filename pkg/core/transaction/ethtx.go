package transaction

import (
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

func verifySender(t *types.LegacyTx, chainId uint64) (common.Address, error) {
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
}

func marshalEthTxJSON(tx *types.LegacyTx) ([]byte, error) {
	t := &ethTxJson{
		Nonce:    hexutil.Uint64(tx.Nonce),
		GasPrice: hexutil.Big(*tx.GasPrice),
		Gas:      hexutil.Uint64(tx.Gas),
		To:       tx.To,
		Value:    hexutil.Big(*tx.Value),
		Data:     hexutil.Bytes(tx.Data),
		V:        hexutil.Big(*tx.V),
		R:        hexutil.Big(*tx.R),
		S:        hexutil.Big(*tx.S),
	}
	return json.Marshal(t)
}

func unmarshalEthTxJSON(b []byte, tx *types.LegacyTx) error {
	t := new(ethTxJson)
	err := json.Unmarshal(b, t)
	if err != nil {
		return err
	}
	tx.Nonce = uint64(t.Nonce)
	tx.GasPrice = (*big.Int)(&t.GasPrice)
	tx.Gas = uint64(t.Gas)
	tx.To = t.To
	tx.Value = (*big.Int)(&t.Value)
	tx.Data = []byte(t.Data)
	tx.V = (*big.Int)(&t.V)
	tx.R = (*big.Int)(&t.R)
	tx.S = (*big.Int)(&t.S)
	return nil
}
