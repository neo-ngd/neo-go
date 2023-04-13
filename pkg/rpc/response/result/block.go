package result

import (
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/neo-ngd/neo-go/pkg/core/block"
	"github.com/neo-ngd/neo-go/pkg/core/state"
	"github.com/neo-ngd/neo-go/pkg/io"
)

type (
	LedgerAux interface {
		BlockHeight() uint32
		GetHeaderHash(int) common.Hash
	}

	transactionsObj struct {
		Transactions []interface{} `json:"transactions"`
	}

	Block struct {
		block.Header
		BlockMetadata
		transactionsObj
	}

	// BlockMetadata is an additional metadata added to standard
	// block.Block.
	BlockMetadata struct {
		Miner           common.Address `json:"miner"`
		Size            hexutil.Uint   `json:"size"`
		Sha3Uncles      common.Hash    `json:"sha3Uncles"`
		LogsBloom       types.Bloom    `json:"logsBloom"`
		StateRoot       common.Hash    `json:"stateRoot"`
		ReceiptsRoot    common.Hash    `json:"receiptsRoot"`
		Difficulty      hexutil.Uint   `json:"difficulty"`
		TotalDifficulty hexutil.Uint   `json:"totalDifficulty"`
		ExtraData       hexutil.Bytes  `json:"extraData"`
		GasLimit        hexutil.Big    `json:"gasLimit"`
		GasUsed         hexutil.Uint64 `json:"gasUsed"`
		Uncles          []common.Hash  `json:"uncles"`
		BaseFeePerGas   hexutil.Uint64 `json:"baseFeePerGas"`
	}
)

// NewBlock creates a new Block wrapper.
func NewBlock(b *block.Block, receipt *types.Receipt, sr *state.MPTRoot, miner common.Address) Block {
	res := Block{
		Header: b.Header,
		BlockMetadata: BlockMetadata{
			Miner:     miner,
			Size:      hexutil.Uint(io.GetVarSize(b)),
			StateRoot: sr.Root,
			GasUsed:   hexutil.Uint64(receipt.GasUsed),
			Uncles:    []common.Hash{},
		},
		transactionsObj: transactionsObj{
			Transactions: make([]interface{}, len(b.Transactions)),
		},
	}
	if b.Trimmed {
		for i, t := range b.Transactions {
			res.Transactions[i] = t.Hash()
		}
	} else {
		for i, t := range b.Transactions {
			res.Transactions[i] = NewTransactionOutputRaw(t, &b.Header, &types.Receipt{TransactionIndex: uint(i)})
		}
	}
	return res
}

// MarshalJSON implements json.Marshaler interface.
func (b Block) MarshalJSON() ([]byte, error) {
	output, err := json.Marshal(b.BlockMetadata)
	if err != nil {
		return nil, err
	}
	baseBytes, err := json.Marshal(b.Header)
	if err != nil {
		return nil, err
	}
	txBytes, err := json.Marshal(b.transactionsObj)
	if err != nil {
		return nil, err
	}
	if output[len(output)-1] != '}' || baseBytes[0] != '{' ||
		baseBytes[len(baseBytes)-1] != '}' || txBytes[0] != '{' {
		return nil, errors.New("can't merge internal jsons")
	}
	output[len(output)-1] = ','
	output = append(output, baseBytes[1:]...)
	output[len(output)-1] = ','
	output = append(output, txBytes[1:]...)
	return output, nil
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (b *Block) UnmarshalJSON(data []byte) error {
	meta := new(BlockMetadata)
	err := json.Unmarshal(data, meta)
	if err != nil {
		return err
	}
	txes := new(transactionsObj)
	err = json.Unmarshal(data, txes)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &b.Header)
	if err != nil {
		return err
	}
	b.BlockMetadata = *meta
	b.transactionsObj = *txes
	return nil
}
