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
	// Block wrapper used for the representation of
	// block.Block / block.Base on the RPC Server.
	Block struct {
		block.Block
		BlockMetadata
	}

	// BlockMetadata is an additional metadata added to standard
	// block.Block.
	BlockMetadata struct {
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
func NewBlock(b *block.Block, receipt *types.Receipt, sr *state.MPTRoot, chain LedgerAux) Block {
	res := Block{
		Block: *b,
		BlockMetadata: BlockMetadata{
			Size:      hexutil.Uint(io.GetVarSize(b)),
			StateRoot: sr.Root,
			GasUsed:   hexutil.Uint64(receipt.GasUsed),
		},
	}

	_ = chain.GetHeaderHash(int(b.Index) + 1)

	return res
}

// MarshalJSON implements json.Marshaler interface.
func (b Block) MarshalJSON() ([]byte, error) {
	output, err := json.Marshal(b.BlockMetadata)
	if err != nil {
		return nil, err
	}
	baseBytes, err := json.Marshal(b.Block)
	if err != nil {
		return nil, err
	}

	// We have to keep both "fields" at the same level in json in order to
	// match C# API, so there's no way to marshall Block correctly with
	// standard json.Marshaller tool.
	if output[len(output)-1] != '}' || baseBytes[0] != '{' {
		return nil, errors.New("can't merge internal jsons")
	}
	output[len(output)-1] = ','
	output = append(output, baseBytes[1:]...)
	return output, nil
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (b *Block) UnmarshalJSON(data []byte) error {
	// As block.Block and BlockMetadata are at the same level in json,
	// do unmarshalling separately for both structs.
	meta := new(BlockMetadata)
	err := json.Unmarshal(data, meta)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &b.Block)
	if err != nil {
		return err
	}
	b.BlockMetadata = *meta
	return nil
}
