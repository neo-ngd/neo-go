package result

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

type FeeHistory struct {
	OldestBlock   hexutil.Big   `json:"oldestBlock"`
	BaseFeePerGas []hexutil.Big `json:"baseFeePerGas"`
	GasUsedRatio  []float32     `json:"gasUsedRatio"`
	Reward        []hexutil.Big `json:"reward"`
}

func NewFeeHistory(receipts types.Receipts, gasPrice *big.Int) (*FeeHistory, error) {
	fh := &FeeHistory{
		BaseFeePerGas: make([]hexutil.Big, receipts.Len()),
		GasUsedRatio:  make([]float32, receipts.Len()),
		Reward:        make([]hexutil.Big, receipts.Len()),
	}
	if receipts.Len() == 0 {
		return fh, nil
	}
	fh.OldestBlock = hexutil.Big(*receipts[receipts.Len()-1].BlockNumber)
	for i, r := range receipts {
		fh.BaseFeePerGas[i] = hexutil.Big(*gasPrice)
		if r.GasUsed != 0 {
			fh.GasUsedRatio[i] = float32(r.CumulativeGasUsed) / float32(r.GasUsed)
		} else {
			fh.GasUsedRatio[i] = 0
		}
		fh.Reward[i] = hexutil.Big(*big.NewInt(0))
	}
	return fh, nil
}
