package interop

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/neo-ngd/neo-go/pkg/config"
	"github.com/neo-ngd/neo-go/pkg/core/block"
	"github.com/neo-ngd/neo-go/pkg/evm/vm"
)

func NewEVMBlockContext(block *block.Block,
	bc Chain,
	protocolSettings config.ProtocolConfiguration) (bctx vm.BlockContext) {
	var coinbase common.Address
	if block.Index > 0 {
		validators, err := bc.GetCurrentValidators()
		if err != nil {
			panic(err)
		}
		if len(validators) == 0 {
			panic("no validators")
		}
		coinbase = validators[block.PrimaryIndex].Address()
	}
	random := common.BigToHash(big.NewInt(int64(block.Nonce)))
	bctx = vm.BlockContext{
		CanTransfer: func(sdb vm.StateDB, from common.Address, amount *big.Int) bool {
			// block and restrict
			return sdb.GetBalance(from).Cmp(amount) > 0
		},
		Transfer: func(sdb vm.StateDB, from common.Address, to common.Address, amount *big.Int) {
			fromAmount := big.NewInt(0).Neg(amount)
			sdb.AddBalance(from, fromAmount)
			sdb.AddBalance(to, amount)
		},
		Coinbase:    coinbase,
		GasLimit:    uint64(protocolSettings.MaxBlockGas),
		BlockNumber: big.NewInt(int64(block.Index)),
		Time:        big.NewInt(int64(block.Timestamp)),
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		Random:      &random,
	}
	return
}
