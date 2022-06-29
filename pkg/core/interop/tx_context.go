package interop

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/neo-ngd/neo-go/pkg/evm/vm"
)

func NewEVMTxContext(sender common.Address, gasPrice *big.Int) vm.TxContext {
	return vm.TxContext{
		Origin:   common.Address(sender),
		GasPrice: gasPrice,
	}
}
