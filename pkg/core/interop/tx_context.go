package interop

import (
	"math/big"

	"github.com/ZhangTao1596/neo-go/pkg/evm/vm"
	"github.com/ethereum/go-ethereum/common"
)

func NewEVMTxContext(sender common.Address, gasPrice *big.Int) vm.TxContext {
	return vm.TxContext{
		Origin:   common.Address(sender),
		GasPrice: gasPrice,
	}
}
