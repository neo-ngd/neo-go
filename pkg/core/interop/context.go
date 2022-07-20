package interop

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/neo-ngd/neo-go/pkg/config"
	"github.com/neo-ngd/neo-go/pkg/core/block"
	"github.com/neo-ngd/neo-go/pkg/core/dao"
	"github.com/neo-ngd/neo-go/pkg/core/native"
	"github.com/neo-ngd/neo-go/pkg/core/statedb"
	"github.com/neo-ngd/neo-go/pkg/core/transaction"
	"github.com/neo-ngd/neo-go/pkg/crypto/keys"
	"github.com/neo-ngd/neo-go/pkg/evm"
	"github.com/neo-ngd/neo-go/pkg/evm/vm"
)

type NativeContract interface {
	RequiredGas(ic native.InteropContext, input []byte) uint64
	Run(ic native.InteropContext, input []byte) ([]byte, error)
}

type Chain interface {
	GetConfig() config.ProtocolConfiguration
	Contracts() *native.Contracts
	GetCurrentValidators() ([]*keys.PublicKey, error)
}

// Context represents context in which interops are executed.
type Context struct {
	Chain  Chain
	Block  *block.Block
	Tx     *transaction.Transaction
	VM     *vm.EVM
	bctx   vm.BlockContext
	sdb    *statedb.StateDB
	caller common.Address
}

func NewContext(block *block.Block, tx *transaction.Transaction, sdb *statedb.StateDB, chain Chain) (*Context, error) {
	ctx := &Context{
		Chain:  chain,
		Block:  block,
		Tx:     tx,
		sdb:    sdb,
		caller: tx.From(),
	}
	ctx.bctx = NewEVMBlockContext(block, chain, chain.GetConfig())
	txContext := NewEVMTxContext(tx.From(), big.NewInt(1))
	ctx.VM = evm.NewEVM(ctx.bctx,
		txContext, sdb, chain.GetConfig(),
		map[common.Address]vm.NativeContract{
			native.DesignationAddress: nativeWrapper{
				nativeContract: chain.Contracts().Designate,
				ic:             ctx,
			},
			native.PolicyAddress: nativeWrapper{
				nativeContract: chain.Contracts().Policy,
				ic:             ctx,
			},
			native.GASAddress: nativeWrapper{
				nativeContract: chain.Contracts().GAS,
				ic:             ctx,
			},
			native.ManagementAddress: nativeWrapper{
				nativeContract: chain.Contracts().Management,
				ic:             ctx,
			},
		})
	return ctx, nil
}

func (c Context) Sender() common.Address {
	return c.caller
}

func (c Context) Natives() *native.Contracts {
	return c.Chain.Contracts()
}

func (c Context) Dao() *dao.Simple {
	return c.sdb.CurrentStore().Simple
}

func (c Context) PersistingBlock() *block.Block {
	return c.Block
}

func (c Context) Coinbase() common.Address {
	return c.bctx.Coinbase
}

func (c Context) Address() common.Address {
	return c.Tx.From()
}
