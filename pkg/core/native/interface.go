package native

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/neo-ngd/neo-go/pkg/core/block"
	"github.com/neo-ngd/neo-go/pkg/core/dao"
	"github.com/neo-ngd/neo-go/pkg/core/transaction"
)

type InteropContext interface {
	Log(*types.Log)
	Sender() common.Address
	Dao() *dao.Simple
	Container() *transaction.Transaction
	PersistingBlock() *block.Block
}
