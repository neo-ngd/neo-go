package native

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/neo-ngd/neo-go/pkg/core/block"
	"github.com/neo-ngd/neo-go/pkg/core/dao"
)

type InteropContext interface {
	Log(*types.Log)
	Sender() common.Address
	Natives() *Contracts
	Dao() *dao.Simple
	PersistingBlock() *block.Block
}
