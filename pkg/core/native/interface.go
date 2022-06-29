package native

import (
	"github.com/ZhangTao1596/neo-go/pkg/core/block"
	"github.com/ZhangTao1596/neo-go/pkg/core/dao"
	"github.com/ethereum/go-ethereum/common"
)

type InteropContext interface {
	Sender() common.Address
	Natives() *Contracts
	Dao() *dao.Simple
	PersistingBlock() *block.Block
}
