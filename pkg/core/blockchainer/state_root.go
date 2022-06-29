package blockchainer

import (
	"github.com/ZhangTao1596/neo-go/pkg/core/state"
	"github.com/ZhangTao1596/neo-go/pkg/core/storage"
	"github.com/ethereum/go-ethereum/common"
)

// StateRoot represents local state root module.
type StateRoot interface {
	CurrentLocalHeight() uint32
	CurrentLocalStateRoot() common.Hash
	CurrentValidatedHeight() uint32
	FindStates(root common.Hash, prefix, start []byte, max int) ([]storage.KeyValue, error)
	GetState(root common.Hash, key []byte) ([]byte, error)
	GetStateProof(root common.Hash, key []byte) ([][]byte, error)
	GetStateRoot(height uint32) (*state.MPTRoot, error)
}
