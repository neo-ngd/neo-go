package native

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/neo-ngd/neo-go/pkg/config"
	"github.com/neo-ngd/neo-go/pkg/core/dao"
	"github.com/neo-ngd/neo-go/pkg/core/storage"
	"github.com/neo-ngd/neo-go/pkg/crypto/hash"
	"github.com/neo-ngd/neo-go/pkg/crypto/keys"
	"github.com/stretchr/testify/assert"
)

func TestSetGasPrice(t *testing.T) {
	pubs, _ := keys.NewPublicKeysFromStrings([]string{
		"023c4d39a3fd2150407a9d4654430cdce0464eccaaf739eea79d63e2862f989ee6",
	})
	dao := dao.NewSimple(storage.NewMemoryStore())
	des := NewDesignate(config.ProtocolConfiguration{
		StandbyValidators: pubs,
	})
	p := NewPolicy(&Contracts{
		Designate: des,
	})
	ic := interopContext{
		D: dao,
		L: make([]*types.Log, 1),
	}
	err := des.ContractCall_initialize(ic)
	assert.NoError(t, err)
	err = p.ContractCall_initialize(ic)
	assert.NoError(t, err)
	ic.S, _ = des.GetConsensusAddress(dao, 1)
	fn, ok := p.Abi.Methods["setGasPrice"]
	assert.True(t, ok)
	input := append(fn.ID, []byte{0}...)
	_, err = p.Run(ic, input)
	assert.NotNil(t, err)

	input, err = p.Abi.Pack("setGasPrice", uint64(1))
	assert.NoError(t, err)
	_, err = p.Run(ic, input)
	assert.NoError(t, err)

	gasPrice := p.GetGasPrice(dao)
	assert.Equal(t, uint64(1), gasPrice.Uint64())
}

func TestBlockAccount(t *testing.T) {
	pubs, _ := keys.NewPublicKeysFromStrings([]string{
		"023c4d39a3fd2150407a9d4654430cdce0464eccaaf739eea79d63e2862f989ee6",
	})
	dao := dao.NewSimple(storage.NewMemoryStore())
	des := NewDesignate(config.ProtocolConfiguration{
		StandbyValidators: pubs,
	})
	p := NewPolicy(&Contracts{
		Designate: des,
	})
	ic := interopContext{
		D: dao,
		L: make([]*types.Log, 1),
	}
	err := des.ContractCall_initialize(ic)
	assert.NoError(t, err)
	err = p.ContractCall_initialize(ic)
	assert.NoError(t, err)
	ic.S, _ = des.GetConsensusAddress(dao, 1)
	fn, ok := p.Abi.Methods["blockAccount"]
	assert.True(t, ok)
	input := append(fn.ID, []byte{0}...)
	_, err = p.Run(ic, input)
	assert.NotNil(t, err)

	input, err = p.Abi.Pack("blockAccount", common.Address{})
	assert.NoError(t, err)
	_, err = p.Run(ic, input)
	assert.NoError(t, err)

	r := p.IsBlocked(dao, common.Address{})
	assert.True(t, r)
}

func TestEvent(t *testing.T) {
	p := NewPolicy(nil)
	e := p.Abi.Events["setFeePerByte"]
	assert.Equal(t, hash.Keccak256([]byte("setFeePerByte(uint64)")), e.ID)
}
