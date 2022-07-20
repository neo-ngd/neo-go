package native

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/neo-ngd/neo-go/pkg/config"
	"github.com/neo-ngd/neo-go/pkg/core/dao"
	"github.com/neo-ngd/neo-go/pkg/core/storage"
	"github.com/stretchr/testify/assert"
)

func TestSetGasPrice(t *testing.T) {
	dao := dao.NewSimple(storage.NewMemoryStore())
	des := NewDesignate(config.ProtocolConfiguration{
		StandbyCommittee: []string{
			"023c4d39a3fd2150407a9d4654430cdce0464eccaaf739eea79d63e2862f989ee6",
		},
	})
	p := NewPolicy()
	ic := interopContext{
		D: dao,
		Contracts: &Contracts{
			Designate: des,
		},
	}
	err := des.ContractCall_initialize(ic)
	assert.NoError(t, err)
	err = p.ContractCall_initialize(ic)
	assert.NoError(t, err)
	ic.S, _ = des.GetCommitteeAddress(dao, 1)
	fn, ok := p.Abi.Methods["setGasPrice"]
	assert.True(t, ok)
	input := append(fn.ID, []byte{0}...)
	_, err = p.Run(ic, input)
	t.Log(err)
	assert.NotNil(t, err)

	input, err = p.Abi.Pack("setGasPrice", uint64(1))
	assert.NoError(t, err)
	_, err = p.Run(ic, input)
	assert.NoError(t, err)

	gasPrice := p.GetGasPriceInternal(dao)
	assert.Equal(t, uint64(1), gasPrice.Uint64())
}

func TestBlockAccount(t *testing.T) {
	dao := dao.NewSimple(storage.NewMemoryStore())
	des := NewDesignate(config.ProtocolConfiguration{
		StandbyCommittee: []string{
			"023c4d39a3fd2150407a9d4654430cdce0464eccaaf739eea79d63e2862f989ee6",
		},
	})
	p := NewPolicy()
	b, _ := json.Marshal(p.Abi)
	t.Log(string(b))
	ic := interopContext{
		D: dao,
		Contracts: &Contracts{
			Designate: des,
		},
	}
	err := des.ContractCall_initialize(ic)
	assert.NoError(t, err)
	err = p.ContractCall_initialize(ic)
	assert.NoError(t, err)
	ic.S, _ = des.GetCommitteeAddress(dao, 1)
	fn, ok := p.Abi.Methods["blockAccount"]
	assert.True(t, ok)
	input := append(fn.ID, []byte{0}...)
	_, err = p.Run(ic, input)
	t.Log(err)
	assert.NotNil(t, err)

	input, err = p.Abi.Pack("blockAccount", common.Address{})
	t.Log(hex.EncodeToString(input))
	assert.NoError(t, err)
	_, err = p.Run(ic, input)
	assert.NoError(t, err)

	r := p.IsBlocked(dao, common.Address{})
	assert.True(t, r)
}

func TestJson(t *testing.T) {
	p := NewPolicy()
	b, _ := json.Marshal(p)
	t.Log(string(b))
}
