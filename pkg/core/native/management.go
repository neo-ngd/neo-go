package native

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/neo-ngd/neo-go/pkg/core/dao"
	"github.com/neo-ngd/neo-go/pkg/core/native/nativeids"
	"github.com/neo-ngd/neo-go/pkg/core/native/nativenames"
	"github.com/neo-ngd/neo-go/pkg/core/state"
	"github.com/neo-ngd/neo-go/pkg/crypto/hash"
	"github.com/neo-ngd/neo-go/pkg/io"
)

const (
	prefixContract = 0x01
)

var ManagementAddress common.Address = common.Address(common.BytesToAddress([]byte{nativeids.Management}))

type Management struct {
	state.NativeContract
}

func createContractKey(h common.Address) []byte {
	return makeAddressKey(prefixContract, h)
}

func NewManagement() *Management {
	m := &Management{
		NativeContract: state.NativeContract{
			Name: nativenames.Management,
			Contract: state.Contract{
				Address: ManagementAddress,
				Code:    []byte{},
			},
		},
	}
	mAbi, contractCalls, err := constructAbi(m)
	if err != nil {
		panic(err)
	}
	m.Abi = *mAbi
	m.ContractCalls = contractCalls
	return m
}

func (m *Management) GetContract(s *dao.Simple, addr common.Address) *state.Contract {
	item := s.GetStorageItem(m.Address, createContractKey(addr))
	if item == nil {
		return nil
	}
	contract := &state.Contract{}
	err := io.FromByteArray(contract, item)
	if err != nil {
		panic(err)
	}
	return contract
}

func (m *Management) GetCode(s *dao.Simple, addr common.Address) []byte {
	contract := m.GetContract(s, addr)
	if contract == nil {
		return nil
	}
	return contract.Code
}

func (m *Management) GetCodeHash(s *dao.Simple, addr common.Address) common.Hash {
	contract := m.GetContract(s, addr)
	if contract == nil {
		return common.Hash{}
	}
	return contract.CodeHash
}

func (m *Management) GetCodeSize(s *dao.Simple, addr common.Address) int {
	contract := m.GetContract(s, addr)
	if contract == nil {
		return 0
	}
	return len(contract.Code)
}

func (m *Management) SetCode(s *dao.Simple, addr common.Address, code []byte) {
	contract := m.GetContract(s, addr)
	if contract == nil {
		contract = &state.Contract{
			Address: addr,
		}
	}
	contract.Code = code
	contract.CodeHash = hash.Keccak256(code)
	bytes, err := io.ToByteArray(contract)
	if err != nil {
		panic(err)
	}
	s.PutStorageItem(m.Address, createContractKey(addr), bytes)
}

func (m *Management) Destroy(s *dao.Simple, addr common.Address) bool {
	contract := m.GetContract(s, addr)
	if contract == nil {
		return false
	}
	k := createContractKey(addr)
	s.DeleteStorageItem(addr, k)
	return true
}
