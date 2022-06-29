package state

import (
	"github.com/ZhangTao1596/neo-go/pkg/io"
	"github.com/ethereum/go-ethereum/common"
)

type Contract struct {
	Address  common.Address `json:"address"`
	CodeHash common.Hash    `json:"codeHash"`
	Code     []byte         `json:"code"`
}

// NativeContract holds information about native contract.
type NativeContract struct {
	Name string `json:"name"`
	Contract
	UpdateHistory []uint32 `json:"updatehistory"`
}

func (c *Contract) EncodeBinary(bw *io.BinWriter) {
	bw.WriteBytes(c.Address[:])
	bw.WriteBytes(c.CodeHash[:])
	bw.WriteVarBytes(c.Code)
}

func (c *Contract) DecodeBinary(br *io.BinReader) {
	br.ReadBytes(c.Address[:])
	br.ReadBytes(c.CodeHash[:])
	c.Code = br.ReadVarBytes()
}
