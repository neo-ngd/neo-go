package state

import (
	"github.com/ZhangTao1596/neo-go/pkg/io"
	"github.com/ethereum/go-ethereum/common"
)

type StorageKey struct {
	Hash common.Address
	Key  []byte
}

func (sk *StorageKey) EncodeBinary(bw *io.BinWriter) {
	bw.WriteBytes(sk.Hash[:])
	bw.WriteVarBytes(sk.Key)
}

func (sk *StorageKey) DecodeBinary(br *io.BinReader) {
	br.ReadBytes(sk.Hash[:])
	sk.Key = br.ReadVarBytes()
}
