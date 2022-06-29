package evm

import "github.com/ZhangTao1596/neo-go/pkg/core/native"

type NativeContracts interface {
	Contracts() *native.Contracts
}
