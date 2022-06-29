package statedb

import "github.com/neo-ngd/neo-go/pkg/core/native"

type NativeContracts interface {
	Contracts() *native.Contracts
}
