package address

import (
	"errors"

	"github.com/ZhangTao1596/neo-go/pkg/encoding/base58"
	"github.com/ethereum/go-ethereum/common"
)

var Prefix byte = 0x32

func AddressToBase58(u common.Address) string {
	b := append([]byte{Prefix}, u.Bytes()...)
	return base58.CheckEncode(b)
}

func Base58ToAddress(s string) (u common.Address, err error) {
	b, err := base58.CheckDecode(s)
	if err != nil {
		return u, err
	}
	if b[0] != Prefix {
		return u, errors.New("wrong address prefix")
	}
	return common.BytesToAddress(b[1:21]), nil
}
