package result

import (
	"github.com/ZhangTao1596/neo-go/pkg/crypto/keys"
)

// Validator used for the representation of
// state.Validator on the RPC Server.
type Validator struct {
	PublicKey keys.PublicKey `json:"publickey"`
	Votes     int64          `json:"votes,string"`
	Active    bool           `json:"active"`
}
