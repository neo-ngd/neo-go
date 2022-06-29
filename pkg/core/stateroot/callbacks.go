package stateroot

import (
	"github.com/neo-ngd/neo-go/pkg/crypto/keys"
)

// SetUpdateValidatorsCallback sets callback for sending signed root.
func (s *Module) SetUpdateValidatorsCallback(f func(uint32, keys.PublicKeys)) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.updateValidatorsCb = f
}
