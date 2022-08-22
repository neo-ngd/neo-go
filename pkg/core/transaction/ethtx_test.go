package transaction

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
)

func TestEncodeRLP(t *testing.T) {
	s := "f868800182d6d8946cb3e9d55dc87d4586bd2e558a1ee46a94e300b4880de0b6b3a764000080818da0ccd99c35f99317a094d99a8b677acb495dda3402e8aa45f91c524dea9aeb4c7ba02e5fffeedca5c7e4bbc7f36f16e94d1f85daf0ed0cd036187aa9c564708ce220"
	b, err := hex.DecodeString(s)
	assert.NoError(t, err)
	tx := &EthTx{}
	err = rlp.DecodeBytes(b, tx)
	assert.NoError(t, err)
	b, err = rlp.EncodeToBytes(tx)
	assert.NoError(t, err)
	assert.Equal(t, s, hex.EncodeToString(b))
}
