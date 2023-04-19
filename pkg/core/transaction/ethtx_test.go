package transaction

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
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

func TestDynamicTx(t *testing.T) {
	s := "02f87504808502540be4008502540be40083018f9c94ef8e8e9e00b9ef71519728923a148632f9cad3d3880de0b6b3a764000080c001a0f2483ce9a2b374064c74f93f08fa7f119ef08c82c4c64f251637d65e91d864f2a051f6e8c4b5d122b4467c925c2ba5e8f4f6ffed1f57b349c2ba2689ee391c7eec"
	b, err := hex.DecodeString(s)
	assert.NoError(t, err)
	tx := &types.Transaction{}
	err = tx.UnmarshalBinary(b)
	assert.NoError(t, err)
	assert.Equal(t, types.DynamicFeeTxType, int(tx.Type()))
	etx, err := NewEthTx(tx)
	t.Log(etx.Hash())
	assert.NoError(t, err)
	b, err = json.Marshal(etx)
	assert.NoError(t, err)
	t.Log(string(b))
	tt := NewTx(etx)
	assert.NoError(t, err)
	assert.Equal(t, tt.Hash(), tx.Hash())
}

func TestLegacyTx(t *testing.T) {
	s := "f86e808502540be400809455decb32ef6f3a76cb9b56f4c8c38ad572b3d3968a152d02c7e14af68000008082021ea0e042c68ea701552929e972f52205b960705704abb6a57a893b41d44935c6abf2a060b08ba9ee2c0089c699c6684bd996f214860fc898574c7be5078a76a57226f0"
	b, err := hex.DecodeString(s)
	assert.NoError(t, err)
	tx := &types.Transaction{}
	err = tx.UnmarshalBinary(b)
	assert.NoError(t, err)
	assert.Equal(t, types.LegacyTxType, int(tx.Type()))
	etx, err := NewEthTx(tx)
	assert.NoError(t, err)
	b, err = json.Marshal(etx)
	assert.NoError(t, err)
	t.Log(string(b))
}
