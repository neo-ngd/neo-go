package hash

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestProve(t *testing.T) {
	hashes := make([]common.Hash, 10)
	for i := byte(0); i < 10; i++ {
		hashes[i] = common.BytesToHash([]byte{i})
	}
	tree, err := NewMerkleTree(hashes)
	assert.NoError(t, err)
	proofs, path, err := tree.Prove(common.BytesToHash([]byte{0x01}))
	assert.NoError(t, err)
	assert.Equal(t, 4, len(proofs))
	assert.Equal(t, uint32(14), path)
}

func TestVerify(t *testing.T) {
	hashes := make([]common.Hash, 10)
	for i := byte(0); i < 10; i++ {
		hashes[i] = common.BytesToHash([]byte{i})
	}
	tree, err := NewMerkleTree(hashes)
	assert.NoError(t, err)
	proofs, path, err := tree.Prove(common.BytesToHash([]byte{0x01}))
	assert.NoError(t, err)
	assert.Equal(t, 4, len(proofs))
	assert.Equal(t, uint32(14), path)
	r := VerifyMerkleProof(tree.root.hash, common.BytesToHash([]byte{0x01}), proofs, path)
	assert.True(t, r)
}

func TestVerifySingle(t *testing.T) {
	h := common.BytesToHash([]byte{1})
	r := VerifyMerkleProof(h, h, nil, uint32(0))
	assert.True(t, r)
}
