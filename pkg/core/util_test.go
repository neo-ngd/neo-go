package core

import (
	"testing"

	"github.com/neo-ngd/neo-go/pkg/config"
	"github.com/neo-ngd/neo-go/pkg/core/block"
	"github.com/neo-ngd/neo-go/pkg/io"
	"github.com/stretchr/testify/assert"
)

func TestGenesisBlock(t *testing.T) {
	b, err := createGenesisBlock(&config.ProtocolConfiguration{})
	assert.NoError(t, err)
	bs, err := io.ToByteArray(b)
	assert.NoError(t, err)
	bb := &block.Block{}
	err = io.FromByteArray(bb, bs)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(bb.Transactions))
}
