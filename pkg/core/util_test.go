package core

import (
	"testing"

	"github.com/ZhangTao1596/neo-go/pkg/config"
	"github.com/ZhangTao1596/neo-go/pkg/core/block"
	"github.com/ZhangTao1596/neo-go/pkg/io"
	"github.com/stretchr/testify/assert"
)

func TestGenesisBlock(t *testing.T) {
	cfg := config.ProtocolConfiguration{}
	b, err := createGenesisBlock(cfg)
	assert.NoError(t, err)
	bs, err := io.ToByteArray(b)
	assert.NoError(t, err)
	bb := &block.Block{}
	err = io.FromByteArray(bb, bs)
	assert.NoError(t, err)
}
