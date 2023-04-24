package result

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
)

func TestJson(t *testing.T) {
	r := &types.Receipt{
		BlockNumber:       big.NewInt(1),
		GasUsed:           1000,
		CumulativeGasUsed: 990,
	}
	fh, err := NewFeeHistory([]*types.Receipt{}, big.NewInt(100000000000))
	assert.NoError(t, err)
	b, err := json.Marshal(fh)
	assert.NoError(t, err)
	t.Log(string(b))
	fh, err = NewFeeHistory([]*types.Receipt{r}, big.NewInt(100000000000))
	assert.NoError(t, err)
	b, err = json.Marshal(fh)
	assert.NoError(t, err)
	t.Log(string(b))
	r = &types.Receipt{
		BlockNumber:       big.NewInt(1),
		GasUsed:           0,
		CumulativeGasUsed: 0,
	}
	fh, err = NewFeeHistory([]*types.Receipt{r}, big.NewInt(100000000000))
	assert.NoError(t, err)
	b, err = json.Marshal(fh)
	assert.NoError(t, err)
	t.Log(string(b))
}
