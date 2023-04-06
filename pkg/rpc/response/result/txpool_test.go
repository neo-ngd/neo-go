package result

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTxPool(t *testing.T) {
	tp := NewTxPool(nil)
	b, err := json.Marshal(tp)
	assert.NoError(t, err)
	t.Log(string(b))
}

func TestPoolTx(t *testing.T) {
	pt := poolTx{}
	b, err := json.Marshal(pt)
	assert.NoError(t, err)
	t.Log(string(b))
}
