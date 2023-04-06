package result

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBlockJson(t *testing.T) {
	block := Block{}
	bs, err := json.Marshal(block)
	assert.NoError(t, err)
	t.Log(string(bs))
}
