package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const testConfigPath = "./testdata/protocol.test.yml"

func TestLoadConfig(t *testing.T) {
	_, err := LoadFile(testConfigPath)
	require.NoError(t, err)
}
