package result

import (
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/neo-ngd/neo-go/pkg/core/block"
	"github.com/neo-ngd/neo-go/pkg/io"
)

type (
	// Header wrapper used for the representation of
	// block header on the RPC Server.
	Header struct {
		block.Header
		BlockMetadata
	}
)

// NewHeader creates a new Header wrapper.
func NewHeader(h *block.Header, chain LedgerAux) Header {
	res := Header{
		Header: *h,
		BlockMetadata: BlockMetadata{
			Size: hexutil.Uint(io.GetVarSize(h)),
		},
	}
	return res
}

// MarshalJSON implements json.Marshaler interface.
func (h Header) MarshalJSON() ([]byte, error) {
	output, err := json.Marshal(h.BlockMetadata)
	if err != nil {
		return nil, err
	}
	baseBytes, err := json.Marshal(h.Header)
	if err != nil {
		return nil, err
	}

	// We have to keep both "fields" at the same level in json in order to
	// match C# API, so there's no way to marshall Block correctly with
	// standard json.Marshaller tool.
	if output[len(output)-1] != '}' || baseBytes[0] != '{' {
		return nil, errors.New("can't merge internal jsons")
	}
	output[len(output)-1] = ','
	output = append(output, baseBytes[1:]...)
	return output, nil
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (h *Header) UnmarshalJSON(data []byte) error {
	// As block.Block and BlockMetadata are at the same level in json,
	// do unmarshalling separately for both structs.
	meta := new(BlockMetadata)
	err := json.Unmarshal(data, meta)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, &h.Header)
	if err != nil {
		return err
	}
	h.BlockMetadata = *meta
	return nil
}
