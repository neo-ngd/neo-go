package client

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/neo-ngd/neo-go/pkg/rpc/request"
)

func (c *Client) Bridge_GetMinted(id int64) (common.Hash, error) {
	var (
		params = request.NewRawParams()
		resp   = common.Hash{}
	)
	err := c.performRequest("bridge_getMinted", params, &resp)
	return resp, err
}
