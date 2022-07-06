package native

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/neo-ngd/neo-go/cli/options"
	"github.com/neo-ngd/neo-go/cli/wallet"
	"github.com/urfave/cli"
)

func NewCommands() []cli.Command {
	return []cli.Command{{
		Name:  "native",
		Usage: "invoke native contract",
		Subcommands: []cli.Command{
			{
				Name:        "designate",
				Usage:       "designate committee or validators",
				Subcommands: newDesignateCommands(),
			},
			{
				Name:        "policy",
				Usage:       "manage policy",
				Subcommands: newPolicyCommands(),
			},
		},
	},
	}
}

func makeCommitteeTx(ctx *cli.Context, to common.Address, data []byte) error {
	wall, err := wallet.ReadWallet(ctx.String("wallet"))
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	gctx, cancel := options.GetTimeoutContext(ctx)
	defer cancel()
	c, err := options.GetRPCClient(gctx, ctx)
	if err != nil {
		return cli.NewExitError(err, 1)
	}
	committeeAddr, err := c.GetCommitteeAddress()
	if err != nil {
		return cli.NewExitError(fmt.Errorf("failed get committee address: %w", err), 1)
	}
	return wallet.MakeTx(ctx, wall, committeeAddr, to, big.NewInt(0), data)
}
