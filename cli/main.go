package main

import (
	"os"

	"github.com/neo-ngd/neo-go/cli/native"
	"github.com/neo-ngd/neo-go/cli/query"
	"github.com/neo-ngd/neo-go/cli/server"
	"github.com/neo-ngd/neo-go/cli/utils"
	"github.com/neo-ngd/neo-go/cli/vm"
	"github.com/neo-ngd/neo-go/cli/wallet"
	"github.com/neo-ngd/neo-go/pkg/config"
	"github.com/urfave/cli"
)

func main() {
	ctl := newApp()

	if err := ctl.Run(os.Args); err != nil {
		panic(err)
	}
}

func newApp() *cli.App {
	ctl := cli.NewApp()
	ctl.Name = "neo-go-evm"
	ctl.Version = config.Version
	ctl.Usage = "Official Go client for neo-go-evm"
	ctl.ErrWriter = os.Stdout

	ctl.Commands = append(ctl.Commands, server.NewCommands()...)
	ctl.Commands = append(ctl.Commands, wallet.NewCommands()...)
	ctl.Commands = append(ctl.Commands, vm.NewCommands()...)
	ctl.Commands = append(ctl.Commands, query.NewCommands()...)
	ctl.Commands = append(ctl.Commands, native.NewCommands()...)
	ctl.Commands = append(ctl.Commands, utils.NewCommands()...)
	return ctl
}
