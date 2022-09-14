package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	//"syscall"

	"github.com/neo-ngd/neo-go/cli/contract"
	"github.com/neo-ngd/neo-go/cli/native"
	"github.com/neo-ngd/neo-go/cli/query"
	"github.com/neo-ngd/neo-go/cli/server"
	"github.com/neo-ngd/neo-go/cli/utils"
	"github.com/neo-ngd/neo-go/cli/wallet"
	"github.com/neo-ngd/neo-go/pkg/config"
	"github.com/urfave/cli"
)

func main() {
	ctl := newApp()

	var command []string

	cli.OsExiter = func(c int) {}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if text == "quit" || text == "q" {
			break
		}
		command = append(os.Args, strings.Split(text, " ")...)
		ctl.Run(command)
		command = []string{}
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
	ctl.Commands = append(ctl.Commands, query.NewCommands()...)
	ctl.Commands = append(ctl.Commands, native.NewCommands()...)
	ctl.Commands = append(ctl.Commands, contract.NewCommands()...)
	ctl.Commands = append(ctl.Commands, utils.NewCommands()...)
	return ctl
}
