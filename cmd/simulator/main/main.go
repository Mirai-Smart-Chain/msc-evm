// (c) 2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/cmd/simulator/config"
	"github.com/ethereum/go-ethereum/cmd/simulator/load"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/utils"
	"github.com/spf13/pflag"
)

func main() {
	fs := config.BuildFlagSet()
	v, err := config.BuildViper(fs, os.Args[1:])
	if errors.Is(err, pflag.ErrHelp) {
		os.Exit(0)
	}

	if err != nil {
		fmt.Printf("couldn't build viper: %s\n", err)
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("couldn't configure flags: %s\n", err)
		os.Exit(1)
	}

	if v.GetBool(config.VersionKey) {
		fmt.Printf("%s\n", config.Version)
		os.Exit(0)
	}

	logLevel, err := utils.LvlFromString(v.GetString(config.LogLevelKey))
	if err != nil {
		fmt.Printf("couldn't parse log level: %s\n", err)
		os.Exit(1)
	}
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, logLevel, true)))

	config, err := config.BuildConfig(v)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
	if err := load.ExecuteLoader(context.Background(), config); err != nil {
		fmt.Printf("load execution failed: %s\n", err)
		os.Exit(1)
	}
}
