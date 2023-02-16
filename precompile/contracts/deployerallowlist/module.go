// (c) 2019-2020, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package deployerallowlist

import (
	"fmt"

	"github.com/ava-labs/subnet-evm/precompile/config"
	"github.com/ava-labs/subnet-evm/precompile/contract"
	"github.com/ava-labs/subnet-evm/precompile/modules"
	"github.com/ethereum/go-ethereum/common"
)

var _ contract.Configurator = &configurator{}

// ConfigKey is the key used in json config files to specify this precompile config.
// must be unique across all precompiles.
const ConfigKey = "contractDeployerAllowListConfig"

var ContractAddress = common.HexToAddress("0x0200000000000000000000000000000000000000")

var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     ContractDeployerAllowListPrecompile,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

func (*configurator) NewConfig() config.Config {
	return &Config{}
}

// Configure configures [state] with the given [cfg] config.
func (c *configurator) Configure(_ contract.ChainConfig, cfg config.Config, state contract.StateDB, _ contract.BlockContext) error {
	config, ok := cfg.(*Config)
	if !ok {
		return fmt.Errorf("incorrect config %T: %v", config, config)
	}
	return config.Config.Configure(state, ContractAddress)
}