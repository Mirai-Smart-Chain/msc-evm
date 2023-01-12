// (c) 2019-2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.
package bind

// tmplSourcePrecompileConfigGo is the Go precompiled config source template.
const tmplSourcePrecompileConfigGo = `
// Code generated
// This file is a generated precompile contract config with stubbed abstract functions.
// The file is generated by a template. Please inspect every code and comment in this file before use.

// There are some must-be-done changes waiting in the file. Each area requiring you to add your code is marked with CUSTOM CODE to make them easy to find and modify.
// Additionally there are other files you need to edit to activate your precompile.
// These areas are highlighted with comments "ADD YOUR PRECOMPILE HERE".
// For testing take a look at other precompile tests in core/stateful_precompile_test.go and config_test.go in other precompile folders.

/* General guidelines for precompile development:
1- Read the comment and set a suitable contract address in generated contract.go. E.g:
	ContractAddress = common.HexToAddress("ASUITABLEHEXADDRESS")
2- Set gas costs in generated contract.go
3- It is recommended to only modify code in the highlighted areas marked with "CUSTOM CODE STARTS HERE". Modifying code outside of these areas should be done with caution and with a deep understanding of how these changes may impact the EVM.
Typically, custom codes are required in only those areas.
4- Register your precompile module in params/precompile_modules.go
5- Add your config unit tests under generated package config_test.go
6- Add your contract unit tests under core/vm/contractstatefultests/{precompilename}_test.go
7- Add your solidity interface and test contract to contract-examples/contracts
8- Write solidity tests for your precompile in contract-examples/test
9- Create your genesis with your precompile enabled in tests/e2e/genesis/
10- Create e2e test for your solidity test in tests/e2e/solidity/suites.go
11- Run your e2e precompile Solidity tests with 'E2E=true ./scripts/run.sh'

*/

package {{.Package}}

{{$contract := .Contract}}
import (
	"math/big"

	"github.com/ava-labs/subnet-evm/precompile"
	{{- if .Contract.AllowList}}
	"github.com/ava-labs/subnet-evm/precompile/allowlist"
	{{- end}}

	"github.com/ethereum/go-ethereum/common"
)

var _ precompile.StatefulPrecompileConfig = &{{.Contract.Type}}Config{}

// ConfigKey is the key used in json config files to specify this precompile config.
// Must be unique across all precompiles.
const ConfigKey = "{{decapitalise .Contract.Type}}Config"

// {{.Contract.Type}}Config implements the StatefulPrecompileConfig
// interface while adding in the {{.Contract.Type}} specific precompile address.
type {{.Contract.Type}}Config struct {
	{{- if .Contract.AllowList}}
	allowlist.AllowListConfig
	{{- end}}
	precompile.UpgradeableConfig
}

{{$structs := .Structs}}
{{range $structs}}
	// {{.Name}} is an auto generated low-level Go binding around an user-defined struct.
	type {{.Name}} struct {
	{{range $field := .Fields}}
	{{$field.Name}} {{$field.Type}}{{end}}
	}
{{- end}}

{{- range .Contract.Funcs}}
{{ if len .Normalized.Inputs | lt 1}}
type {{capitalise .Normalized.Name}}Input struct{
{{range .Normalized.Inputs}} {{capitalise .Name}} {{bindtype .Type $structs}}; {{end}}
}
{{- end}}
{{ if len .Normalized.Outputs | lt 1}}
type {{capitalise .Normalized.Name}}Output struct{
{{range .Normalized.Outputs}} {{capitalise .Name}} {{bindtype .Type $structs}}; {{end}}
}
{{- end}}
{{- end}}

// New{{.Contract.Type}}Config returns a config for a network upgrade at [blockTimestamp] that enables
// {{.Contract.Type}} {{if .Contract.AllowList}} with the given [admins] as members of the allowlist {{end}}.
func New{{.Contract.Type}}Config(blockTimestamp *big.Int{{if .Contract.AllowList}}, admins []common.Address{{end}}) *{{.Contract.Type}}Config {
	return &{{.Contract.Type}}Config{
		{{if .Contract.AllowList}}AllowListConfig:   allowlist.AllowListConfig{AdminAddresses: admins},{{end}}
		UpgradeableConfig: precompile.UpgradeableConfig{BlockTimestamp: blockTimestamp},
	}
}

// NewDisable{{.Contract.Type}}Config returns config for a network upgrade at [blockTimestamp]
// that disables {{.Contract.Type}}.
func NewDisable{{.Contract.Type}}Config(blockTimestamp *big.Int) *{{.Contract.Type}}Config {
	return &{{.Contract.Type}}Config{
		UpgradeableConfig: precompile.UpgradeableConfig{
			BlockTimestamp: blockTimestamp,
			Disable:        true,
		},
	}
}

// Verify tries to verify {{.Contract.Type}}Config and returns an error accordingly.
func (c *{{.Contract.Type}}Config) Verify() error {
	{{if .Contract.AllowList}}
	// Verify AllowList first
	if err := c.AllowListConfig.Verify(); err != nil {
		return err
	}
	{{end}}
	// CUSTOM CODE STARTS HERE
	// Add your own custom verify code for {{.Contract.Type}}Config here
	// and return an error accordingly
	return nil
}

// Equal returns true if [s] is a [*{{.Contract.Type}}Config] and it has been configured identical to [c].
func (c *{{.Contract.Type}}Config) Equal(s precompile.StatefulPrecompileConfig) bool {
	// typecast before comparison
	other, ok := (s).(*{{.Contract.Type}}Config)
	if !ok {
		return false
	}
	// CUSTOM CODE STARTS HERE
	// modify this boolean accordingly with your custom {{.Contract.Type}}Config, to check if [other] and the current [c] are equal
	// if {{.Contract.Type}}Config contains only UpgradeableConfig {{if .Contract.AllowList}} and AllowListConfig {{end}} you can skip modifying it.
	equals := c.UpgradeableConfig.Equal(&other.UpgradeableConfig) {{if .Contract.AllowList}} && c.AllowListConfig.Equal(&other.AllowListConfig) {{end}}
	return equals
}

// Address returns the address of the {{.Contract.Type}}. Addresses reside under the precompile/params.go
// Select a non-conflicting address and set it in the params.go.
func (c {{.Contract.Type}}Config) Address() common.Address {
	return ContractAddress
}

// Configure configures [state] with the initial configuration.
func (c *{{.Contract.Type}}Config) Configure(_ precompile.ChainConfig, state precompile.StateDB, _ precompile.BlockContext) error {
	{{if .Contract.AllowList}}c.AllowListConfig.Configure(state, ContractAddress){{end}}
	// CUSTOM CODE STARTS HERE
	return nil
}

// Contract returns the singleton stateful precompiled contract to be used for {{.Contract.Type}}.
func ({{.Contract.Type}}Config) Contract() precompile.StatefulPrecompiledContract {
	return {{.Contract.Type}}Precompile
}

// Key returns the key used in json config files to specify this precompile config.
func ({{.Contract.Type}}Config) Key() string {
	return ConfigKey
}

// New returns a new {{.Contract.Type}}Config.
// This is used by the json parser to create a new instance of the {{.Contract.Type}}Config.
func ({{.Contract.Type}}Config) New() precompile.StatefulPrecompileConfig {
	return new({{.Contract.Type}}Config)
}
`