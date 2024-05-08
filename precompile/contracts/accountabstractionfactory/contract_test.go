package accountabstractionfactory

import (
	"math/big"
	"testing"

	"github.com/ava-labs/subnet-evm/core/state"
	"github.com/ava-labs/subnet-evm/precompile/allowlist"
	"github.com/ava-labs/subnet-evm/precompile/testutils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

var (
	tests = map[string]testutils.PrecompileTest{
		"calling getAddress with a SimpleAccount preset from NoRole should success": {
			Caller: allowlist.TestNoRoleAddr,
			InputFn: func(t testing.TB) []byte {
				input, err := PackGetAddress(common.HexToAddress("0xFF1B1469112dd4D82697E4C10bF70Dd44F37435b"), big.NewInt(1))
				require.NoError(t, err)

				return input
			},
			SuppliedGas: GetAddressGasCost,
			ReadOnly:    true,
			ExpectedRes: func() []byte {
				res, err := PackGetAddressOutput(common.HexToAddress("0xD3d8aA6e5ff0D7551a85823C88E8cEbd46c41B96"))
				if err != nil {
					panic(err)
				}
				return res
			}(),
		},
	}
)

func TestGetAddress(t *testing.T) {
	allowlist.RunPrecompileWithAllowListTests(t, Module, state.NewTestStateDB, tests)
}
