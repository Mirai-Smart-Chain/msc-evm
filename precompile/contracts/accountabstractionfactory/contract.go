package accountabstractionfactory

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"

	_ "embed"

	"github.com/ava-labs/subnet-evm/core/state"
	"github.com/ava-labs/subnet-evm/core/vm"
	"github.com/ava-labs/subnet-evm/core/vm/runtime"
	"github.com/ava-labs/subnet-evm/params"
	"github.com/ava-labs/subnet-evm/precompile/allowlist"
	"github.com/ava-labs/subnet-evm/precompile/contract"
	"github.com/ava-labs/subnet-evm/vmerrs"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

const (
	ERC1967ProxyCreationCode = "60806040526040516107c13803806107c183398101604081905261002291610321565b61002e82826000610035565b505061043e565b61003e8361006b565b60008251118061004b5750805b156100665761006483836100ab60201b6100291760201c565b505b505050565b610074816100d7565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a250565b60606100d0838360405180606001604052806027815260200161079a602791396101a9565b9392505050565b6100ea8161022260201b6100551760201c565b6101515760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b60648201526084015b60405180910390fd5b806101887f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc60001b61023160201b6100711760201c565b80546001600160a01b0319166001600160a01b039290921691909117905550565b6060600080856001600160a01b0316856040516101c691906103ef565b600060405180830381855af49150503d8060008114610201576040519150601f19603f3d011682016040523d82523d6000602084013e610206565b606091505b50909250905061021886838387610234565b9695505050505050565b6001600160a01b03163b151590565b90565b606083156102a357825160000361029c576001600160a01b0385163b61029c5760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e74726163740000006044820152606401610148565b50816102ad565b6102ad83836102b5565b949350505050565b8151156102c55781518083602001fd5b8060405162461bcd60e51b8152600401610148919061040b565b634e487b7160e01b600052604160045260246000fd5b60005b838110156103105781810151838201526020016102f8565b838111156100645750506000910152565b6000806040838503121561033457600080fd5b82516001600160a01b038116811461034b57600080fd5b60208401519092506001600160401b038082111561036857600080fd5b818501915085601f83011261037c57600080fd5b81518181111561038e5761038e6102df565b604051601f8201601f19908116603f011681019083821181831017156103b6576103b66102df565b816040528281528860208487010111156103cf57600080fd5b6103e08360208301602088016102f5565b80955050505050509250929050565b600082516104018184602087016102f5565b9190910192915050565b602081526000825180602084015261042a8160408501602087016102f5565b601f01601f19169190910160400192915050565b61034d8061044d6000396000f3fe60806040523661001357610011610017565b005b6100115b610027610022610074565b6100b9565b565b606061004e83836040518060600160405280602781526020016102f1602791396100dd565b9392505050565b73ffffffffffffffffffffffffffffffffffffffff163b151590565b90565b60006100b47f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc5473ffffffffffffffffffffffffffffffffffffffff1690565b905090565b3660008037600080366000845af43d6000803e8080156100d8573d6000f35b3d6000fd5b60606000808573ffffffffffffffffffffffffffffffffffffffff16856040516101079190610283565b600060405180830381855af49150503d8060008114610142576040519150601f19603f3d011682016040523d82523d6000602084013e610147565b606091505b509150915061015886838387610162565b9695505050505050565b606083156101fd5782516000036101f65773ffffffffffffffffffffffffffffffffffffffff85163b6101f6576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e747261637400000060448201526064015b60405180910390fd5b5081610207565b610207838361020f565b949350505050565b81511561021f5781518083602001fd5b806040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101ed919061029f565b60005b8381101561026e578181015183820152602001610256565b8381111561027d576000848401525b50505050565b60008251610295818460208701610253565b9190910192915050565b60208152600082518060208401526102be816040850160208701610253565b601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe016919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564a26469706673582212201cd78ab6a31213989661cff2d7d05fc9b9c38b1a848e8249e2e398659a9eb7e364736f6c634300080f0033416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564"
	// Gas costs for each function. These are set to 1 by default.
	// You should set a gas cost for each function in your contract.
	// Generally, you should not set gas costs very low as this may cause your network to be vulnerable to DoS attacks.
	// There are some predefined gas costs in contract/utils.go that you can use.
	// This contract also uses AllowList precompile.
	// You should also increase gas costs of functions that read from AllowList storage.
	GetAddressGasCost    uint64 = contract.ReadGasCostPerSlot
	CreateAccountGasCost uint64 = 0
)

type GetAddressInput struct {
	Owner common.Address
	Salt  *big.Int
}

type CreateAccountInput struct {
	Owner common.Address
	Salt  *big.Int
}

// Singleton StatefulPrecompiledContract and signatures.
var (
	ErrCannotCreateAccount     = errors.New("non-enabled cannot call createAccount")
	ErrInvalidLenGetAddress    = errors.New("invalid input length for getAddress")
	ErrInvalidLenCreateAccount = errors.New("invalid input length for createAccount")

	// SimpleAccount Preset
	SimpleAccountFactory        = common.HexToAddress("0x9406Cc6185a346906296840746125a0E44976454")
	SimpleAccountImplementation = common.HexToAddress("0x8ABB13360b87Be5EEb1B98647A016adD927a136c")

	// AccountAbstractionRawABI contains the raw ABI of AccountAbstraction contract.
	//go:embed AccountAbstractionFactory.abi
	AccountAbstractionFactoryRawABI string
	AccountAbstractionFactoryABI    = contract.ParseABI(AccountAbstractionFactoryRawABI)

	// ERC1967ProxyRawABI contains the raw ABI of ERC1967Proxy contract.
	//go:embed ERC1967Proxy.abi
	ERC1967ProxyRawABI string
	ERC1967ProxyABI    = contract.ParseABI(ERC1967ProxyRawABI)

	initializeABI = contract.ParseABI("[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"owner\",\"type\":\"address\"}],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]")

	AccountAbstractionPrecompile = createAccountAbstractionFactoryPrecompile()
)

// GetAccountAbstractionAllowListStatus returns the role of [address] for the AccountAbstraction list.
func GetAccountAbstractionAllowListStatus(stateDB contract.StateDB, address common.Address) allowlist.Role {
	return allowlist.GetAllowListStatus(stateDB, ContractAddress, address)
}

// SetAccountAbstractionAllowListStatus sets the permissions of [address] to [role] for the
// AccountAbstraction list. Assumes [role] has already been verified as valid.
// This stores the [role] in the contract storage with address [ContractAddress]
// and [address] hash. It means that any reusage of the [address] key for different value
// conflicts with the same slot [role] is stored.
// Precompile implementations must use a different key than [address] for their storage.
func SetAccountAbstractionAllowListStatus(stateDB contract.StateDB, address common.Address, role allowlist.Role) {
	allowlist.SetAllowListRole(stateDB, ContractAddress, address, role)
}

// PackGetAddress packs the include selector (first 4 func signature bytes).
func PackGetAddress(owner common.Address, salt *big.Int) ([]byte, error) {
	return AccountAbstractionFactoryABI.Pack("getAddress", owner, salt)
}

// PackCreateAccount packs the include selector (first 4 func signature bytes).
func PackCreateAccount(owner common.Address, salt *big.Int) ([]byte, error) {
	return AccountAbstractionFactoryABI.Pack("createAccount", owner, salt)
}

// PackGetAddressOutput attempts to pack given result of type address
// to conform the ABI outputs.
func PackGetAddressOutput(account common.Address) ([]byte, error) {
	return AccountAbstractionFactoryABI.PackOutput("getAddress", account)
}

// PackCreateAccountOutput attempts to pack given result of type address
// to conform the ABI outputs.
func PackCreateAccountOutput(account common.Address) ([]byte, error) {
	return AccountAbstractionFactoryABI.PackOutput("createAccount", account)
}

func UnpackGetAddressInput(input []byte, useStrictMode bool) (common.Address, *big.Int, error) {
	if useStrictMode && len(input) != common.HashLength+common.HashLength {
		return common.Address{}, nil, fmt.Errorf("%w: %d", ErrInvalidLenGetAddress, len(input))
	}

	inputStruct := GetAddressInput{}
	err := AccountAbstractionFactoryABI.UnpackInputIntoInterface(&inputStruct, "getAddress", input, useStrictMode)
	return inputStruct.Owner, inputStruct.Salt, err
}

func UnpackCreateAccountInput(input []byte, useStrictMode bool) (common.Address, *big.Int, error) {
	if useStrictMode && len(input) != common.HashLength+common.HashLength {
		return common.Address{}, nil, fmt.Errorf("%w: %d", ErrInvalidLenCreateAccount, len(input))
	}

	inputStruct := CreateAccountInput{}
	err := AccountAbstractionFactoryABI.UnpackInputIntoInterface(&inputStruct, "createAccount", input, useStrictMode)
	return inputStruct.Owner, inputStruct.Salt, err
}

func getAddress(accessibleState contract.AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = contract.DeductGas(suppliedGas, GetAddressGasCost); err != nil {
		return nil, 0, err
	}

	useStrictMode := !contract.IsDurangoActivated(accessibleState)
	owner, salt, err := UnpackGetAddressInput(input, useStrictMode)
	if err != nil {
		return nil, remainingGas, err
	}

	initialize, _ := initializeABI.Pack("initialize", owner)
	encode, _ := ERC1967ProxyABI.Pack("", SimpleAccountImplementation, initialize)

	var encodePacked bytes.Buffer
	encodePacked.Write(common.Hex2Bytes(ERC1967ProxyCreationCode))
	encodePacked.Write(encode)

	initHash := crypto.Keccak256(encodePacked.Bytes())

	newAccount := crypto.CreateAddress2(SimpleAccountFactory, uint256.MustFromBig(salt).Bytes32(), initHash)

	packedOutput, err := PackGetAddressOutput(newAccount)
	if err != nil {
		return nil, remainingGas, err
	}

	// Return the packed output and the remaining gas
	return packedOutput, remainingGas, nil
}

func createAccount(accessibleState contract.AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = contract.DeductGas(suppliedGas, CreateAccountGasCost); err != nil {
		return nil, 0, err
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	useStrictMode := !contract.IsDurangoActivated(accessibleState)
	owner, salt, err := UnpackCreateAccountInput(input, useStrictMode)
	if err != nil {
		return nil, remainingGas, err
	}

	stateDB := accessibleState.GetStateDB()

	// Verify that the caller is in the allow list and therefore has the right to call this function.
	callerStatus := allowlist.GetAllowListStatus(stateDB, ContractAddress, caller)
	if !callerStatus.IsEnabled() {
		return nil, remainingGas, fmt.Errorf("%w: %s", ErrCannotCreateAccount, caller)
	}

	initialize, _ := initializeABI.Pack("initialize", owner)
	encode, _ := ERC1967ProxyABI.Pack("", SimpleAccountImplementation, initialize)

	var encodePacked bytes.Buffer
	encodePacked.Write(common.Hex2Bytes(ERC1967ProxyCreationCode))
	encodePacked.Write(encode)

	evm := runtime.NewEnv(&runtime.Config{
		Origin:      caller,
		ChainConfig: accessibleState.GetChainConfig().(*params.ChainConfig),
		State:       stateDB.(*state.StateDB),
		BlockNumber: accessibleState.GetBlockContext().Number(),
		Time:        accessibleState.GetBlockContext().Timestamp(),
		GasLimit:    math.MaxUint64,
		Difficulty:  new(big.Int),
		GasPrice:    new(big.Int),
		BaseFee:     new(big.Int).Set(params.DefaultFeeConfig.MinBaseFee),
	})

	_, newAccount, _, err := evm.Create2(vm.AccountRef(SimpleAccountFactory), encodePacked.Bytes(), math.MaxUint64, big.NewInt(0), uint256.MustFromBig(salt))

	if err != nil {
		return nil, remainingGas, err
	}

	if contract.IsDurangoActivated(accessibleState) {
		if remainingGas, err = contract.DeductGas(remainingGas, AccountCreatedEventGasCost); err != nil {
			return nil, 0, err
		}
		topics, data, err := PackAccountCreatedEvent(newAccount, owner, salt)
		if err != nil {
			return nil, remainingGas, err
		}
		stateDB.AddLog(
			ContractAddress,
			topics,
			data,
			accessibleState.GetBlockContext().Number().Uint64(),
		)
	}

	packedOutput, err := PackCreateAccountOutput(newAccount)
	if err != nil {
		return nil, remainingGas, err
	}

	// Return the packed output and the remaining gas
	return packedOutput, remainingGas, nil
}

// createAccountAbstractionPrecompile returns a StatefulPrecompiledContract with getters and setters for the precompile.
// Access to the getters/setters is controlled by an allow list for ContractAddress.
func createAccountAbstractionFactoryPrecompile() contract.StatefulPrecompiledContract {
	var functions []*contract.StatefulPrecompileFunction
	functions = append(functions, allowlist.CreateAllowListFunctions(ContractAddress)...)

	abiFunctionMap := map[string]contract.RunStatefulPrecompileFunc{
		"getAddress":    getAddress,
		"createAccount": createAccount,
	}

	for name, function := range abiFunctionMap {
		method, ok := AccountAbstractionFactoryABI.Methods[name]
		if !ok {
			panic(fmt.Errorf("given method (%s) does not exist in the ABI", name))
		}
		functions = append(functions, contract.NewStatefulPrecompileFunction(method.ID, function))
	}
	// Construct the contract with no fallback function.
	statefulContract, err := contract.NewStatefulPrecompileContract(nil, functions)
	if err != nil {
		panic(err)
	}
	return statefulContract
}
