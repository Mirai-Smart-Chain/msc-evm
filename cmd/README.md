# Stateful Precompile Generation Tutorial
In this tutorial,  we are going to walkthrough how we can generate a stateful precompile from scratch. Before we start, let's brush up on what a precompile is, what a stateful precompile is, and why this is extremely useful. 

## Precompiled Contracts
Precompiles were introduced to Ethereum as a way to solve the problem of allowing complex cryptographic computations to be usable in the EVM without having to deal with EVM overhead. The following precompiles are currently included: ecrecover, sha256, blake2f, ripemd-160, Bn256Add, Bn256Mul, Bn256Pairing, the identity function, and modular exponentiation.

We can see these precompile mappings from address to function here in the ethereum vm. 

``` go
// PrecompiledContractsBerlin contains the default set of pre-compiled Ethereum
// contracts used in the Berlin release.
var PrecompiledContractsBerlin = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}): &blake2F{},
}
```

These precompile addresses start from `0x0000000000000000000000000000000000000001` and increment by 1. 

A precompile follows this interface.
``` go 
// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64  // RequiredPrice calculates the contract gas use
	Run(input []byte) ([]byte, error) // Run runs the precompiled contract
}
```

Here is an example of the sha256 precompile function.
``` go 
type sha256hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Sha256PerWordGas + params.Sha256BaseGas
}

func (c *sha256hash) Run(input []byte) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}
```

The CALL opcode (CALL, STATICCALL, DELEGATECALL, and CALLCODE) allows us to invoke this precompile. 

The function signature of CALL in the evm is as follows: 
``` go
 Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
```

Smart contracts in solidity are compiled and converted into bytecode when they are first deployed. They are then stored on the blockchain and an address (usually known as the contract address) is assigned to it. When a user calls a function from a smart contract, it goes through the `CALL` function in the EVM. It takes in the caller address, the contract address, the input (function’s signature (truncated to the first leading four bytes) followed by the packed arguments data), gas, and value (native token). The function selector from the input lets the EVM know where to start from in the bytecode of the smart contract. It then executes a series of instructions (EVM opcodes) and returns the result. 

When a precompile function is called, it still goes through the `CALL` function in the EVM. However, it works a little differently. The EVM checks if the address is a precompile address from the mapping list and if so redirects to the precompile function. 

``` go
  if p := precompiles[addr]; p != nil {
    return RunPrecompiledContract(p, input, contract)
  }
```
The evm then performs the function and subtracts the `RequiredGas`.

Precompiles provide complex library functions that are commonly used in smart contracts and do not use EVM opcodes which makes execution faster and gas costs lower.

## Stateful Precompiled Contracts

A stateful precompile allows us to add even more functionality and customization to the EVM. It builds on a precompile in that it adds state access. 

A stateful precompile follows this interface. 
``` go
// StatefulPrecompiledContract is the interface for executing a precompiled contract
type StatefulPrecompiledContract interface {
	// Run executes the precompiled contract.
	Run(accessibleState PrecompileAccessibleState, caller common.Address, addr  common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error)

}
```

Notice the most important difference between the stateful precompile and precompile interface. We now inject state access to the `Run` function. Precompiles only took in a single byte slice as input. However, stateful precompile functions have complete access to the EVM state, and can be used to implement a much wider range of functionalities.

## Why This is Useful

 With state access, we can modify balances, read/write the storage of other contracts, and could even hook into external storage outside of the bounds of the EVM’s merkle trie (note: this would come with repercussions for fast sync since part of the state would be moved off of the merkle trie). We can now write custom logic to make our own EVM. We can do more on Avalanche in Solidity than on Ethereum!

## The Process

We will first create a Solidity interface that our precompile will implement.  Then we will use the precompile tool to autogenerate functions and fill out the rest. We're not done yet! We will then have to update a few more places within the EVM. Some of this work involves assigning a precompile address, adding the precompile to the list of EVM precompiles, and finally enabling the precompile. Now we can see our functions in action as we write another solidity smart contract that interacts with our precompile. Lastly, we will write some tests to make sure everything works as promised. 

## Assumption of Knowledge

Here are some helpful resources on the EVM to solidify your knowledge.

- [The Ethereum Virtual Machine](https://github.com/ethereumbook/ethereumbook/blob/develop/13evm.asciidoc)
- [Precompiles in Solidity](https://medium.com/@rbkhmrcr/precompiles-solidity-e5d29bd428c4)
- [Deconstructing a Smart Contract](https://blog.openzeppelin.com/deconstructing-a-solidity-contract-part-i-introduction-832efd2d7737/)
- [Layout of State Variables in Storage](https://docs.soliditylang.org/en/v0.8.10/internals/layout_in_storage.html)
- [Layout in Memory](https://docs.soliditylang.org/en/v0.8.10/internals/layout_in_memory.html)
- [Layout of Call Data](https://docs.soliditylang.org/en/v0.8.10/internals/layout_in_calldata.html)
- [Contract ABI Specification](https://docs.soliditylang.org/en/v0.8.10/abi-spec.html)
- [Precompiles in Solidity](https://medium.com/@rbkhmrcr/precompiles-solidity-e5d29bd428c4)
- [Customizing the EVM with Stateful Precompiles](https://medium.com/avalancheavax/customizing-the-evm-with-stateful-precompiles-f44a34f39efd)


## Tutorial

We will first start off by creating the Solidity interface that we want our precompile to implement. This will be the HelloWorld Interface. It will have two simple functions, `sayHello` and `setGreeting`. These two functions will demonstrate the getting and setting respectively of a value using state access. 

We will place the interface in `./contract-examples/contracts`

``` sol
// (c) 2022-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0;

interface IHelloWorld {
 // sayHello returns the string located at [key]
  function sayHello() external returns (string calldata);

// setGreeting sets the string located at [key]
  function setGreeting(string calldata response) external;
}
```

Now we have an interface that our precompile can implement!
Let's create an [abi](https://docs.soliditylang.org/en/v0.8.13/abi-spec.html#:~:text=Contract%20ABI%20Specification-,Basic%20Design,as%20described%20in%20this%20specification.) of our solidity code.

In the same `./contract-examples/contracts` directory, let's [download solc](https://docs.soliditylang.org/en/v0.8.9/installing-solidity.html) and run
```
solc --abi IHelloWorld.sol -o .
```

This spits out the abi code!

IHelloWorld.abi

``` json
[{"inputs":[],"name":"sayHello","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"recipient","type":"string"}],"name":"setGreeting","outputs":[],"stateMutability":"nonpayable","type":"function"}]
```

## Precompile tool

The precompile tool can take in 4 arguments. 


### `--abi` (string):

It needs an ABI input so it can bind it to the precompile template.

`--abi ./contract-examples/contracts/contract-abis/IHelloWorld.abi`

### `--type `(string):

It takes in a type which it uses as a struct name for the precompile. This is optional 
and will default to the abi name. 

`--type HelloWorld`

### `--pkg` (string):

It also takes in a pkg, which is the package name to generate the precompile into. 
This is optional and it defaults to "precompile".

`--pkg precompile` 

### `--out `(string):

Finally it can take in an out which is the path and name of the output file of the generated precompile. 

`--out ./precompile/hello_world.go`

Currently it can only generate precompiles in Golang only.  


## Generating the precompile 

Now that we have an abi for the precompile gen tool to interact with. We can run the following command to generate our HelloWorld precompile!


In the root of the repo run 
``` 
go run ./cmd/precompilegen/main.go --abi ./contract-examples/contracts/IHelloWorld.abi --type HelloWorld --pkg precompile --out ./precompile/hello_world.go
```

Wow! We just got a precompile template that's mostly complete located at `./precompile/hello_world.go`. Let's fill out the rest!

The precompile gives us commented instructions on the first 25 lines of the autogenerated file. Let's look at the 10 steps and follow them step by step.

``` go
/* General guidelines for precompile development:
1- Read the comment and set a suitable contract address in precompile/params.go. E.g:
	HelloWorldAddress = common.HexToAddress("ASUITABLEHEXADDRESS")
2- Set gas costs here
3- It is recommended to only modify code in the highlighted areas marked with "CUSTOM CODE STARTS HERE". Modifying code outside of these areas should be done with caution and with a deep understanding of how these changes may impact the EVM.
Typically, custom codes are required in only those areas.
4- Add your upgradable config in params/precompile_config.go
5- Add your precompile upgrade in params/config.go
6- Add your solidity interface and test contract to contract-examples/contracts
7- Write solidity tests for your precompile in contract-examples/test
8- Create your genesis with your precompile enabled in tests/e2e/genesis/
9- Create e2e test for your solidity test in tests/e2e/solidity/suites.go
10- Run your e2e precompile Solidity tests with 'E2E=true ./scripts/run.sh'
```

## Step 1: Set Contract Address

In `./precompile/params.go` let's set a precompile address. We can cut the
address from the var declaration block and remove it from the precompile. 
![](2022-09-01-22-46-00.png)
![](2022-08-24-16-45-48.png)

Now when subnet-evm sees the `HelloWorldAddress` as input when executing [`CALL`](../core/vm/evm.go#L222), [STATICCALL](../core/vm/evm.go#L401), [DELEGATECALL](core/vm/evm.go#L362), [CALLCODE](core/vm/evm.go#L311), it can [run the precompile](https://github.com/ava-labs/subnet-evm/blob/master/core/vm/evm.go#L271-L272) if the precompile is enabled.

## Step 2: Set Gas Costs

Set up gas costs. In `precompile/params.go` we have `writeGasCostPerSlot` and `readGasCostPerSlot`. This is a good starting point for estimating gas costs. 

```// Gas costs for stateful precompiles

const (
	writeGasCostPerSlot = 20_000
	readGasCostPerSlot  = 5_000
)
```

For example, 

![](2022-08-24-16-31-24.png)

**Example:** 
The sha256 precompile computes gas with the following equation
``` go
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Sha256PerWordGas + params.Sha256BaseGas
}
```

We'll probably have to come back later and change these costs. 

## Step 3: Add Custom Code

Ok time to `CTRL F` throughout the file with `CUSTOM CODE STARTS HERE` to find the areas in the precompile that we need to modify. 

![](2022-09-01-22-48-26.png)

If we use any of the following imports we can remove the reference imports.
We can come back if needed to remove. Next we see this in `Equals()`.

![](2022-09-01-22-51-30.png)

We can skip this step since our HelloWorldConfig struct looks like this.

```
// HelloWorldConfig implements the StatefulPrecompileConfig
// interface while adding in the HelloWorld specific precompile address.
type HelloWorldConfig struct {
	UpgradeableConfig
}
```

**Optional Note** 

If our HelloWorldConfig wrapped another config in its struct to implement the StatefulPrecompileConfig
like so 

``` go
// HelloWorldConfig implements the StatefulPrecompileConfig
// interface while adding in the IHelloWorld specific precompile address.

type HelloWorldConfig struct {
	UpgradeableConfig
    AllowListConfig
}
```

We would have to modify the `Equal()` function as follows: 

![](2022-09-01-22-54-22.png)

The next place we see the `CUSTOM CODE STARTS HERE` is in `Configure()`
Let's set it up. 

``` go
// Configure configures [state] with the initial configuration.
func (c *HelloWorldConfig) Configure(_ ChainConfig, state StateDB, _ BlockContext) {
	// CUSTOM CODE STARTS HERE
	// This will be called in the first block where HelloWorld stateful precompile is enabled.
	// 1) If BlockTimestamp is nil, this will not be called
	// 2) If BlockTimestamp is 0, this will be called while setting up the genesis block
	// 3) If BlockTimestamp is 1000, this will be called while processing the first block
	// whose timestamp is >= 1000
	//
	// Set the initial value under [common.BytesToHash([]byte("storageKey")] to "Hello World!"
	res := common.LeftPadBytes([]byte("Hello World!"), common.HashLength)
	state.SetState(HelloWorldAddress, common.BytesToHash([]byte("storageKey")), common.BytesToHash(res))
}
```

Next place to modify is in our `sayHello()` function.

``` go
func sayHello(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, SayHelloGasCost); err != nil {
		return nil, 0, err
	}
	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}
	// no input provided for this function

	// CUSTOM CODE STARTS HERE
	// Get the current state
	currentState := accessibleState.GetStateDB()
	// Get the value set at recipient
	value := currentState.GetState(HelloWorldAddress, common.BytesToHash([]byte("storageKey")))
	// Do some processing and pack the output
	packedOutput, err := PackSayHelloOutput(string(common.TrimLeftZeroes(value.Bytes())))
	if err != nil {
		return nil, remainingGas, err
	}

	// Return the packed output and the remaining gas
	return packedOutput, remainingGas, nil
}
```

Finally we can modify our `setGreeting()` function 

``` go
func setGreeting(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = deductGas(suppliedGas, SetGreetingGasCost); err != nil {
		return nil, 0, err
	}
	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}
	// attempts to unpack [input] into the arguments to the SetGreetingInput.
	// Assumes that [input] does not include selector
	// You can use unpacked [inputStruct] variable in your code
    inputStr, err := UnpackSetGreetingInput(input)
	if err != nil {
		return nil, remainingGas, err
	}

	// CUSTOM CODE STARTS HERE
    // check if the input string is longer than 32 bytes
    if len(inputStr) > 32 {
      return nil, 0, errors.New("input string is longer than 32 bytes")
    }

	// setGreeting is the execution function "SetGreeting(name string)"
    // and sets the storageKey in the string returned by hello world
  
    res := common.LeftPadBytes([]byte(inputStr), common.HashLength)
	accessibleState.GetStateDB().SetState(HelloWorldAddress, common. BytesToHash([]byte("storageKey")), common.BytesToHash(res))

	// this function does not return an output, leave this one as is
	packedOutput := []byte{}

	// Return the packed output and the remaining gas
	return packedOutput, remainingGas, nil
}
```

## Step 4: Add Upgradable Config

Let's now modify `params/precompile_config.go`. We can `CTRL F` for `ADD YOUR PRECOMPILE HERE`. 

Let's add our key. 

![](2022-09-01-23-20-53.png)

Let's add our precompile config to `PrecompileUpgrade`

![](2022-09-01-23-19-42.png)

Finally, we can add a getter function. 

![](2022-09-01-23-23-20.png)

Done! All we had to do was follow the comments.


## Step 5: Add Precompile Upgrade

Let's add our precompile upgrade in `params/config.go`. We can `CTRL F` for `ADD YOUR PRECOMPILE HERE`. 

Let's add the bool to check if our precompile is enabled.  

![](2022-09-01-23-35-47.png)

We can now add it to the Avalanche rules. 

![](2022-09-01-23-36-56.png)

Lastly, we can add `IsHelloWorld` which checks if we are equal or greater than the fork `blockTimestamp`. 
We use this to see if we should enable the precompile. 

![](2022-09-01-23-32-51.png)

## Step 6: Add Test Contract

Let's add our test contract to `contract-examples/contracts`. This smart contract lets us interact with our precompile! We cast the HelloWorld precompile address to the IHelloWorld interface. In doing so, `helloWorld` is now a contract of type `IHelloWorld` and when we call any functions on that contract, they will be sent to the HelloWorld precompile address. 

``` sol
//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IHelloWorld.sol";

// ExampleHelloWorld shows how the HelloWorld precompile can be used in a smart contract.
contract ExampleHelloWorld {
  address constant HELLO_WORLD_ADDRESS = 0x0200000000000000000000000000000000000004;
  IHelloWorld helloWorld = IHelloWorld(HELLO_WORLD_ADDRESS);

  function getHello() public returns (string memory) {
    return helloWorld.sayHello();
  }

  function setGreeting(string calldata greeting) public {
    helloWorld.setGreeting(greeting);
  }
}
```

Note that the contract methods do not need to have the same function signatures as the precompile. This contract is simply a wrapper. 

## Step 7: Add Precompile Solidity Tests 

We can now write our hardhat test in `contract-examples/test`. This file is called `ExampleHelloWorld.ts`

``` js
// (c) 2019-2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

import { expect } from "chai";
import { ethers } from "hardhat"
import {
    Contract,
    ContractFactory,
} from "ethers"

describe("ExampleHelloWorld", function () {
    let helloWorldContract: Contract;

    before(async function () {
        // Deploy Hello World Contract
        const ContractF: ContractFactory = await ethers.getContractFactory("ExampleHelloWorld");
        helloWorldContract = await ContractF.deploy();
        await helloWorldContract.deployed();
        const helloWorldContractAddress: string = helloWorldContract.address;
        console.log(`Contract deployed to: ${helloWorldContractAddress}`);
    });

    it("should getHello properly", async function () {
        let result = await helloWorldContract.callStatic.getHello();
        expect(result).to.equal("Hello World!");
    });

    it("should setGreeting and getHello", async function () {
        const modifiedGreeting = "What's up";
        let tx = await helloWorldContract.setGreeting(modifiedGreeting);
        await tx.wait();

        expect(await helloWorldContract.callStatic.getHello()).to.be.equal(modifiedGreeting);
    });
});
```

Let's see if it passes! We need to get a local network up and running. 

Before we do this, we actually need to create and modify the genesis to enable our HelloWorld precompile. Put this file in `/tmp/subnet-evm-genesis.json`
```json
{
    "config": {
        "chainId": 99999,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip150Hash": "0x2086799aeebeae135c246c65021c82b4e15a2c451340993aacfd2751886514f0",
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "muirGlacierBlock": 0,
        "subnetEVMTimestamp": 0,
        "feeConfig": {
            "gasLimit": 20000000,
            "minBaseFee": 1000000000,
            "targetGas": 100000000,
            "baseFeeChangeDenominator": 48,
            "minBlockGasCost": 0,
            "maxBlockGasCost": 10000000,
            "targetBlockRate": 2,
            "blockGasCostStep": 500000
        },
        "helloWorldConfig": {
            "blockTimestamp": 0
        }
    },
    "alloc": {
        "8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC": {
            "balance": "0x52B7D2DCC80CD2E4000000"
        },
        "0x0Fa8EA536Be85F32724D57A37758761B86416123": {
            "balance": "0x52B7D2DCC80CD2E4000000"
        }
    },
    "nonce": "0x0",
    "timestamp": "0x0",
    "extraData": "0x00",
    "gasLimit": "0x1312D00",
    "difficulty": "0x0",
    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "number": "0x0",
    "gasUsed": "0x0",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
```

Adding this to our genesis enables our HelloWorld precompile.  

``` json
"helloWorldConfig": {
  "blockTimestamp": 0
},
```

As a reminder, we defined `helloWorldConfig` in `./params/precompile_config.go`. By putting this in genesis, we enable our HelloWorld precompile at blockTimestamp 0. 

``` go
// PrecompileUpgrade is a helper struct embedded in UpgradeConfig, representing
// each of the possible stateful precompile types that can be activated
// as a network upgrade.
type PrecompileUpgrade struct {
	ContractDeployerAllowListConfig *precompile.ContractDeployerAllowListConfig `json:"contractDeployerAllowListConfig,omitempty"` // Config for the contract deployer allow list precompile
	ContractNativeMinterConfig      *precompile.ContractNativeMinterConfig      `json:"contractNativeMinterConfig,omitempty"`      // Config for the native minter precompile
	TxAllowListConfig               *precompile.TxAllowListConfig               `json:"txAllowListConfig,omitempty"`               // Config for the tx allow list precompile
	FeeManagerConfig                *precompile.FeeConfigManagerConfig          `json:"feeManagerConfig,omitempty"`                // Config for the fee manager precompile
	HelloWorldConfig                *precompile.HelloWorldConfig                `json:"helloWorldConfig,omitempty"`
	// ADD YOUR PRECOMPILE HERE
	// {YourPrecompile}Config  *precompile.{YourPrecompile}Config `json:"{yourPrecompile}Config,omitempty"`
}
```

Now we can get the network up and running. 
Open some terminal tabs and enter the following commands. 

``` go
// Start the server 
anr server \
--log-level debug \
--port=":8080" \
--grpc-gateway-port=":8081"

// In the root of the repo, run this to get the latest subnetevm binary 
./scripts/build.sh
 
// Spin up some nodes that run the latest version of subnet evm 
  anr control start \
  --log-level debug \
  --endpoint="0.0.0.0:8080" \
  --number-of-nodes=5 \
  --avalanchego-path ${AVALANCHEGO_EXEC_PATH} \
  --plugin-dir ${AVALANCHEGO_PLUGIN_PATH} \
  --blockchain-specs '[{"vm_name": "subnetevm", "genesis": "/tmp/subnet-evm-genesis.json"}]'

```

If the network startup is successful then you should see something like this.
```
[blockchain RPC for "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy"] "http://127.0.0.1:9650/ext/bc/2jDWMrF9yKK8gZfJaaaSfACKeMasiNgHmuZip5mWxUfhKaYoEU"
[blockchain RPC for "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy"] "http://127.0.0.1:9652/ext/bc/2jDWMrF9yKK8gZfJaaaSfACKeMasiNgHmuZip5mWxUfhKaYoEU"
[blockchain RPC for "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy"] "http://127.0.0.1:9654/ext/bc/2jDWMrF9yKK8gZfJaaaSfACKeMasiNgHmuZip5mWxUfhKaYoEU"
[blockchain RPC for "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy"] "http://127.0.0.1:9656/ext/bc/2jDWMrF9yKK8gZfJaaaSfACKeMasiNgHmuZip5mWxUfhKaYoEU"
[blockchain RPC for "srEXiWaHuhNyGwPUi444Tu47ZEDwxTWrbQiuD7FmgSAQ6X7Dy"] "http://127.0.0.1:9658/ext/bc/2jDWMrF9yKK8gZfJaaaSfACKeMasiNgHmuZip5mWxUfhKaYoEU"
```

Sweet! Now we have blockchain rpcs that can be used to talk to the network!

We now need to modify the hardhat config located in `./contract-examples/contracts/hardhat.config.ts`

We need to modify the `local` network. 
Let's change `chainId`, `gas`, and `gasPrice`. Make sure the `chainId` matches the one in the genesis file. 

``` 
networks: {
    local: {
      //"http://{ip}:{port}/ext/bc/{chainID}/rpc
      // modify this in the local_rpc.json
      url: localRPC,
      chainId: 99999,
      accounts: [
        "0x56289e99c94b6912bfc12adc093c9b51124f0dc54ac7a766b2bc5ccf558d8027",
        "0x7b4198529994b0dc604278c99d153cfd069d594753d471171a1d102a10438e07",
        "0x15614556be13730e9e8d6eacc1603143e7b96987429df8726384c2ec4502ef6e",
        "0x31b571bf6894a248831ff937bb49f7754509fe93bbd2517c9c73c4144c0e97dc",
        "0x6934bef917e01692b789da754a0eae31a8536eb465e7bff752ea291dad88c675",
        "0xe700bdbdbc279b808b1ec45f8c2370e4616d3a02c336e68d85d4668e08f53cff",
        "0xbbc2865b76ba28016bc2255c7504d000e046ae01934b04c694592a6276988630",
        "0xcdbfd34f687ced8c6968854f8a99ae47712c4f4183b78dcc4a903d1bfe8cbf60",
        "0x86f78c5416151fe3546dece84fda4b4b1e36089f2dbc48496faf3a950f16157c",
        "0x750839e9dbbd2a0910efe40f50b2f3b2f2f59f5580bb4b83bd8c1201cf9a010a"
      ],
      gasPrice: 25000000000,
      gas: 10000000,
    }
  }
```

We also need to make sure `localRPC` points to the right value.

Let's copy `local_rpc.example.json`. 

``` cp local_rpc.example.json local_rpc.json ``` 

Now in `local_rpc.json` we can modify the rpc url to the one we just created. It should look something like this. 

```
{
  "rpc": "http://127.0.0.1:9656/ext/bc/2jDWMrF9yKK8gZfJaaaSfACKeMasiNgHmuZip5mWxUfhKaYoEU/rpc"
}
```

Now if we go to `./contract-examples`, we can finally run our tests. 

``` npx hardhat test --network local ```

Great they passed! All the functions implemented in the precompile work as expected!

## Step 8: Create Genesis

We can move our genesis file we created in the last step to  `tests/e2e/genesis/`.

```cp /tmp/subnet-evm-genesis.json  tests/e2e/genesis/hello_world.json``` 

## Step 9: Add E2E tests

In `tests/e2e/solidity/suites.go` we can now write our first e2e test!
It's another nice copy and paste situation. 

``` go
ginkgo.It("hello world", func() {
		err := startSubnet("./tests/e2e/genesis/hello_world.json")
		gomega.Expect(err).Should(gomega.BeNil())
		running := runner.IsRunnerUp()
		gomega.Expect(running).Should(gomega.BeTrue())
		runHardhatTests("./test/HelloWorld.ts")
		stopSubnet()
		running = runner.IsRunnerUp()
		gomega.Expect(running).Should(gomega.BeFalse())
	})

	// ADD YOUR PRECOMPILE HERE
	/*
			ginkgo.It("your precompile", func() {
			err := startSubnet("./tests/e2e/genesis/{your_precompile}.json")
			gomega.Expect(err).Should(gomega.BeNil())
			running := runner.IsRunnerUp()
			gomega.Expect(running).Should(gomega.BeTrue())
			runHardhatTests("./test/Example{YourPrecompile}Test.ts")
			stopSubnet()
			running = runner.IsRunnerUp()
			gomega.Expect(running).Should(gomega.BeFalse())
		})
	*/
```

## Step 10: Run E2E Test

Now we can run it, this time with the E2E flag on. We should expect this to pass since we did such thorough testing in Step 7. 
Going back to the root let's run
```E2E=true ./scripts/run.sh```

![](2022-09-01-16-53-58.png)