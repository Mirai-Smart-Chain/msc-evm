// (c) 2019-2022, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

import { ethers } from "hardhat"
import { test } from "./utils"

const ADMIN_ADDRESS: string = "0x8db97C7cEcE249c2b98bDC0226Cc4C2A57BF52FC"
const DEPLOYER_ALLOWLIST_ADDRESS = "0x0200000000000000000000000000000000000000"

describe("ExampleDeployerList", function () {
  beforeEach('Setup DS-Test contract', async function () {
    const signer = await ethers.getSigner(ADMIN_ADDRESS)
    const allowListPromise = ethers.getContractAt("IAllowList", DEPLOYER_ALLOWLIST_ADDRESS, signer)

    return ethers.getContractFactory("ExampleDeployerListTest", { signer })
      .then(factory => factory.deploy())
      .then(contract => {
        this.testContract = contract;
        return contract.deployed().then(() => contract)
      })
      .then(contract => contract.setUp())
      .then(tx => Promise.all([allowListPromise, tx.wait()]))
      .then(([allowList]) => allowList.setAdmin(this.testContract.address))
      .then(tx => tx.wait())
  })

  test("precompile should see owner address has admin role", "test_verifySenderIsAdmin")

  test("precompile should see test address has no role", "test_newAddressHasNoRole")

  test("contract should report test address has no admin role", "test_noRoleIsNotAdmin")

  test("contract should report owner address has admin role", "test_ownerIsAdmin")

  test("should not let test address deploy", "test_noRoleCannotDeploy")

  test("should allow admin to add contract as admin", "test_adminAddContractAsAdmin")

  test("should allow admin to add deployer address as deployer through contract", "test_addDeployerThroughContract")

  test("should let deployer address to deploy", "test_deployerCanDeploy")

  test("should let admin revoke deployer", "test_adminCanRevokeDeployer")
})
