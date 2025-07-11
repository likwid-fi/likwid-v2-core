// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {LikwidVault} from "../src/LikwidVault.sol";

contract DeployLikwidVaultScript is Script {
    function setUp() public {}

    function run() external {
        vm.startBroadcast();

        // Deploy the LikwidVault
        LikwidVault vault = new LikwidVault(msg.sender);

        console.log("LikwidVault deployed at:", address(vault));

        vm.stopBroadcast();
    }
}
