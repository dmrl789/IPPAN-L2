// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console2.sol";
import "../src/IppanAiOracle.sol";

contract DeployIppanAiOracle is Script {
    function run() external {
        address updater = vm.envAddress("UPDATER_ADDRESS");

        vm.startBroadcast();
        IppanAiOracle oracle = new IppanAiOracle(updater);
        vm.stopBroadcast();

        console2.log("IppanAiOracle deployed at:", address(oracle));
    }
}
