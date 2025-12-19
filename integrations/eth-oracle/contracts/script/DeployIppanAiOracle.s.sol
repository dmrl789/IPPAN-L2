// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import {IppanAiOracle} from "../contracts/IppanAiOracle.sol";

contract DeployIppanAiOracle is Script {
    function run() external returns (IppanAiOracle deployed) {
        address updater = vm.envAddress("UPDATER_ADDRESS");

        vm.startBroadcast();
        deployed = new IppanAiOracle(updater);
        vm.stopBroadcast();

        console2.log("IppanAiOracle deployed at:", address(deployed));
    }
}
