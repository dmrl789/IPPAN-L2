// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Vm.sol";

/// @notice Minimal script base contract (subset of forge-std/Script.sol).
contract Script {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
}
