// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Vm.sol";

/// @notice Minimal test base contract (subset of forge-std/Test.sol).
contract Test {
    // Standard Foundry cheatcode address.
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertEq(uint256 a, uint256 b) internal pure {
        require(a == b, "assertEq(uint256) failed");
    }

    function assertEq(address a, address b) internal pure {
        require(a == b, "assertEq(address) failed");
    }
}
