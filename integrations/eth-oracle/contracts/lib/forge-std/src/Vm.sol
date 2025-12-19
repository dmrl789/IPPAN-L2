// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal Foundry cheatcode interface (subset).
interface Vm {
    // prank
    function prank(address) external;

    // expects
    function expectRevert(bytes calldata) external;

    // env
    function envAddress(string calldata) external returns (address);

    // broadcast (scripts)
    function startBroadcast() external;
    function stopBroadcast() external;
}
