// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal console2 shim for compilation.
library console2 {
    function log(string memory, address) internal pure {
        // no-op (Foundry injects a real console at runtime)
    }
}
