// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/IppanAiOracle.sol";

contract IppanAiOracleTest is Test {
    IppanAiOracle private oracle;
    address private updater = address(0x1234);
    address private stranger = address(0x5678);

    function setUp() public {
        oracle = new IppanAiOracle(updater);
    }

    function testUpdaterCanUpdateScore() public {
        bytes32 subject = keccak256("validator-1");
        uint256 score = 42;

        vm.prank(updater);
        oracle.updateScore(subject, score);

        assertEq(oracle.scores(subject), score);
    }

    function testStrangerCannotUpdateScore() public {
        bytes32 subject = keccak256("validator-1");

        vm.prank(stranger);
        vm.expectRevert(bytes("IppanAiOracle: not updater"));
        oracle.updateScore(subject, 1);
    }

    function testBatchUpdate() public {
        bytes32[] memory subjects = new bytes32[](2);
        uint256[] memory values = new uint256[](2);
        subjects[0] = keccak256("v1");
        subjects[1] = keccak256("v2");
        values[0] = 10;
        values[1] = 20;

        vm.prank(updater);
        oracle.updateScores(subjects, values);

        assertEq(oracle.scores(subjects[0]), 10);
        assertEq(oracle.scores(subjects[1]), 20);
    }

    function testBatchLengthMismatchReverts() public {
        bytes32[] memory subjects = new bytes32[](2);
        uint256[] memory scores = new uint256[](1);

        vm.prank(updater);
        vm.expectRevert(bytes("IppanAiOracle: length mismatch"));
        oracle.updateScores(subjects, scores);
    }
}
