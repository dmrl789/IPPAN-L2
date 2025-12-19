// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {IppanAiOracle} from "../contracts/IppanAiOracle.sol";

contract IppanAiOracleTest is Test {
    address internal updater = address(0xBEEF);
    address internal nonUpdater = address(0xCAFE);

    IppanAiOracle internal oracle;

    function setUp() public {
        oracle = new IppanAiOracle(updater);
    }

    function testUpdaterCanUpdateScore() public {
        bytes32 subject = keccak256("validator-1");
        uint256 score = 123;

        vm.prank(updater);
        oracle.updateScore(subject, score);

        assertEq(oracle.getScore(subject), score);
    }

    function testNonUpdaterCannotUpdateScore() public {
        bytes32 subject = keccak256("validator-1");

        vm.prank(nonUpdater);
        vm.expectRevert(bytes("not updater"));
        oracle.updateScore(subject, 1);
    }

    function testBatchUpdate() public {
        bytes32[] memory subjects = new bytes32[](2);
        uint256[] memory scores = new uint256[](2);
        subjects[0] = keccak256("validator-1");
        subjects[1] = keccak256("validator-2");
        scores[0] = 111;
        scores[1] = 222;

        vm.prank(updater);
        oracle.updateScores(subjects, scores);

        assertEq(oracle.getScore(subjects[0]), 111);
        assertEq(oracle.getScore(subjects[1]), 222);
    }

    function testBatchLengthMismatchReverts() public {
        bytes32[] memory subjects = new bytes32[](2);
        uint256[] memory scores = new uint256[](1);

        vm.prank(updater);
        vm.expectRevert(bytes("length mismatch"));
        oracle.updateScores(subjects, scores);
    }
}
