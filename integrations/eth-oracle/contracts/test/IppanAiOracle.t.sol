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
        string memory label = "@alice.ipn";

        vm.prank(updater);
        oracle.updateScore(subject, score, label);

        assertEq(oracle.scores(subject), score);
        assertEq(
            uint256(keccak256(bytes(oracle.labels(subject)))),
            uint256(keccak256(bytes(label)))
        );
    }

    function testStrangerCannotUpdateScore() public {
        bytes32 subject = keccak256("validator-1");

        vm.prank(stranger);
        vm.expectRevert(bytes("IppanAiOracle: not updater"));
        oracle.updateScore(subject, 1, "@stranger.ipn");
    }

    function testBatchUpdate() public {
        bytes32[] memory subjects = new bytes32[](2);
        uint256[] memory values = new uint256[](2);
        string[] memory labels = new string[](2);
        subjects[0] = keccak256("v1");
        subjects[1] = keccak256("v2");
        values[0] = 10;
        values[1] = 20;
        labels[0] = "@v1.ipn";
        labels[1] = "@v2.ipn";

        vm.prank(updater);
        oracle.updateScores(subjects, values, labels);

        assertEq(oracle.scores(subjects[0]), 10);
        assertEq(
            uint256(keccak256(bytes(oracle.labels(subjects[0])))),
            uint256(keccak256(bytes("@v1.ipn")))
        );
        assertEq(oracle.scores(subjects[1]), 20);
        assertEq(
            uint256(keccak256(bytes(oracle.labels(subjects[1])))),
            uint256(keccak256(bytes("@v2.ipn")))
        );
    }

    function testBatchLengthMismatchReverts() public {
        bytes32[] memory subjects = new bytes32[](2);
        uint256[] memory scores = new uint256[](1);
        string[] memory labels = new string[](2);

        vm.prank(updater);
        vm.expectRevert(bytes("IppanAiOracle: length mismatch"));
        oracle.updateScores(subjects, scores, labels);
    }

    function testBatchLabelsLengthMismatchReverts() public {
        bytes32[] memory subjects = new bytes32[](2);
        uint256[] memory scores = new uint256[](2);
        string[] memory labels = new string[](1);

        vm.prank(updater);
        vm.expectRevert(bytes("IppanAiOracle: labels length mismatch"));
        oracle.updateScores(subjects, scores, labels);
    }

    function testGetSubjectHelper() public {
        bytes32 subject = keccak256("validator-1");
        uint256 score = 42;
        string memory label = "@alice.ipn";

        vm.prank(updater);
        oracle.updateScore(subject, score, label);

        (string memory gotLabel, uint256 gotScore) = oracle.getSubject(subject);
        assertEq(uint256(keccak256(bytes(gotLabel))), uint256(keccak256(bytes(label))));
        assertEq(gotScore, score);
    }
}
