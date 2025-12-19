// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IppanAiOracle
/// @notice Stores deterministic scores for IPPAN-related subjects (validators, handles, datasets, etc.).
contract IppanAiOracle {
    address public updater;

    mapping(bytes32 => uint256) public scores;

    event ScoreUpdated(bytes32 indexed subject, uint256 score, uint256 timestamp);
    event BatchScoreUpdated(uint256 count, uint256 timestamp);

    modifier onlyUpdater() {
        require(msg.sender == updater, "IppanAiOracle: not updater");
        _;
    }

    constructor(address _updater) {
        require(_updater != address(0), "IppanAiOracle: updater is zero address");
        updater = _updater;
    }

    function updateScore(bytes32 subject, uint256 score) external onlyUpdater {
        scores[subject] = score;
        emit ScoreUpdated(subject, score, block.timestamp);
    }

    function updateScores(bytes32[] calldata subjects, uint256[] calldata newScores) external onlyUpdater {
        uint256 len = subjects.length;
        require(len == newScores.length, "IppanAiOracle: length mismatch");

        for (uint256 i = 0; i < len; i++) {
            scores[subjects[i]] = newScores[i];
        }

        emit BatchScoreUpdated(len, block.timestamp);
    }

    function getScore(bytes32 subject) external view returns (uint256) {
        return scores[subject];
    }
}
