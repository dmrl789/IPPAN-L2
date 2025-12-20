// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IppanAiOracle
/// @notice Stores deterministic scores for IPPAN-related subjects (validators, handles, datasets, etc.).
contract IppanAiOracle {
    address public updater;

    mapping(bytes32 => uint256) public scores;
    mapping(bytes32 => string) public labels;

    event ScoreUpdated(bytes32 indexed subject, uint256 score, uint256 timestamp);
    event BatchScoreUpdated(uint256 count, uint256 timestamp);
    event LabelUpdated(bytes32 indexed subject, string label);

    modifier onlyUpdater() {
        require(msg.sender == updater, "IppanAiOracle: not updater");
        _;
    }

    constructor(address _updater) {
        require(_updater != address(0), "IppanAiOracle: updater is zero address");
        updater = _updater;
    }

    function updateScore(bytes32 subject, uint256 score, string calldata label) external onlyUpdater {
        labels[subject] = label;
        scores[subject] = score;
        emit LabelUpdated(subject, label);
        emit ScoreUpdated(subject, score, block.timestamp);
    }

    function updateScores(bytes32[] calldata subjects, uint256[] calldata newScores, string[] calldata newLabels)
        external
        onlyUpdater
    {
        uint256 len = subjects.length;
        require(len == newScores.length, "IppanAiOracle: length mismatch");
        require(len == newLabels.length, "IppanAiOracle: labels length mismatch");

        for (uint256 i = 0; i < len; i++) {
            bytes32 subject = subjects[i];
            uint256 score = newScores[i];
            string calldata label = newLabels[i];

            labels[subject] = label;
            scores[subject] = score;

            emit LabelUpdated(subject, label);
            emit ScoreUpdated(subject, score, block.timestamp);
        }

        emit BatchScoreUpdated(len, block.timestamp);
    }

    function getScore(bytes32 subject) external view returns (uint256) {
        return scores[subject];
    }

    function getSubject(bytes32 subject) external view returns (string memory label, uint256 score) {
        return (labels[subject], scores[subject]);
    }
}
