// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IppanAiOracle {
    address public updater;

    mapping(bytes32 => uint256) public scores;

    event ScoreUpdated(bytes32 indexed subject, uint256 score, uint256 timestamp);
    event BatchScoreUpdated(uint256 count, uint256 timestamp);

    modifier onlyUpdater() {
        require(msg.sender == updater, "not updater");
        _;
    }

    constructor(address _updater) {
        require(_updater != address(0), "invalid updater");
        updater = _updater;
    }

    function updateScore(bytes32 subject, uint256 score) external onlyUpdater {
        scores[subject] = score;
        emit ScoreUpdated(subject, score, block.timestamp);
    }

    function updateScores(bytes32[] calldata subjects, uint256[] calldata newScores) external onlyUpdater {
        require(subjects.length == newScores.length, "length mismatch");

        for (uint256 i = 0; i < subjects.length; i++) {
            scores[subjects[i]] = newScores[i];
            emit ScoreUpdated(subjects[i], newScores[i], block.timestamp);
        }

        emit BatchScoreUpdated(subjects.length, block.timestamp);
    }

    function getScore(bytes32 subject) external view returns (uint256) {
        return scores[subject];
    }
}
