// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import { ISP1DkimVerifier } from "./ISP1DkimVerifier.sol";

/// @title Suffragium Interface
/// @author Alessadro Manfredi
/// @notice This contract is the interface for the Suffragium voting system.
interface ISuffragium is ISP1DkimVerifier {
    enum VoteState {
        NotCreated,
        Created,
        RequestedToReveal,
        Revealed
    }

    struct Vote {
        uint256 endBlock;
        euint64 encryptedResult;
        euint64 encryptedValidVotes;
        uint256 result;
        uint256 validVotes;
        string description;
        VoteState state;
    }

    event VoteCasted(uint256 indexed voteId);
    event VoteCreated(uint256 indexed voteId);
    event VoteRevealRequested(uint256 indexed voteId);
    event VoteRevealed(uint256 indexed voteId);

    error AlreadyVoted();
    error VoteDoesNotExist();
    error VoteNotClosed();
    error VoteClosed();

    function createVote(uint256 endBlock, string calldata description) external;

    function castVote(
        uint256 voteId,
        einput encryptedSupport,
        bytes calldata supportProof,
        bytes calldata registrationPublicValues,
        bytes calldata registrationProofBytes
    ) external;

    function getVote(uint256 voteId) external view returns (Vote memory);

    function isVotePassed(uint256 voteId) external view returns (bool);

    function requestRevealVote(uint256 voteId) external;

    function revealVote(uint256 requestId, uint256 encryptedResult, uint256 encryptedValidVotes) external;
}
