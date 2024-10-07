// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import { GatewayCaller, Gateway } from "fhevm/gateway/GatewayCaller.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { SP1DkimVerifier } from "./SP1DkimVerifier.sol";
import { ISuffragium } from "./interfaces/ISuffragium.sol";

contract Suffragium is ISuffragium, SP1DkimVerifier, GatewayCaller, Ownable {
    euint64 private immutable ENC_ONE;

    mapping(uint256 => Vote) public votes;
    mapping(bytes32 => bool) private _voters;
    uint256 private _nextVoteId;
    uint256 public minQuorum;

    constructor(
        address verifier,
        bytes32 programVKey,
        bytes32 emailPublicKeyHash,
        bytes32 fromDomainHash,
        uint256 initialMinQuorum
    ) SP1DkimVerifier(verifier, programVKey, emailPublicKeyHash, fromDomainHash) Ownable(msg.sender) {
        ENC_ONE = TFHE.asEuint64(1);
        TFHE.allow(ENC_ONE, address(this));
        minQuorum = initialMinQuorum;
    }

    /// @inheritdoc ISuffragium
    function createVote(uint256 endBlock, string calldata description) external onlyOwner {
        uint256 voteId = _nextVoteId;
        votes[voteId] = Vote(endBlock, TFHE.asEuint64(0), TFHE.asEuint64(0), 0, 0, description, VoteState.Created);
        TFHE.allow(votes[voteId].encryptedResult, address(this));
        TFHE.allow(votes[voteId].encryptedValidVotes, address(this));
        _nextVoteId++;
        emit VoteCreated(voteId);
    }

    /// @inheritdoc ISuffragium
    function castVote(
        uint256 voteId,
        einput encryptedSupport,
        bytes calldata supportProof,
        bytes calldata registrationPublicValues,
        bytes calldata registrationProofBytes
    ) external {
        // NOTE: If an attacker gains access to the email, they can generate a proof and submit it on-chain with a support value greater than 1, resulting in censorship of the legitimate voter.
        bytes32 voterId = keccak256(abi.encodePacked(registrationPublicValues, registrationProofBytes));
        if (_voters[voterId]) revert AlreadyVoted();
        _voters[voterId] = true;

        verifyDkim(registrationPublicValues, registrationProofBytes);

        Vote storage vote = _getVote(voteId);
        if (block.number > vote.endBlock) revert VoteClosed();

        euint64 support = TFHE.asEuint64(encryptedSupport, supportProof);
        TFHE.allowTransient(support, address(this));
        ebool isValid = TFHE.le(support, ENC_ONE);
        TFHE.allowTransient(isValid, address(this));

        euint64 encryptedResult = vote.encryptedResult;
        euint64 encryptedValidVotes = vote.encryptedValidVotes;
        vote.encryptedResult = TFHE.select(isValid, TFHE.add(support, encryptedResult), encryptedResult);
        vote.encryptedValidVotes = TFHE.select(isValid, TFHE.add(encryptedValidVotes, ENC_ONE), encryptedValidVotes);
        TFHE.allow(vote.encryptedResult, address(this));
        TFHE.allow(vote.encryptedValidVotes, address(this));

        emit VoteCasted(voteId);
    }

    /// @inheritdoc ISuffragium
    function getVote(uint256 voteId) external view returns (Vote memory) {
        return _getVote(voteId);
    }

    /// @inheritdoc ISuffragium
    function isVotePassed(uint256 voteId) external view returns (bool) {
        Vote storage vote = _getVote(voteId);
        if (vote.state != VoteState.Revealed) return false;
        return (vote.result * 10 ** 18) / vote.validVotes >= minQuorum;
    }

    /// @inheritdoc ISuffragium
    function requestRevealVote(uint256 voteId) external {
        Vote storage vote = _getVote(voteId);
        if (block.number <= vote.endBlock) revert VoteNotClosed();

        uint256[] memory cts = new uint256[](2);
        cts[0] = Gateway.toUint256(vote.encryptedResult);
        cts[1] = Gateway.toUint256(vote.encryptedValidVotes);
        uint256 requestId = Gateway.requestDecryption(cts, this.revealVote.selector, 0, block.timestamp + 100, false);
        addParamsUint256(requestId, voteId);
        vote.state = VoteState.RequestedToReveal;

        emit VoteRevealRequested(voteId);
    }

    /// @inheritdoc ISuffragium
    function revealVote(uint256 requestId, uint256 result, uint256 validVotes) external onlyGateway {
        uint256[] memory params = getParamsUint256(requestId);
        uint256 voteId = params[0];

        Vote storage vote = _getVote(voteId);
        vote.state = VoteState.Revealed;
        vote.result = result;
        vote.validVotes = validVotes;

        emit VoteRevealed(voteId);
    }

    /// @inheritdoc ISuffragium
    function setMinQuorum(uint256 newMinQuorum) external onlyOwner {
        minQuorum = newMinQuorum;
        emit MinQuorumSet(newMinQuorum);
    }

    function _getVote(uint256 voteId) internal view returns (Vote storage) {
        Vote storage vote = votes[voteId];
        if (vote.endBlock == 0) revert VoteDoesNotExist();
        return vote;
    }
}
