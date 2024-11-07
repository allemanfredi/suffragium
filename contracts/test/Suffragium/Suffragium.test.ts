// Import required testing and contract dependencies
import { expect } from "chai";
import { ethers } from "hardhat";

import { SP1MockVerifier, Suffragium } from "../../types";
import { awaitAllDecryptionResults } from "../asyncDecrypt";
import { createInstances } from "../instance";
import { Signers, getSigners, initSigners } from "../signers";
import { FhevmInstances } from "../types";
import { mineNBlocks } from "../utils";

// Constants used throughout the tests
const PROGRAM_VERIFICATION_KEY = "0x0000000000000000000000000000000000000000000000000000000000000000";
const VOTE_DURATION = 100; // blocks
const EMAIL_PUBLIC_KEY_HASH = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const FROM_DOMAIN_HASH = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const abiCoder = new ethers.AbiCoder();
const MIN_QUORUM = "500000000000000000"; // 0.5 -> 50%

describe("Suffragium", function () {
  // Test variables
  let signers: Signers;
  let verifier: SP1MockVerifier;
  let suffragium: Suffragium;
  let instances: FhevmInstances;

  // Initialize signers before all tests
  before(async () => {
    await initSigners();
    signers = await getSigners();
  });

  // Setup fresh contract instances before each test
  beforeEach(async () => {
    const Suffragium = await ethers.getContractFactory("Suffragium");
    const SP1MockVerifier = await ethers.getContractFactory("SP1MockVerifier");

    verifier = await SP1MockVerifier.deploy();
    suffragium = await Suffragium.deploy(
      await verifier.getAddress(),
      PROGRAM_VERIFICATION_KEY,
      EMAIL_PUBLIC_KEY_HASH,
      FROM_DOMAIN_HASH,
    );
    instances = await createInstances(signers);
  });

  // Test basic vote casting functionality
  it("should be able to cast a vote", async () => {
    const voteId = 0;
    const voterId = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, MIN_QUORUM, "description"))
      .to.emit(suffragium, "VoteCreated")
      .withArgs(voteId);

    // Create and submit an encrypted vote
    const input = instances.alice.createEncryptedInput(await suffragium.getAddress(), signers.alice.address);
    const encryptedInput = input.addBool(1).encrypt();
    const publicValues = abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bool"],
      [FROM_DOMAIN_HASH, EMAIL_PUBLIC_KEY_HASH, voterId, true],
    );
    await expect(suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, "0x"))
      .to.emit(suffragium, "VoteCasted")
      .withArgs(voteId);
  });

  // Test prevention of double voting
  it("should not be able to cast a vote using the same proof more than once", async () => {
    const voteId = 0;
    const voterId = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, MIN_QUORUM, "description"))
      .to.emit(suffragium, "VoteCreated")
      .withArgs(voteId);

    // Create and submit first vote
    const input = instances.alice.createEncryptedInput(await suffragium.getAddress(), signers.alice.address);
    const encryptedInput = input.addBool(1).encrypt();
    const publicValues = abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bool"],
      [FROM_DOMAIN_HASH, EMAIL_PUBLIC_KEY_HASH, voterId, true],
    );
    await suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, "0x");

    // Attempt to vote again with same proof should fail
    await expect(
      suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, "0x"),
    ).to.be.revertedWithCustomError(suffragium, "AlreadyVoted");
  });

  // Test vote passing with 80% quorum
  it("should be able to cast more votes and reveal the result when the quorum (80%) is reached", async () => {
    const voteId = 0;
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, "800000000000000000", "description"))
      .to.emit(suffragium, "VoteCreated")
      .withArgs(voteId);

    // Cast votes from multiple instances
    for (const [index, instance] of Object.values(instances).entries()) {
      const input = instance.createEncryptedInput(await suffragium.getAddress(), Object.values(signers)[index].address);
      const encryptedInput = input.addBool(index === 0 ? 0 : 1).encrypt();
      const voterId = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + index.toString(16);
      const publicValues = abiCoder.encode(
        ["bytes32", "bytes32", "bytes32", "bool"],
        [FROM_DOMAIN_HASH, EMAIL_PUBLIC_KEY_HASH, voterId, true],
      );
      await expect(
        suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, `0x0${index}`),
      )
        .to.emit(suffragium, "VoteCasted")
        .withArgs(voteId);
    }

    // Reveal and verify vote results
    await mineNBlocks(VOTE_DURATION);
    await expect(suffragium.requestRevealVote(voteId)).to.emit(suffragium, "VoteRevealRequested").withArgs(voteId);
    await awaitAllDecryptionResults();

    expect(await suffragium.isVotePassed(voteId)).to.be.eq(true);
  });

  // Test vote passing with 100% quorum
  it("should be able to cast more votes and reveal the result when the quorum (100%) is reached", async () => {
    const voteId = 0;
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, "1000000000000000000", "description"))
      .to.emit(suffragium, "VoteCreated")
      .withArgs(voteId);

    // Cast unanimous yes votes
    for (const [index, instance] of Object.values(instances).entries()) {
      const input = instance.createEncryptedInput(await suffragium.getAddress(), Object.values(signers)[index].address);
      const encryptedInput = input.addBool(1).encrypt();
      const voterId = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + index.toString(16);
      const publicValues = abiCoder.encode(
        ["bytes32", "bytes32", "bytes32", "bool"],
        [FROM_DOMAIN_HASH, EMAIL_PUBLIC_KEY_HASH, voterId, true],
      );
      await expect(
        suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, `0x0${index}`),
      )
        .to.emit(suffragium, "VoteCasted")
        .withArgs(voteId);
    }

    // Reveal and verify vote results
    await mineNBlocks(VOTE_DURATION);
    await expect(suffragium.requestRevealVote(voteId)).to.emit(suffragium, "VoteRevealRequested").withArgs(voteId);
    await awaitAllDecryptionResults();

    expect(await suffragium.isVotePassed(voteId)).to.be.eq(true);
  });

  // Test vote failing with all "no" votes
  it("should fail when all votes are false", async () => {
    const voteId = 0;
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, MIN_QUORUM, "description"))
      .to.emit(suffragium, "VoteCreated")
      .withArgs(voteId);

    // Cast all "no" votes
    for (const [index, instance] of Object.values(instances).entries()) {
      const input = instance.createEncryptedInput(await suffragium.getAddress(), Object.values(signers)[index].address);
      const encryptedInput = input.addBool(0).encrypt(); // All votes are false/no
      const voterId = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + index.toString(16);
      const publicValues = abiCoder.encode(
        ["bytes32", "bytes32", "bytes32", "bool"],
        [FROM_DOMAIN_HASH, EMAIL_PUBLIC_KEY_HASH, voterId, true],
      );
      await expect(
        suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, `0x0${index}`),
      )
        .to.emit(suffragium, "VoteCasted")
        .withArgs(voteId);
    }

    // Reveal and verify vote results
    await mineNBlocks(VOTE_DURATION);
    await expect(suffragium.requestRevealVote(voteId)).to.emit(suffragium, "VoteRevealRequested").withArgs(voteId);
    await awaitAllDecryptionResults();

    expect(await suffragium.isVotePassed(voteId)).to.be.eq(false);
  });

  // Test vote failing when quorum is not reached
  it("should be able to cast more votes and reveal the result when the quorum is not reached", async () => {
    const voteId = 0;
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, MIN_QUORUM, "description"))
      .to.emit(suffragium, "VoteCreated")
      .withArgs(voteId);

    // Cast alternating yes/no votes
    for (const [index, instance] of Object.values(instances).entries()) {
      const input = instance.createEncryptedInput(await suffragium.getAddress(), Object.values(signers)[index].address);
      const encryptedInput = input.addBool(index % 2 ? 1 : 0).encrypt();
      const voterId = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + index.toString(16);
      const publicValues = abiCoder.encode(
        ["bytes32", "bytes32", "bytes32", "bool"],
        [FROM_DOMAIN_HASH, EMAIL_PUBLIC_KEY_HASH, voterId, true],
      );
      await expect(
        suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, `0x0${index}`),
      )
        .to.emit(suffragium, "VoteCasted")
        .withArgs(voteId);
    }

    // Reveal and verify vote results
    await mineNBlocks(VOTE_DURATION);
    await expect(suffragium.requestRevealVote(voteId)).to.emit(suffragium, "VoteRevealRequested").withArgs(voteId);
    await awaitAllDecryptionResults();

    expect(await suffragium.isVotePassed(voteId)).to.be.eq(false);
  });
});
