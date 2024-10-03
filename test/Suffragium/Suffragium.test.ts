import { expect } from "chai";
import { ethers } from "hardhat";

import { SP1MockVerifier, Suffragium } from "../../types";
import { awaitAllDecryptionResults } from "../asyncDecrypt";
import { createInstances } from "../instance";
import { Signers, getSigners, initSigners } from "../signers";
import { FhevmInstances } from "../types";
import { mineNBlocks } from "../utils";

const PROGRAM_VERIFICATION_KEY = "0x0000000000000000000000000000000000000000000000000000000000000000";
const VOTE_DURATION = 100; // blocks
const EMAIL_PUBLIC_KEY_HASH = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const abiCoder = new ethers.AbiCoder();

describe("Suffragium", function () {
  let signers: Signers;
  let verifier: SP1MockVerifier;
  let suffragium: Suffragium;
  let instances: FhevmInstances;

  before(async () => {
    await initSigners();
    signers = await getSigners();
  });

  beforeEach(async () => {
    const Suffragium = await ethers.getContractFactory("Suffragium");
    const SP1MockVerifier = await ethers.getContractFactory("SP1MockVerifier");

    verifier = await SP1MockVerifier.deploy();
    suffragium = await Suffragium.deploy(await verifier.getAddress(), PROGRAM_VERIFICATION_KEY, EMAIL_PUBLIC_KEY_HASH);
    instances = await createInstances(signers);
  });

  it("should be able to cast a vote", async () => {
    const voteId = 0;
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, "description")).to.emit(suffragium, "VoteCreated").withArgs(voteId);

    const input = instances.alice.createEncryptedInput(await suffragium.getAddress(), signers.alice.address);
    const encryptedInput = input.add64(1).encrypt();
    const publicValues = abiCoder.encode(["bytes32"], [EMAIL_PUBLIC_KEY_HASH]);
    await expect(suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, "0x"))
      .to.emit(suffragium, "VoteCasted")
      .withArgs(voteId);
  });

  it("should not be able to cast a vote using the same proof more than once", async () => {
    const voteId = 0;
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, "description")).to.emit(suffragium, "VoteCreated").withArgs(voteId);

    const input = instances.alice.createEncryptedInput(await suffragium.getAddress(), signers.alice.address);
    const encryptedInput = input.add64(1).encrypt();
    const publicValues = abiCoder.encode(["bytes32"], [EMAIL_PUBLIC_KEY_HASH]);
    await suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, "0x");
    await expect(
      suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, "0x"),
    ).to.be.revertedWithCustomError(suffragium, "AlreadyVoted");
  });

  it("should be able to cast more votes and reveal the result when the quorum is reached", async () => {
    const voteId = 0;
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, "description")).to.emit(suffragium, "VoteCreated").withArgs(voteId);

    for (const [index, instance] of Object.values(instances).entries()) {
      const input = instance.createEncryptedInput(await suffragium.getAddress(), Object.values(signers)[index].address);
      const encryptedInput = input.add64(!Boolean(index % 2) ? 1 : 0).encrypt();
      const publicValues = abiCoder.encode(["bytes32"], [EMAIL_PUBLIC_KEY_HASH]);
      await expect(
        suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, `0x0${index}`),
      )
        .to.emit(suffragium, "VoteCasted")
        .withArgs(voteId);
    }

    await mineNBlocks(VOTE_DURATION);
    await expect(suffragium.requestRevealVote(voteId)).to.emit(suffragium, "VoteRevealRequested").withArgs(voteId);
    await awaitAllDecryptionResults();

    expect(await suffragium.isVotePassed(voteId)).to.be.eq(true);
  });

  it("should be able to cast more votes and reveal the result when the quorum is not reached", async () => {
    const voteId = 0;
    const endBlock = (await ethers.provider.getBlockNumber()) + VOTE_DURATION;
    await expect(suffragium.createVote(endBlock, "description")).to.emit(suffragium, "VoteCreated").withArgs(voteId);

    for (const [index, instance] of Object.values(instances).entries()) {
      const input = instance.createEncryptedInput(await suffragium.getAddress(), Object.values(signers)[index].address);
      const encryptedInput = input.add64(Boolean(index % 2) ? 1 : 0).encrypt();
      const publicValues = abiCoder.encode(["bytes32"], [EMAIL_PUBLIC_KEY_HASH]);
      await expect(
        suffragium.castVote(voteId, encryptedInput.handles[0], encryptedInput.inputProof, publicValues, `0x0${index}`),
      )
        .to.emit(suffragium, "VoteCasted")
        .withArgs(voteId);
    }

    await mineNBlocks(VOTE_DURATION);
    await expect(suffragium.requestRevealVote(voteId)).to.emit(suffragium, "VoteRevealRequested").withArgs(voteId);
    await awaitAllDecryptionResults();

    expect(await suffragium.isVotePassed(voteId)).to.be.eq(false);
  });
});
