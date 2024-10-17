// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import { ISP1Verifier } from "./interfaces/ISP1Verifier.sol";
import { IIdentityManager } from "./interfaces/IIdentityManager.sol";

contract IdentityManager is IIdentityManager {
    bytes32 public constant IDENTITY_PUBLIC_KEY_HASH = bytes32(0); // TODO: set prod public key hash once generated

    address public immutable VERIFIER;
    bytes32 public immutable PROGRAM_V_KEY;
    bytes32 public immutable EMAIL_PUBLIC_KEY_HASH;
    bytes32 public immutable FROM_DOMAIN_HASH;

    constructor(address verifier, bytes32 programVKey, bytes32 emailPublicKeyHash, bytes32 fromDomainHash) {
        VERIFIER = verifier;
        PROGRAM_V_KEY = programVKey;
        EMAIL_PUBLIC_KEY_HASH = emailPublicKeyHash;
        FROM_DOMAIN_HASH = fromDomainHash;
    }

    /// @inheritdoc IIdentityManager
    function verifyProofAndGetVoterId(
        bytes calldata identityPublicValues,
        bytes calldata identityProofBytes
    ) public view returns (bytes32) {
        // TODO: use identityPublicValues and identityProofBytes
        ISP1Verifier(VERIFIER).verifyProof(PROGRAM_V_KEY, abi.encodePacked(""), abi.encodePacked(""));
        (
            bytes32 fromDomainHash,
            bytes32 emailPublicKeyHash,
            bytes32 identityPublicKeyHash,
            bytes32 voterId,
            bool verified
        ) = abi.decode(identityPublicValues, (bytes32, bytes32, bytes32, bytes32, bool));
        if (!verified) revert DkimSignatureVerificationFailed();
        if (emailPublicKeyHash != EMAIL_PUBLIC_KEY_HASH) revert InvalidEmailPublicKeyHash();
        if (fromDomainHash != FROM_DOMAIN_HASH) revert InvalidFromDomainHash();
        if (identityPublicKeyHash != IDENTITY_PUBLIC_KEY_HASH) revert InvalidVoterIdPublicKeyHash();
        return voterId;
    }
}
