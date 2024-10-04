// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import { ISP1Verifier } from "./interfaces/ISP1Verifier.sol";
import { ISP1DkimVerifier } from "./interfaces/ISP1DkimVerifier.sol";

contract SP1DkimVerifier is ISP1DkimVerifier {
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

    /// @inheritdoc ISP1DkimVerifier
    function verifyDkim(bytes calldata registrationPublicValues, bytes calldata registrationProofBytes) public view {
        // TODO: use registrationPublicValues and registrationProofBytes
        ISP1Verifier(VERIFIER).verifyProof(PROGRAM_V_KEY, abi.encodePacked(""), abi.encodePacked(""));
        (bytes32 fromDomainHash, bytes32 emailPublicKeyHash, bool verified) = abi.decode(
            registrationPublicValues,
            (bytes32, bytes32, bool)
        );
        if (!verified) revert DkimSignatureVerificationFailed();
        if (emailPublicKeyHash != EMAIL_PUBLIC_KEY_HASH) revert InvalidEmailPublicKeyHash();
        if (fromDomainHash != FROM_DOMAIN_HASH) revert InvalidFromDomainHash();
    }
}
