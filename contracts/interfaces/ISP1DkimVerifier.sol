// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

/// @title SP1DkimVerifier Interface
/// @author Alessadro Manfredi
/// @notice This contract is the interface for the SP1DkimVerifier contract.
interface ISP1DkimVerifier {
    error DkimSignatureVerificationFailed();
    error InvalidEmailPublicKeyHash();
    error InvalidFromDomainHash();

    function verifyDkim(bytes calldata registrationPublicValues, bytes calldata registrationProofBytes) external view;
}
