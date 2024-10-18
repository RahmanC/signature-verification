// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./ERC20/IERC20.sol";

contract SignatureVerification {
    IERC20 public token;
    mapping(address => bool) public isWhitelisted;

    constructor(address[] memory whitelistedAddresses, IERC20 _token) {
        for (uint256 i = 0; i < whitelistedAddresses.length; i++) {
            isWhitelisted[whitelistedAddresses[i]] = true;
        }
        token = _token;
    }

    // Verify that the signature is valid and the signer is whitelisted
    function verifyAndClaim(
        bytes32 messageHash, 
        bytes memory signature, 
        uint256 amount
    ) public {
        require(isWhitelisted[msg.sender], "Not whitelisted");

        // Recover the signer's address from the signature
        address signer = recoverSigner(messageHash, signature);
        require(signer == msg.sender, "Invalid signature");

        // If all checks pass, transfer tokens
        token.transfer(msg.sender, amount);
    }

    // Recover the signer address from the signature
    function recoverSigner(bytes32 messageHash, bytes memory signature) public pure returns (address) {
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        return _recover(ethSignedMessageHash, signature);
    }

    function getEthSignedMessageHash(bytes32 messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }

    function _recover(bytes32 ethSignedMessageHash, bytes memory signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
