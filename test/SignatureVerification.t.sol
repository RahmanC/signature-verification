// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "forge-std/Test.sol"; 
import "../src/SignatureVerification.sol"; 
import "../src/MockERC20.sol"; 

contract SignatureVerificationTest is Test {
    SignatureVerification public sigVerification;
    MockERC20 public token; 

    address whitelisted;
    address notWhitelisted;

    function setUp() public {
        whitelisted = vm.addr(1); 
        notWhitelisted = vm.addr(2);

        token = new MockERC20("MockToken", "MTK");

        token.mint(address(this), 1000 ether);

        // Declare and initialize whitelistedAddresses array
         address[] memory whitelistedAddresses = new address[](1);
        whitelistedAddresses[0] = whitelisted;

        // Deploy SignatureVerification with whitelisted addresses
        sigVerification = new SignatureVerification(whitelistedAddresses, token);
    }

    function testValidSignature() public {
        uint256 amount = 10 ether;

        bytes32 messageHash = keccak256(abi.encodePacked(whitelisted, amount));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, messageHash); 

        vm.prank(whitelisted);
        sigVerification.verifyAndClaim(messageHash, abi.encodePacked(r, s, v), amount);

        // Assert that the token balance has been transferred
        assertEq(token.balanceOf(whitelisted), amount);
    }

    function testInvalidSignature() public {
        uint256 amount = 10 ether;

        // Sign a message using a non-whitelisted address
        bytes32 messageHash = keccak256(abi.encodePacked(notWhitelisted, amount));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, messageHash); 

        vm.prank(whitelisted);
        vm.expectRevert("Invalid signature");
        sigVerification.verifyAndClaim(messageHash, abi.encodePacked(r, s, v), amount);
    }

    function testNotWhitelisted() public {
        uint256 amount = 10 ether;

        // Sign a message
        bytes32 messageHash = keccak256(abi.encodePacked(notWhitelisted, amount));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, messageHash);

        
        vm.prank(notWhitelisted);
        vm.expectRevert("Not whitelisted");
        sigVerification.verifyAndClaim(messageHash, abi.encodePacked(r, s, v), amount);
    }
}
