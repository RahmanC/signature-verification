// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "./ERC20/ERC20.sol"; 

contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    // Custom mint function for testing
    function mint(address to, uint256 amount) public {
        _mint(to, amount); 
    }
}
