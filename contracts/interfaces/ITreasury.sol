// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITreasury {
  /// @notice Deposits ERC20 tokens into the treasury
  function deposit(address token, uint256 amount) external;

  /// @notice Withdraws ETH or ERC20 tokens with 2-of-3 multi-sig authorization
  function withdraw(
    address token,
    address to,
    uint256 amount,
    uint256 deadline,
    uint256 nonce,
    bytes calldata signature
  ) external;

  // @notice Adds a token to the whitelist via multi-sig approval
  function whitelistToken(
    address token,
    uint256 deadline,
    uint256 nonce,
    bytes calldata signature
  ) external;

  /// @notice Returns the hash used for a withdrawal request
  function getWithdrawHash(
    address token,
    address to,
    uint256 amount,
    uint256 deadline,
    uint256 nonce
  ) external view returns (bytes32);

  /// @notice Returns the hash used for a token whitelist request
  function getWhitelistHash(
    address token,
    uint256 deadline,
    uint256 nonce
  ) external view returns (bytes32);
}
