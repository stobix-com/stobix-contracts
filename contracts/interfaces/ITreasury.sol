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

  /// @notice Adds a token to the whitelist via multi-sig authorization
  function whitelistToken(
    address token,
    uint256 deadline,
    uint256 nonce,
    bytes calldata signature
  ) external;

  /// @notice Pauses the contract via multi-sig authorization
  function pause(
    uint256 deadline,
    uint256 nonce,
    bytes calldata signature
  ) external;

  /// @notice Unpauses the contract via multi-sig authorization
  function unpause(
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

  /// @notice Returns the hash used for a pause request
  function getPauseHash(
    uint256 deadline,
    uint256 nonce
  ) external view returns (bytes32);

  /// @notice Returns the hash used for an unpause request
  function getUnpauseHash(
    uint256 deadline,
    uint256 nonce
  ) external view returns (bytes32);

  /// @notice Returns the list of validator addresses
  function getValidators() external view returns (address[3] memory);

  /// @notice Returns whether the contract is paused
  function paused() external view returns (bool);

  /// @notice Returns the current nonce value
  function nonce() external view returns (uint256);
}
