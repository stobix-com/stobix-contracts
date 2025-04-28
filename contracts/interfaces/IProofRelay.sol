// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IProofRelay {
  /// @notice Commits a proof of an action via 2-of-3 multi-sig authorization
  function commitProof(
    bytes32 action,
    bytes32 data,
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

  /// @notice Returns the hash used for committing a proof
  function getCommitProofHash(
    bytes32 action,
    bytes32 data,
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
