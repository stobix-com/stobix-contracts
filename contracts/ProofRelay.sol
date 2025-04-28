// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import '@openzeppelin/contracts/security/ReentrancyGuard.sol';

/**
 * @title ProofRelay
 * @notice A minimalistic, production-grade proof publishing contract with on-chain 2-of-3 multi-sig authorization.
 *
 * This contract acts as a public, verifiable, and immutable record of key protocol actions,
 * such as deposits, withdrawals, positions, and rewards, without exposing sensitive user data.
 *
 * Features:
 * - Secure proof commits with 2-of-3 multi-sig validation
 * - Strict nonces to guarantee ordering and uniqueness
 * - Pausing mechanism for operational control
 * - Transparent public view functions for audits and monitoring
 *
 * The contract does not rely on upgradability patterns, third-party governance, or off-chain logic.
 */
contract ProofRelay is ReentrancyGuard {
  using ECDSA for bytes32;

  // ============================
  // ==== Multi-sig & Storage ===
  // ============================
  bool public paused;
  address[3] public validators;
  mapping(address => bool) public isValidator;
  uint256 public nonce;

  // ========================
  // ======== Actions =======
  // ========================
  bytes32 public constant PAUSE_ACTION = keccak256('PAUSE');
  bytes32 public constant UNPAUSE_ACTION = keccak256('UNPAUSE');
  bytes32 public constant COMMIT_PROOF_ACTION = keccak256('COMMIT_PROOF');

  // ========================
  // ======== Events ========
  // ========================
  event Paused(bytes32 hash);
  event Unpaused(bytes32 hash);
  event ProofCommitted(bytes32 indexed action, bytes32 indexed data, uint256 indexed nonce, bytes32 hash);

  /**
   * @notice Initializes the contract with three validators.
   * @param _validators The array of validator addresses (must be length 3).
   */
  constructor(address[3] memory _validators) {
    for (uint8 i = 0; i < 3; i++) {
      address validator = _validators[i];
      require(validator != address(0), 'ProofRelay: invalid validator');
      validators[i] = validator;
      isValidator[validator] = true;
    }
  }

  /**
   * @notice Pauses the contract via 2-of-3 multi-sig signatures.
   * @param deadline Signature expiration.
   * @param _nonce Expected nonce.
   * @param signature Signature from second validator.
   */
  function pause(
    uint256 deadline,
    uint256 _nonce,
    bytes calldata signature
  ) external nonReentrant {
    require(!paused, 'ProofRelay: already paused');
    require(block.timestamp <= deadline, 'ProofRelay: deadline expired');
    require(_nonce == nonce, 'ProofRelay: invalid nonce');

    bytes32 hash = getPauseHash(deadline, _nonce);
    verifyMultiSig(hash, signature);
    nonce++;

    paused = true;

    emit Paused(hash);
  }

  /**
   * @notice Unpauses the contract via 2-of-3 multi-sig signatures.
   * @param deadline Signature expiration.
   * @param _nonce Expected nonce.
   * @param signature Signature from second validator.
   */
  function unpause(
    uint256 deadline,
    uint256 _nonce,
    bytes calldata signature
  ) external nonReentrant {
    require(paused, 'ProofRelay: not paused');
    require(block.timestamp <= deadline, 'ProofRelay: deadline expired');
    require(_nonce == nonce, 'ProofRelay: invalid nonce');

    bytes32 hash = getUnpauseHash(deadline, _nonce);
    verifyMultiSig(hash, signature);
    nonce++;

    paused = false;

    emit Unpaused(hash);
  }

  /**
   * @notice Commits a proof of an action via 2-of-3 multi-sig signatures.
   * @param action The action type identifier.
   * @param data The hash of the action's payload.
   * @param deadline Signature expiration.
   * @param _nonce Expected nonce.
   * @param signature Signature from second validator.
   */
  function commitProof(
    bytes32 action,
    bytes32 data,
    uint256 deadline,
    uint256 _nonce,
    bytes calldata signature
  ) external nonReentrant {
    require(!paused, 'ProofRelay: paused');
    require(block.timestamp <= deadline, 'ProofRelay: deadline expired');
    require(_nonce == nonce, 'ProofRelay: invalid nonce');

    bytes32 hash = getCommitProofHash(action, data, deadline, _nonce);
    verifyMultiSig(hash, signature);
    nonce++;

    emit ProofCommitted(action, data, _nonce, hash);
  }

  /**
   * @notice Computes the hash of a commitProof action.
   */
  function getCommitProofHash(
    bytes32 action,
    bytes32 data,
    uint256 deadline,
    uint256 _nonce
  ) public view returns (bytes32) {
    return keccak256(
      abi.encode(COMMIT_PROOF_ACTION, address(this), block.chainid, action, data, deadline, _nonce)
    );
  }

  /**
   * @notice Computes the hash of a pause request.
   */
  function getPauseHash(
    uint256 deadline,
    uint256 _nonce
  ) public view returns (bytes32) {
    return keccak256(
      abi.encode(PAUSE_ACTION, address(this), block.chainid, deadline, _nonce)
    );
  }

  /**
   * @notice Computes the hash of an unpause request.
   */
  function getUnpauseHash(
    uint256 deadline,
    uint256 _nonce
  ) public view returns (bytes32) {
    return keccak256(
      abi.encode(UNPAUSE_ACTION, address(this), block.chainid, deadline, _nonce)
    );
  }

  /**
   * @notice Returns the list of three validators.
   */
  function getValidators() external view returns (address[3] memory) {
    return validators;
  }

  /**
   * @notice Verifies a validator signature against the transaction hash.
   */
  function verifyMultiSig(bytes32 hash, bytes calldata signature) internal view {
    address signer = hash.toEthSignedMessageHash().recover(signature);

    require(isValidator[signer], 'ProofRelay: invalid signer');
    require(signer != msg.sender, 'ProofRelay: same signer');
    require(isValidator[msg.sender], 'ProofRelay: sender not validator');
  }
}
