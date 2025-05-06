// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import '@openzeppelin/contracts/security/ReentrancyGuard.sol';
import './interfaces/ITreasury.sol';

/**
 * @title Treasury
 * @notice A minimalistic, production-grade treasury contract with on-chain 2-of-3 multi-sig authorization.
 *
 * This contract reflects the architectural and security standards expected from modern decentralized protocols.
 * All critical operations are protected by a two-signature threshold enforced on-chain, ensuring that no single
 * party has unilateral control over the funds.
 *
 * Features:
 * - Native ETH and ERC20 asset support
 * - Secure withdrawals via multi-sig validation
 * - Whitelisting mechanism for accepted tokens, updated only through validator consensus
 * - Transparent public view functions for integrations and audits
 *
 * The contract does not rely on upgradability patterns, third-party governance, or off-chain logic.
 * It serves as a verifiable, immutable, and auditable foundation for managing protocol reserves or treasury capital.
 */
contract Treasury is ReentrancyGuard, ITreasury {
  using SafeERC20 for IERC20;
  using ECDSA for bytes32;

  // ============================
  // ==== Multi-sig & Storage ===
  // ============================
  bool public paused;
  address[3] public validators;
  mapping(address => bool) public isValidator;
  mapping(address => bool) public isWhitelistedToken;
  uint256 public nonce;

  // ========================
  // ======== Actions =======
  // ========================
  bytes32 public constant PAUSE_ACTION = keccak256('PAUSE');
  bytes32 public constant UNPAUSE_ACTION = keccak256('UNPAUSE');
  bytes32 public constant WITHDRAW_ACTION = keccak256('WITHDRAW');
  bytes32 public constant WHITELIST_ACTION = keccak256('WHITELIST');

  // ========================
  // ======== Events ========
  // ========================
  event Paused(bytes32 hash);
  event Unpaused(bytes32 hash);
  event Deposit(address indexed token, address indexed from, uint256 amount);
  event Withdrawal(address indexed token, address indexed to, uint256 amount, bytes32 hash);
  event TokenWhitelisted(address indexed token, bytes32 hash);

  /**
   * @notice Initializes the contract with three validators.
   * @param _validators The array of validator addresses (must be length 3).
   */
  constructor(address[3] memory _validators) {
    for (uint8 i = 0; i < 3; i++) {
      address validator = _validators[i];
      require(validator != address(0), 'Treasury: invalid validator');
      validators[i] = validator;
      isValidator[validator] = true;
    }
  }

  /**
   * @notice Accepts ETH deposits to the contract.
   */
  receive() external payable {
    emit Deposit(address(0), msg.sender, msg.value);
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
    require(!paused, 'Treasury: already paused');
    require(block.timestamp <= deadline, 'Treasury: deadline expired');
    require(_nonce == nonce, 'Treasury: invalid nonce');

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
    require(paused, 'Treasury: not paused');
    require(block.timestamp <= deadline, 'Treasury: deadline expired');
    require(_nonce == nonce, 'Treasury: invalid nonce');

    bytes32 hash = getUnpauseHash(deadline, _nonce);
    verifyMultiSig(hash, signature);
    nonce++;

    paused = false;

    emit Unpaused(hash);
  }

  /**
   * @notice Deposits ERC20 tokens into the treasury.
   * @param token The address of the ERC20 token.
   * @param amount The amount of tokens to deposit.
   */
  function deposit(address token, uint256 amount) external nonReentrant {
    require(!paused, 'Treasury: paused');
    require(amount > 0, 'Treasury: invalid amount');
    require(isWhitelistedToken[token], 'Treasury: token not whitelisted');
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    emit Deposit(token, msg.sender, amount);
  }

  /**
   * @notice Withdraw ETH or ERC20 tokens with 2-of-3 validator signatures.
   * @param token The token address (use address(0) for ETH).
   * @param to The recipient address.
   * @param amount The amount to withdraw.
   * @param deadline Timestamp until when the signature is valid.
   * @param _nonce The current transaction nonce.
   * @param signature The signature from the second validator.
   */
  function withdraw(
    address token,
    address to,
    uint256 amount,
    uint256 deadline,
    uint256 _nonce,
    bytes calldata signature
  ) external nonReentrant {
    require(!paused, 'Treasury: paused');
    require(block.timestamp <= deadline, 'Treasury: deadline expired');
    require(to != address(0), 'Treasury: zero recipient');
    require(amount > 0, 'Treasury: zero amount');
    require(_nonce == nonce, 'Treasury: invalid nonce');
    require(token == address(0) || isWhitelistedToken[token], 'Treasury: token not whitelisted');

    bytes32 hash = getWithdrawHash(token, to, amount, deadline, _nonce);
    verifyMultiSig(hash, signature);
    nonce++;

    if (token == address(0)) {
      (bool success, ) = to.call{value: amount}('');
      require(success, 'Treasury: call execution failed');
    } else {
      IERC20(token).safeTransfer(to, amount);
    }

    emit Withdrawal(token, to, amount, hash);
  }

  /**
   * @notice Whitelist a token via multi-sig 2-of-3 validator signatures.
   * @param token The token address to whitelist.
   * @param deadline Signature expiration.
   * @param _nonce The expected nonce.
   * @param signature Signature from second validator.
   */
  function whitelistToken(
    address token,
    uint256 deadline,
    uint256 _nonce,
    bytes calldata signature
  ) external nonReentrant {
    require(!paused, 'Treasury: paused');
    require(block.timestamp <= deadline, 'Treasury: deadline expired');
    require(token != address(0), 'Treasury: zero token');
    require(_nonce == nonce, 'Treasury: invalid nonce');

    bytes32 hash = getWhitelistHash(token, deadline, _nonce);
    verifyMultiSig(hash, signature);
    nonce++;

    isWhitelistedToken[token] = true;

    emit TokenWhitelisted(token, hash);
  }

  /**
   * @notice Computes the hash of a withdrawal request.
   */
  function getWithdrawHash(
    address token,
    address to,
    uint256 amount,
    uint256 deadline,
    uint256 _nonce
  ) public view returns (bytes32) {
    return
      keccak256(
        abi.encode(
          WITHDRAW_ACTION,
          address(this),
          block.chainid,
          token,
          to,
          amount,
          deadline,
          _nonce
        )
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
   * @notice Computes the hash of a whitelist request.
   */
  function getWhitelistHash(
    address token,
    uint256 deadline,
    uint256 _nonce
  ) public view returns (bytes32) {
    return
      keccak256(
        abi.encode(WHITELIST_ACTION, address(this), block.chainid, token, deadline, _nonce)
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

    require(isValidator[signer], 'Treasury: invalid signer');
    require(signer != msg.sender, 'Treasury: same signer');
    require(isValidator[msg.sender], 'Treasury: sender not validator');
  }
}
