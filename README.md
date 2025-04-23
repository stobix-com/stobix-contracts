# ⚡ Stobix Core Contracts

Stobix is a next-gen crypto trading platform built for privacy, performance, and user control. We bring together high-leverage futures (up to 100x), yield-optimized investment tools, and smart decision-making features — all in one seamless, wallet-first interface. No fluff, no friction — just clean, fast, confident trading powered by Web3.

The system is designed with decentralization, self-custody, and validator-based governance at its core. There are no centralized owners, upgradeability patterns, or privileged access — every critical action is enforced by consensus.

## Design Principles

### Validator-Based Multi-Sig (2-of-3)

All sensitive operations (withdrawals, token permissions) require two out of three independent validator signatures. This ensures that no single entity can act unilaterally, and that consensus is enforced on-chain without reliance on external infrastructure.

### Decentralized Treasury Control

The protocol architecture eliminates single points of control. Assets are managed by an immutable treasury contract, with all outbound flows subject to validator consensus. There is no ownership role, no upgrade path, and no centralized authority.

### Composable and Gas-Efficient

The contracts are optimized for composability with external systems. Hashes are computed on-chain using domain separation, deadlines, and unique nonces, providing strong guarantees against replay attacks and signature reuse.

## Security Model

- **Immutable architecture:** All contracts are non-upgradeable and deployed without admin controls.
- **Validator-based governance:** Token whitelisting and fund movements require dual approval from designated validators.
- **Nonce-based replay protection:** All sensitive operations include a nonce and strict deadline to prevent reuse.
- **Fully self-contained logic:** No reliance on external contracts or off-chain components for core functionality.
- **Reentrancy-resistant by design:** All state-mutating functions are protected with non-reentrancy guards.

## Development

This repository contains production-ready smart contracts written with clarity, safety, and minimalism in mind. All contracts follow modern best practices for decentralized protocol design and are covered with comprehensive unit tests and gas profiling.

## License

The code in this repository is released under the MIT License.
