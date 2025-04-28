import { expect } from 'chai'
import { ethers } from 'hardhat'
import { Signer } from 'ethers'
import { MockERC20, ProofRelay } from '../typechain-types'

describe('ProofRelay', () => {
  let proofRelay: ProofRelay
  let token: MockERC20
  let v1: Signer, v2: Signer, v3: Signer, user: Signer

  beforeEach(async () => {
    ;[v1, v2, v3, user] = await ethers.getSigners()

    const ProofRelay = await ethers.getContractFactory('ProofRelay')
    const MockERC20 = await ethers.getContractFactory('MockERC20')

    proofRelay = await ProofRelay.deploy([
      await v1.getAddress(),
      await v2.getAddress(),
      await v3.getAddress(),
    ])

    await proofRelay.waitForDeployment()

    token = await MockERC20.deploy('Mock', 'MOCK', ethers.parseUnits('1000', 18))

    await token.waitForDeployment()
  })

  describe('constructor()', () => {
    it('should revert if any validator is zero address', async () => {
      const ProofRelay = await ethers.getContractFactory('ProofRelay')

      await expect(
        ProofRelay.deploy([ethers.ZeroAddress, await v1.getAddress(), await v2.getAddress()])
      ).to.be.revertedWith('ProofRelay: invalid validator')
    })
  })

  describe('pause()', () => {
    it('should pause the contract', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await proofRelay.connect(v1).pause(deadline, nonce, signature)

      expect(await proofRelay.paused()).to.equal(true)
    })

    it('should revert if already paused', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await proofRelay.connect(v1).pause(deadline, nonce, signature)

      await expect(
        proofRelay.connect(v1).pause(deadline, nonce + 1n, signature)
      ).to.be.revertedWith('ProofRelay: already paused')
    })

    it('should revert if deadline expired', async () => {
      const deadline = Math.floor(Date.now() / 1000) - 10
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(proofRelay.connect(v1).pause(deadline, nonce, signature)).to.be.revertedWith(
        'ProofRelay: deadline expired'
      )
    })

    it('should revert on invalid nonce', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        proofRelay.connect(v1).pause(deadline, nonce + 1n, signature)
      ).to.be.revertedWith('ProofRelay: invalid nonce')
    })
  })

  describe('unpause()', () => {
    beforeEach(async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await proofRelay.connect(v1).pause(deadline, nonce, signature)
    })

    it('should unpause the contract', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getUnpauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await proofRelay.connect(v1).unpause(deadline, nonce, signature)

      expect(await proofRelay.paused()).to.equal(false)
    })

    it('should revert if not paused', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getUnpauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await proofRelay.connect(v1).unpause(deadline, nonce, signature)

      await expect(
        proofRelay.connect(v1).unpause(deadline, nonce + 1n, signature)
      ).to.be.revertedWith('ProofRelay: not paused')
    })

    it('should revert if deadline expired', async () => {
      const deadline = Math.floor(Date.now() / 1000) - 10
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getUnpauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(proofRelay.connect(v1).unpause(deadline, nonce, signature)).to.be.revertedWith(
        'ProofRelay: deadline expired'
      )
    })

    it('should revert on invalid nonce', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getUnpauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        proofRelay.connect(v1).unpause(deadline, nonce + 1n, signature)
      ).to.be.revertedWith('ProofRelay: invalid nonce')
    })
  })

  describe('commitProof()', () => {
    let action, salt, data

    beforeEach(async () => {
      action = ethers.keccak256(ethers.toUtf8Bytes('DEPOSIT'))

      salt = ethers.keccak256(ethers.randomBytes(32))

      data = ethers.keccak256(
        ethers.solidityPacked(
          ['address', 'address', 'uint256', 'uint256', 'bytes32'],
          [
            await user.getAddress(),
            await token.getAddress(),
            ethers.parseUnits('1000', 18),
            Math.floor(Date.now() / 1000),
            salt,
          ]
        )
      )
    })

    it('should commit proof', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getCommitProofHash(action!, data!, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      const tx = await proofRelay
        .connect(v1)
        .commitProof(action!, data!, deadline, nonce, signature)

      await expect(tx).to.emit(proofRelay, 'ProofCommitted').withArgs(action!, data!, nonce, hash)

      expect(await proofRelay.nonce()).to.equal(1)
    })

    it('should revert if deadline expired', async () => {
      const deadline = Math.floor(Date.now() / 1000) - 10
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getCommitProofHash(action!, data!, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        proofRelay.connect(v1).commitProof(action!, data!, deadline, nonce, signature)
      ).to.be.revertedWith('ProofRelay: deadline expired')
    })

    it('should revert on reused nonce', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getCommitProofHash(action!, data!, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await proofRelay.connect(v1).commitProof(action!, data!, deadline, nonce, signature)

      await expect(
        proofRelay.connect(v1).commitProof(action!, data!, deadline, nonce, signature)
      ).to.be.revertedWith('ProofRelay: invalid nonce')
    })

    it('should revert if deadline expired', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const signature = '0xdeadbeef' + '0'.repeat(130 - 10)

      await expect(
        proofRelay.connect(v1).commitProof(action!, data!, deadline, nonce, signature)
      ).to.be.revertedWith('ECDSA: invalid signature length')
    })

    it('should revert if signature is from non-validator', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getCommitProofHash(action!, data!, deadline, nonce)
      const signature = await user.signMessage(ethers.getBytes(hash))

      await expect(
        proofRelay.connect(v1).commitProof(action!, data!, deadline, nonce, signature)
      ).to.be.revertedWith('ProofRelay: invalid signer')
    })

    it('should revert if signer and sender are the same', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getCommitProofHash(action!, data!, deadline, nonce)
      const signature = await v1.signMessage(ethers.getBytes(hash))

      await expect(
        proofRelay.connect(v1).commitProof(action!, data!, deadline, nonce, signature)
      ).to.be.revertedWith('ProofRelay: same signer')
    })

    it('should revert if caller is not a validator', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await proofRelay.nonce()

      const hash = await proofRelay.getCommitProofHash(action!, data!, deadline, nonce)
      const signature = await v1.signMessage(ethers.getBytes(hash))

      await expect(
        proofRelay.connect(user).commitProof(action!, data!, deadline, nonce, signature)
      ).to.be.revertedWith('ProofRelay: sender not validator')
    })

    it('should revert if paused', async () => {
      let deadline = Math.floor(Date.now() / 1000) + 3600
      let nonce = await proofRelay.nonce()

      let hash = await proofRelay.getPauseHash(deadline, nonce)
      let signature = await v2.signMessage(ethers.getBytes(hash))

      await proofRelay.connect(v1).pause(deadline, nonce, signature)

      deadline = Math.floor(Date.now() / 1000) + 3600
      nonce = await proofRelay.nonce()

      hash = await proofRelay.getCommitProofHash(action!, data!, deadline, nonce)
      signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        proofRelay.connect(v1).commitProof(action!, data!, deadline, nonce, signature)
      ).to.be.revertedWith('ProofRelay: paused')
    })
  })

  describe('getValidators()', () => {
    it('should return validators correctly', async () => {
      const validators = await proofRelay.getValidators()

      expect(validators).to.deep.equal([
        await v1.getAddress(),
        await v2.getAddress(),
        await v3.getAddress(),
      ])
    })
  })
})
