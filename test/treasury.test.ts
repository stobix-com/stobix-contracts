import { expect } from 'chai'
import { ethers } from 'hardhat'
import { Signer } from 'ethers'
import { Treasury, MockERC20 } from '../typechain-types'

describe('Treasury', () => {
  let treasury: Treasury
  let token: MockERC20
  let token2: MockERC20
  let v1: Signer, v2: Signer, v3: Signer, user: Signer

  beforeEach(async () => {
    ;[v1, v2, v3, user] = await ethers.getSigners()

    const Treasury = await ethers.getContractFactory('Treasury')
    const MockERC20 = await ethers.getContractFactory('MockERC20')

    treasury = await Treasury.deploy([
      await v1.getAddress(),
      await v2.getAddress(),
      await v3.getAddress(),
    ])

    await treasury.waitForDeployment()

    token = await MockERC20.deploy('Mock', 'MOCK', ethers.parseUnits('1000', 18))
    token2 = await MockERC20.deploy('Mock2', 'MOCK2', ethers.parseUnits('1000', 18))

    await token.waitForDeployment()
    await token2.waitForDeployment()
  })

  describe('receive()', () => {
    it('should receive eth', async () => {
      const tx = await v1.sendTransaction({
        to: treasury.target,
        value: ethers.parseEther('1'),
      })

      await expect(tx)
        .to.emit(treasury, 'Deposit')
        .withArgs(ethers.ZeroAddress, await v1.getAddress(), ethers.parseEther('1'))

      const balance = await ethers.provider.getBalance(treasury.target)

      expect(balance).to.equal(ethers.parseEther('1'))
    })
  })

  describe('constructor()', () => {
    it('should revert if any validator is zero address', async () => {
      const Treasury = await ethers.getContractFactory('Treasury')

      await expect(
        Treasury.deploy([ethers.ZeroAddress, await v1.getAddress(), await v2.getAddress()])
      ).to.be.revertedWith('Treasury: invalid validator')
    })
  })

  describe('pause()', () => {
    it('should pause the contract', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury.connect(v1).pause(deadline, nonce, signature)

      expect(await treasury.paused()).to.equal(true)
    })

    it('should revert if already paused', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury.connect(v1).pause(deadline, nonce, signature)

      await expect(treasury.connect(v1).pause(deadline, nonce + 1n, signature)).to.be.revertedWith(
        'Treasury: already paused'
      )
    })

    it('should revert if deadline expired', async () => {
      const deadline = Math.floor(Date.now() / 1000) - 10
      const nonce = await treasury.nonce()

      const hash = await treasury.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(treasury.connect(v1).pause(deadline, nonce, signature)).to.be.revertedWith(
        'Treasury: deadline expired'
      )
    })

    it('should revert on invalid nonce', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(treasury.connect(v1).pause(deadline, nonce + 1n, signature)).to.be.revertedWith(
        'Treasury: invalid nonce'
      )
    })
  })

  describe('unpause()', () => {
    beforeEach(async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury.connect(v1).pause(deadline, nonce, signature)
    })

    it('should unpause the contract', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getUnpauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury.connect(v1).unpause(deadline, nonce, signature)

      expect(await treasury.paused()).to.equal(false)
    })

    it('should revert if not paused', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getUnpauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury.connect(v1).unpause(deadline, nonce, signature)

      await expect(
        treasury.connect(v1).unpause(deadline, nonce + 1n, signature)
      ).to.be.revertedWith('Treasury: not paused')
    })

    it('should revert if deadline expired', async () => {
      const deadline = Math.floor(Date.now() / 1000) - 10
      const nonce = await treasury.nonce()

      const hash = await treasury.getUnpauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(treasury.connect(v1).unpause(deadline, nonce, signature)).to.be.revertedWith(
        'Treasury: deadline expired'
      )
    })

    it('should revert on invalid nonce', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getUnpauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).unpause(deadline, nonce + 1n, signature)
      ).to.be.revertedWith('Treasury: invalid nonce')
    })
  })

  describe('deposit()', () => {
    beforeEach(async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWhitelistHash(await token.getAddress(), deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury
        .connect(v1)
        .whitelistToken(await token.getAddress(), deadline, nonce, signature)
    })

    it('should deposit tokens', async () => {
      const amount = ethers.parseUnits('10', 18)
      await token.approve(treasury, amount)

      const tx = await treasury.deposit(await token.getAddress(), amount)

      await expect(tx)
        .to.emit(treasury, 'Deposit')
        .withArgs(await token.getAddress(), await v1.getAddress(), amount)

      const balance = await token.balanceOf(treasury.getAddress())

      expect(balance).to.equal(amount)
    })

    it('should revert with zero amount', async () => {
      await expect(treasury.deposit(await token.getAddress(), 0)).to.be.revertedWith(
        'Treasury: invalid amount'
      )
    })

    it('should revert with not whitelisted token', async () => {
      await expect(treasury.deposit(await token2.getAddress(), 1)).to.be.revertedWith(
        'Treasury: token not whitelisted'
      )
    })

    it('should revert if user has insufficient balance', async () => {
      const amount = ethers.parseUnits('1000000', 18)
      await token.approve(treasury, amount)

      await expect(treasury.deposit(await token.getAddress(), amount)).to.be.revertedWith(
        'ERC20: transfer amount exceeds balance'
      )
    })

    it('should revert if user has not approved tokens', async () => {
      const amount = ethers.parseUnits('10', 18)

      await expect(treasury.deposit(await token.getAddress(), amount)).to.be.revertedWith(
        'ERC20: insufficient allowance'
      )
    })

    it('should revert if paused', async () => {
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getPauseHash(deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury.connect(v1).pause(deadline, nonce, signature)

      const amount = ethers.parseUnits('10', 18)

      await expect(treasury.deposit(await token.getAddress(), amount)).to.be.revertedWith(
        'Treasury: paused'
      )
    })
  })

  describe('withdraw()', () => {
    beforeEach(async () => {
      await v1.sendTransaction({
        to: treasury.target,
        value: ethers.parseEther('10'),
      })
    })

    it('should withdraw', async () => {
      const to = await user.getAddress()
      const amount = ethers.parseEther('1')
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const balance = await ethers.provider.getBalance(to)

      const params = [ethers.ZeroAddress, to, amount, deadline, nonce]
      const hash = await treasury.getWithdrawHash(...params)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      const tx = await treasury.connect(v1).withdraw(...params, signature)

      await expect(tx)
        .to.emit(treasury, 'Withdrawal')
        .withArgs(ethers.ZeroAddress, to, amount, hash)

      const _balance = await ethers.provider.getBalance(to)
      const _nonce = await treasury.nonce()

      expect(_balance - balance).to.equal(amount)
      expect(_nonce).to.equal(1)
    })

    it('should withdraw tokens', async () => {
      await token.transfer(await treasury.getAddress(), ethers.parseUnits('100', 18))

      const whitelistDeadline = Math.floor(Date.now() / 1000) + 3600
      const whitelistNonce = await treasury.nonce()

      const whitelistHash = await treasury.getWhitelistHash(
        await token.getAddress(),
        whitelistDeadline,
        whitelistNonce
      )
      const whitelistSignature = await v2.signMessage(ethers.getBytes(whitelistHash))

      await treasury
        .connect(v1)
        .whitelistToken(
          await token.getAddress(),
          whitelistDeadline,
          whitelistNonce,
          whitelistSignature
        )

      const to = await user.getAddress()
      const amount = ethers.parseUnits('10', 18)

      const withdrawNonce = await treasury.nonce()
      const withdrawDeadline = Math.floor(Date.now() / 1000) + 3600

      const withdrawHash = await treasury.getWithdrawHash(
        await token.getAddress(),
        to,
        amount,
        withdrawDeadline,
        withdrawNonce
      )
      const withdrawSignature = await v2.signMessage(ethers.getBytes(withdrawHash))

      const balance = await token.balanceOf(to)

      const tx = await treasury
        .connect(v1)
        .withdraw(
          await token.getAddress(),
          to,
          amount,
          withdrawDeadline,
          withdrawNonce,
          withdrawSignature
        )

      await expect(tx)
        .to.emit(treasury, 'Withdrawal')
        .withArgs(await token.getAddress(), to, amount, withdrawHash)

      const _balance = await token.balanceOf(to)
      const _nonce = await treasury.nonce()

      expect(_balance - balance).to.equal(amount)
      expect(_nonce).to.equal(2)
    })

    it('should revert if deadline expired', async () => {
      const to = await user.getAddress()
      const amount = ethers.parseEther('1')
      const deadline = Math.floor(Date.now() / 1000) - 10
      const nonce = await treasury.nonce()

      const hash = await treasury.getWithdrawHash(ethers.ZeroAddress, to, amount, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).withdraw(ethers.ZeroAddress, to, amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: deadline expired')
    })

    it('should revert with zero amount', async () => {
      const to = await user.getAddress()
      const amount = ethers.parseEther('0')
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWithdrawHash(ethers.ZeroAddress, to, amount, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).withdraw(ethers.ZeroAddress, to, amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: zero amount')
    })

    it('should revert with zero recipient', async () => {
      const amount = ethers.parseEther('1')
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWithdrawHash(
        ethers.ZeroAddress,
        ethers.ZeroAddress,
        amount,
        deadline,
        nonce
      )
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury
          .connect(v1)
          .withdraw(ethers.ZeroAddress, ethers.ZeroAddress, amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: zero recipient')
    })

    it('should revert for non-whitelisted token', async () => {
      const to = await user.getAddress()
      const amount = ethers.parseUnits('10', 18)
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWithdrawHash(
        await token.getAddress(),
        to,
        amount,
        deadline,
        nonce
      )
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury
          .connect(v1)
          .withdraw(await token.getAddress(), to, amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: token not whitelisted')
    })

    it('should revert if balance is insufficient', async () => {
      const to = await user.getAddress()
      const amount = ethers.parseEther('100')
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWithdrawHash(ethers.ZeroAddress, to, amount, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).withdraw(ethers.ZeroAddress, to, amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: call execution failed')
    })

    it('should revert on reused nonce', async () => {
      const to = await user.getAddress()
      const amount = ethers.parseEther('1')
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWithdrawHash(ethers.ZeroAddress, to, amount, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury
        .connect(v1)
        .withdraw(ethers.ZeroAddress, to, amount, deadline, nonce, signature)

      await expect(
        treasury.connect(v1).withdraw(ethers.ZeroAddress, to, amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: invalid nonce')
    })

    it('should revert if signature is invalid', async () => {
      const to = await user.getAddress()
      const amount = ethers.parseEther('1')
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const signature = '0xdeadbeef' + '0'.repeat(130 - 10)

      await expect(
        treasury.connect(v1).withdraw(ethers.ZeroAddress, to, amount, deadline, nonce, signature)
      ).to.be.revertedWith('ECDSA: invalid signature length')
    })

    it('should revert if signature is from non-validator', async () => {
      const to = await user.getAddress()
      const amount = ethers.parseEther('1')
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWithdrawHash(ethers.ZeroAddress, to, amount, deadline, nonce)
      const signature = await user.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).withdraw(ethers.ZeroAddress, to, amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: invalid signer')
    })

    it('should revert if signer and sender are the same', async () => {
      const amount = ethers.parseEther('1')
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWithdrawHash(
        ethers.ZeroAddress,
        await v1.getAddress(),
        amount,
        deadline,
        nonce
      )
      const signature = await v1.signMessage(ethers.getBytes(hash))

      await expect(
        treasury
          .connect(v1)
          .withdraw(ethers.ZeroAddress, await v1.getAddress(), amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: same signer')
    })

    it('should revert if caller is not a validator', async () => {
      const to = await v1.getAddress()
      const amount = ethers.parseEther('1')
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWithdrawHash(ethers.ZeroAddress, to, amount, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(user).withdraw(ethers.ZeroAddress, to, amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: sender not validator')
    })

    it('should revert if paused', async () => {
      let deadline = Math.floor(Date.now() / 1000) + 3600
      let nonce = await treasury.nonce()

      let hash = await treasury.getPauseHash(deadline, nonce)
      let signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury.connect(v1).pause(deadline, nonce, signature)

      const to = await user.getAddress()
      const amount = ethers.parseEther('1')

      deadline = Math.floor(Date.now() / 1000) + 3600
      nonce = await treasury.nonce()

      hash = await treasury.getWithdrawHash(ethers.ZeroAddress, to, amount, deadline, nonce)
      signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).withdraw(ethers.ZeroAddress, to, amount, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: paused')
    })
  })

  describe('whitelistToken()', () => {
    it('should whitelist token', async () => {
      const address = await token.getAddress()
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWhitelistHash(address, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      const tx = await treasury.connect(v1).whitelistToken(address, deadline, nonce, signature)

      await expect(tx).to.emit(treasury, 'TokenWhitelisted').withArgs(address, hash)

      expect(await treasury.isWhitelistedToken(address)).to.equal(true)
    })

    it('should revert if deadline expired', async () => {
      const address = await token.getAddress()
      const deadline = Math.floor(Date.now() / 1000) - 10
      const nonce = await treasury.nonce()

      const hash = await treasury.getWhitelistHash(address, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).whitelistToken(address, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: deadline expired')
    })

    it('should revert with zero token', async () => {
      const address = ethers.ZeroAddress
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWhitelistHash(address, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).whitelistToken(address, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: zero token')
    })

    it('should revert on reused nonce', async () => {
      const address = await token.getAddress()
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWhitelistHash(address, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury.connect(v1).whitelistToken(address, deadline, nonce, signature)

      await expect(
        treasury.connect(v1).whitelistToken(address, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: invalid nonce')
    })

    it('should revert if signature is invalid', async () => {
      const address = await token.getAddress()
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const signature = '0xdeadbeef' + '0'.repeat(130 - 10)

      await expect(
        treasury.connect(v1).whitelistToken(address, deadline, nonce, signature)
      ).to.be.revertedWith('ECDSA: invalid signature length')
    })

    it('should revert if signature is from non-validator', async () => {
      const address = await token.getAddress()
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWhitelistHash(address, deadline, nonce)
      const signature = await user.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).whitelistToken(address, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: invalid signer')
    })

    it('should revert if signer and sender are the same', async () => {
      const address = await token.getAddress()
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWhitelistHash(address, deadline, nonce)
      const signature = await v1.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).whitelistToken(address, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: same signer')
    })

    it('should revert if caller is not a validator', async () => {
      const address = await token.getAddress()
      const deadline = Math.floor(Date.now() / 1000) + 3600
      const nonce = await treasury.nonce()

      const hash = await treasury.getWhitelistHash(address, deadline, nonce)
      const signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(user).whitelistToken(address, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: sender not validator')
    })

    it('should revert if paused', async () => {
      let deadline = Math.floor(Date.now() / 1000) + 3600
      let nonce = await treasury.nonce()

      let hash = await treasury.getPauseHash(deadline, nonce)
      let signature = await v2.signMessage(ethers.getBytes(hash))

      await treasury.connect(v1).pause(deadline, nonce, signature)

      const address = await token.getAddress()

      deadline = Math.floor(Date.now() / 1000) + 3600
      nonce = await treasury.nonce()

      hash = await treasury.getWhitelistHash(address, deadline, nonce)
      signature = await v2.signMessage(ethers.getBytes(hash))

      await expect(
        treasury.connect(v1).whitelistToken(address, deadline, nonce, signature)
      ).to.be.revertedWith('Treasury: paused')
    })
  })

  describe('getValidators()', () => {
    it('should return validators correctly', async () => {
      const validators = await treasury.getValidators()

      expect(validators).to.deep.equal([
        await v1.getAddress(),
        await v2.getAddress(),
        await v3.getAddress(),
      ])
    })
  })
})
