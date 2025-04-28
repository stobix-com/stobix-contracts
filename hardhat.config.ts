/* eslint-disable @typescript-eslint/no-non-null-asserted-optional-chain */
import * as dotenv from 'dotenv'
import { HardhatUserConfig } from 'hardhat/config'
import '@nomicfoundation/hardhat-toolbox'
import '@nomicfoundation/hardhat-verify'

dotenv.config()

const accounts = process.env.PRIVATE_KEYS?.split(',')!

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.20',
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000,
      },
    },
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_KEY!,
  },
  networks: {
    sepolia: {
      url: 'https://sepolia.drpc.org',
      accounts,
    },
  },
  sourcify: {
    enabled: false,
  },
}

export default config
