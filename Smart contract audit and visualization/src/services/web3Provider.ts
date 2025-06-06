import { ethers } from 'ethers';
import { env } from '../config/env';

export class SecureWeb3Provider {
  private static instance: SecureWeb3Provider;
  private provider: ethers.providers.Web3Provider | null = null;
  private readonly providerUrls: string[];

  private constructor() {
    this.providerUrls = [
      `https://mainnet.infura.io/v3/${env.NEXT_PUBLIC_INFURA_ID}`,
      `https://eth-mainnet.alchemyapi.io/v2/${env.NEXT_PUBLIC_ALCHEMY_ID}`,
    ];
  }

  public static getInstance(): SecureWeb3Provider {
    if (!SecureWeb3Provider.instance) {
      SecureWeb3Provider.instance = new SecureWeb3Provider();
    }
    return SecureWeb3Provider.instance;
  }

  private async validateProvider(provider: any): Promise<boolean> {
    try {
      // Basic provider validation
      if (!provider || typeof provider.send !== 'function') {
        return false;
      }
      // Check network
      const network = await provider.getNetwork();
      return network.chainId === 1; // Ensure mainnet
    } catch {
      return false;
    }
  }

  public async getProvider(): Promise<ethers.providers.Web3Provider> {
    if (this.provider && await this.validateProvider(this.provider)) {
      return this.provider;
    }

    if (typeof window !== 'undefined' && window.ethereum) {
      this.provider = new ethers.providers.Web3Provider(window.ethereum);
      return this.provider;
    }

    throw new Error('No Web3 provider available');
  }
}