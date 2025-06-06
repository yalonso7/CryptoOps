import { ethers } from 'ethers';
import { Web3Provider } from '@ethersproject/providers';

export class Web3Service {
  private provider: Web3Provider;

  constructor() {
    if (typeof window !== 'undefined' && window.ethereum) {
      this.provider = new ethers.providers.Web3Provider(window.ethereum);
    }
  }

  async connectWallet() {
    try {
      await this.provider.send('eth_requestAccounts', []);
      return this.provider.getSigner();
    } catch (error) {
      console.error('Error connecting wallet:', error);
      throw error;
    }
  }

  async getContractData(address: string, abi: any) {
    const contract = new ethers.Contract(address, abi, this.provider);
    return contract;
  }
}