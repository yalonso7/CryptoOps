import { ethers } from 'ethers';
import { SecureWeb3Provider } from './web3Provider';

export class SecureContractInteraction {
  private readonly provider: SecureWeb3Provider;
  private readonly contractGuard: ContractSecurityGuard;

  constructor() {
    this.provider = SecureWeb3Provider.getInstance();
    this.contractGuard = new ContractSecurityGuard();
  }

  async interactWithContract(address: string, abi: any, method: string, params: any[]) {
    // Validate contract address
    if (!ethers.utils.isAddress(address)) {
      throw new Error('Invalid contract address');
    }

    // Validate ABI
    if (!this.contractGuard.validateABI(abi)) {
      throw new Error('Invalid ABI format');
    }

    // Check contract security score
    const securityScore = await this.contractGuard.checkContractSecurity(address);
    if (securityScore < 0.7) {
      throw new Error('Contract security score too low');
    }

    const provider = await this.provider.getProvider();
    const contract = new ethers.Contract(address, abi, provider);

    // Validate method exists and is callable
    if (!contract.functions[method]) {
      throw new Error('Invalid method');
    }

    // Parameter validation
    this.contractGuard.validateParams(method, params, abi);

    return contract[method](...params);
  }
}