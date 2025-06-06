import { encrypt, decrypt } from '../utils/encryption';

export class SecureStorage {
  private static readonly STORAGE_KEY = 'secure_contract_data';

  static async saveContractData(data: any): Promise<void> {
    const encryptedData = await encrypt(JSON.stringify(data));
    localStorage.setItem(this.STORAGE_KEY, encryptedData);
  }

  static async getContractData(): Promise<any> {
    const encryptedData = localStorage.getItem(this.STORAGE_KEY);
    if (!encryptedData) return null;
    
    const decryptedData = await decrypt(encryptedData);
    return JSON.parse(decryptedData);
  }
}