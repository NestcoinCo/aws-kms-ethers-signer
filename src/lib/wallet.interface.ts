import {SignatureResponse} from './signature.response';

export interface IWallet {
  getAddress(): Promise<string>;

  signDigest(msgHash: Buffer, chainId?: number): Promise<SignatureResponse>;

}
