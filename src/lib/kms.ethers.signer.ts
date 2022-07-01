import {Bytes, Signer, logger} from 'ethers';
import {Provider, TransactionRequest} from '@ethersproject/providers';
import {keccak256} from '@ethersproject/keccak256';
import {Deferrable, defineReadOnly, resolveProperties} from '@ethersproject/properties';
import {IWallet} from './wallet.interface';
import {AwsKmsAccount} from './aws.kms.account';
import {hashMessage} from '@ethersproject/hash';
import {toBuffer} from 'ethereumjs-util';
import {serialize, UnsignedTransaction} from '@ethersproject/transactions';

export interface KmsSignerOptions {
  /**
   * The KMS key ID or alias
   */
  keyId: string;

  /**
   * AWS region where key is stored.
   */
  region?: string;

  address?: string;
}

export class KmsEthersSigner extends Signer {
  private address?: string;
  private verified: boolean = false;
  private readonly keyId: string;
  private readonly region?: string;
  private readonly wallet: IWallet;

  constructor(kmsOptions: KmsSignerOptions, provider?: Provider) {
    super();
    if (provider && !Provider.isProvider(provider)) {
      logger.throwArgumentError('invalid provider', 'provider', provider);
    }
    defineReadOnly(this, 'provider', provider || null);

    this.keyId = kmsOptions.keyId;
    this.address = kmsOptions.address;
    this.region = kmsOptions.region;
    this.wallet = AwsKmsAccount.createWallet(this.keyId, this.region);
  }

  connect(provider: Provider): KmsEthersSigner {
    const signer = new KmsEthersSigner(
      {
        region: this.region,
        address: this.address,
        keyId: this.keyId,
      },
      provider,
    );

    signer.verified = this.verified;
    return signer;
  }

  async getAddress(): Promise<string> {
    await this.verifySigner();
    return this.address;
  }

  public async signMessage(message: Bytes | string): Promise<string> {
    await this.verifySigner();
    const msgHash = hashMessage(message);
    const {sig} = await this.wallet.signDigest(toBuffer(msgHash));
    return sig;
  }

  async signTransaction(transaction: Deferrable<TransactionRequest>): Promise<string> {
    await this.verifySigner();
    const tx = await resolveProperties(transaction);

    if (tx.from) {
      if (tx.from.toString() !== this.address) {
        logger.throwArgumentError('transaction from address mismatch', 'transaction.from', transaction.from);
      }

      delete tx.from;
    }

    const txHash = keccak256(serialize(<UnsignedTransaction>tx));
    const signature = await this.wallet.signDigest(toBuffer(txHash), tx.chainId);
    return serialize(<UnsignedTransaction>tx, signature.sig);
  }

  private async verifySigner() {
    if (!this.verified) {
      const address = await this.wallet.getAddress();
      if (this.address && this.address.toLowerCase() !== address.toLowerCase()) {
        throw new Error('InvalidAddress: Address specified does not match derived address');
      }
      this.address = address;
      this.verified = true;
    }
  }

  public isVerified(): boolean {
    return this.verified;
  }
}
