import {
  AbstractSigner,
  assert,
  assertArgument,
  BlockTag,
  BytesLike,
  FetchRequest,
  getAddress,
  JsonRpcApiProviderOptions,
  JsonRpcProvider,
  Network,
  Networkish,
  Provider,
  resolveAddress,
  resolveProperties,
  Transaction,
  type TransactionLike,
  TransactionRequest,
  TypedDataDomain,
  TypedDataEncoder,
  TypedDataField,
} from 'ethers';
import {AwsKmsAccount} from './aws.kms.account';
import {IWallet} from './wallet.interface';
import {hashMessage} from '@ethersproject/hash';
import {toBuffer} from 'ethereumjs-util';
import {keccak256} from '@ethersproject/keccak256';
import {serialize, UnsignedTransaction} from '@ethersproject/transactions';

const _createNetwork = (network: Networkish): Network => {
  if (network instanceof Network) {
    return network;
  } else if (typeof network === 'object') {
    const networkData = network as {
      name?: string;
      chainId?: number;
    };
    return new Network(network.name || '', Number(networkData.chainId!));
  } else {
    // number | bigint | string |
    return new Network('', Number(network));
  }
};

export class StaticJsonRpcProvider extends JsonRpcProvider {
  constructor(url: string | FetchRequest, network: Networkish, options?: JsonRpcApiProviderOptions) {
    options = options || {};
    super(url, network, {
      ...options,
      staticNetwork: _createNetwork(network),
    });
  }

  estimateGas(_tx: TransactionRequest): Promise<bigint> {
    return super.estimateGas(_tx);
  }
}

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

export class KmsEthersSigner extends AbstractSigner {
  private address?: string;
  private verified: boolean = false;
  private readonly keyId: string;
  private readonly region?: string;
  private readonly wallet: IWallet;

  constructor(kmsOptions: KmsSignerOptions, provider?: Provider) {
    super(provider);

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

  async getAddress(): Promise<string> {
    await this.verifySigner();
    return this.address;
  }

  public async signMessage(message: BytesLike | string): Promise<string> {
    await this.verifySigner();
    const msgHash = hashMessage(message);
    const {sig} = await this.wallet.signDigest(toBuffer(msgHash));
    return sig;
  }

  async signTransaction(tx: TransactionRequest): Promise<string> {
    await this.verifySigner();
    const resolvedTx = await resolveProperties({
      to: tx.to ? resolveAddress(tx.to, this.provider) : undefined,
      from: tx.from ? resolveAddress(tx.from, this.provider) : undefined,
    });

    if (resolvedTx.to != null) {
      tx.to = resolvedTx.to;
    }

    if (resolvedTx.from != null) {
      tx.from = resolvedTx.from;
    }

    if (tx.from != null) {
      assertArgument(
        getAddress(<string>tx.from) === this.address,
        'transaction from address mismatch',
        'tx.from',
        tx.from,
      );
      delete tx.from;
    }

    if (resolvedTx.from) {
      assert(resolvedTx.from.toString() === this.address, 'transaction from address mismatch', 'VALUE_MISMATCH');
      delete resolvedTx.from;
    }

    const btx = Transaction.from(<TransactionLike<string>>tx);
    const txHash = keccak256(btx.unsignedSerialized);
    const signature = await this.wallet.signDigest(toBuffer(txHash));
    return serialize(<UnsignedTransaction>tx, signature.sig);
  }

  async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, Array<TypedDataField>>,
    value: Record<string, any>,
  ): Promise<string> {
    // Populate any ENS names
    const populated = await TypedDataEncoder.resolveNames(domain, types, value, async (name: string) => {
      // @TODO: this should use resolveName; addresses don't
      //        need a provider

      assert(this.provider != null, 'cannot resolve ENS names without a provider', 'UNSUPPORTED_OPERATION', {
        operation: 'resolveName',
        info: {name},
      });

      const address = await this.provider.resolveName(name);
      assert(address != null, 'unconfigured ENS name', 'UNCONFIGURED_NAME', {
        value: name,
      });

      return address;
    });

    const digest = TypedDataEncoder.hash(populated.domain, types, populated.value);
    const {sig} = await this.wallet.signDigest(toBuffer(digest));
    return sig;
  }

  getBalance(blockTag?: BlockTag): Promise<bigint> {
    return this.provider!.getBalance(this.getAddress(), blockTag);
  }
}
