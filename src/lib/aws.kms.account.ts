/* eslint-disable no-invalid-this */
/**
 * AWS KMS Signing Adapted from https://github.com/lucashenning/aws-kms-ethereum-signing
 */
import {KMS} from 'aws-sdk';
import * as asn1 from 'asn1.js';
import {BN, bnToHex, bufferToHex, ecrecover, intToHex, keccak256, pubToAddress, toRpcSig} from 'ethereumjs-util';
import {getKeyPolicy} from './key.policy.helper';
import {SignatureResponse} from './signature.response';
import {IWallet} from './wallet.interface';

const SECP256_K1_N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16); // max value on the curve

interface KeyStoreData {
  keyId: string;
  region: string;
}

// noinspection JSVoidFunctionReturnValueUsed
const EcdsaSigAsnParse = asn1.define('EcdsaSig', function (this: any) {
  // parsing this according to https://tools.ietf.org/html/rfc3279#section-2.2.3
  this.seq().obj(this.key('r').int(), this.key('s').int());
});

// noinspection JSVoidFunctionReturnValueUsed
const EcdsaPubKey = asn1.define('EcdsaPubKey', function (this: any) {
  // parsing this according to https://tools.ietf.org/html/rfc5480#section-2
  this.seq().obj(this.key('algo').seq().obj(this.key('a').objid(), this.key('b').objid()), this.key('pubKey').bitstr());
});

function getEthereumAddress(publicKey: Buffer, prefix = '0x'): string {
  // The public key is ASN1 encoded in a format according to
  // https://tools.ietf.org/html/rfc5480#section-2
  // I used https://lapo.it/asn1js to figure out how to parse this
  // and defined the schema in the EcdsaPubKey object
  const res = EcdsaPubKey.decode(publicKey, 'der');
  let pubKeyBuffer: Buffer = res.pubKey.data;

  // The public key starts with a 0x04 prefix that needs to be removed
  // more info: https://www.oreilly.com/library/view/mastering-ethereum/9781491971932/ch04.html
  pubKeyBuffer = pubKeyBuffer.slice(1, pubKeyBuffer.length);

  const address = keccak256(pubKeyBuffer); // keccak256 hash of publicKey
  const buf2 = Buffer.from(address);
  return prefix + buf2.slice(-20).toString('hex'); // take last 20 bytes as ethereum adress
}

function decodeStoreData(storeData: Buffer): KeyStoreData {
  const rawJson = Buffer.from(storeData).toString('utf8');
  return <KeyStoreData>JSON.parse(rawJson);
}

function findEthereumSig(signature: Buffer) {
  if (!signature || signature.length < 1) {
    throw new Error('Signature is undefined.');
  }

  const decoded = EcdsaSigAsnParse.decode(signature, 'der');
  const r: BN = decoded.r;
  let s: BN = decoded.s;

  const secp256k1halfN = SECP256_K1_N.div(new BN(2)); // half of the curve
  // Because of EIP-2 not all elliptic curve signatures are accepted
  // the value of s needs to be SMALLER than half of the curve
  // i.e. we need to flip s if it's greater than half of the curve
  if (s.gt(secp256k1halfN)) {
    // According to EIP2 https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
    // if s < half the curve we need to invert it
    // s = curve.n - s
    s = SECP256_K1_N.sub(s);
  }
  // if s is less than half of the curve, we're on the "good" side of the curve, we can just return
  return {r, s};
}

function calculateRecovery(msg: Buffer, r: BN, s: BN, expectedEthAddr: string) {
  // There are two matching signatures on the elliptic curve
  // we need to find the one that matches to our public key
  // it can be v = 27 or v = 28
  const v = 27;
  const pubKey = recoverPubKeyFromSig(msg, r, s, v);
  return pubKey == expectedEthAddr ? 27 : 28;
}

function recoverPubKeyFromSig(msg: Buffer, r: BN, s: BN, v: number) {
  const pubKey = ecrecover(msg, v, r.toBuffer(), s.toBuffer());
  const addrBuf = pubToAddress(pubKey);
  return bufferToHex(addrBuf);
}

function verifyDerivationPath(path) {
  if (path && !path.endsWith('/0/0')) {
    throw new Error('Derivation path is not at 0th. Attemot to use hierarchical address here.');
  }
}

class EthereumWallet implements IWallet {
  private readonly keyId: string;
  private readonly kmsClient: KMS;

  constructor(keyId: string, kmsClient: KMS) {
    this.keyId = keyId;
    this.kmsClient = kmsClient;
  }

  async getAddress(): Promise<string> {
    const publicKeyData = await this.kmsClient.getPublicKey({KeyId: this.keyId}).promise();
    return getEthereumAddress(publicKeyData.PublicKey as Buffer);
  }

  private async sign(dataHash: Buffer, chainId?: number): Promise<SignatureResponse> {
    // return legacy type ECDSASignature (deprecated in favor of ECDSASignatureBuffer to handle large chainIds)
    if (chainId && !Number.isSafeInteger(chainId)) {
      throw new Error('The provided number is greater than MAX_SAFE_INTEGER (please use an alternative input type)');
    }

    const signing = await this.kmsClient
      .sign({
        Message: dataHash,
        KeyId: this.keyId,
        SigningAlgorithm: 'ECDSA_SHA_256',
        MessageType: 'DIGEST',
      })
      .promise();

    const address = await this.getAddress();
    const {r, s} = findEthereumSig(signing.Signature as Buffer);
    const recovery = calculateRecovery(dataHash, r, s, address);
    const v = chainId ? recovery + 8 + chainId * 2 : recovery;
    return {
      v: intToHex(v),
      r: bnToHex(r),
      s: bnToHex(s),
      sig: toRpcSig(v, r.toBuffer(), s.toBuffer(), chainId),
    };
  }

  signDigest(msgHash: Buffer, chainId?: number): Promise<SignatureResponse> {
    return this.sign(msgHash, chainId);
  }

}

export interface AccountOptions {
  alias?: string;
  tags?: Record<string, string>;
  region?: string;
}

export interface AccountDetails {
  address: string;
  region?: string;
  keyId: string;
  alias: string;
}

const getRegionFromArn = (arn) => arn.split(':')[3];

export class AwsKmsAccount {
  static createKmsClient(region): KMS {
    return new KMS({region});
  }

  public static async createNewAccount(options: AccountOptions): Promise<AccountDetails> {
    const policy = await getKeyPolicy();
    const tags: KMS.TagList = [{TagKey: 'key_creator', TagValue: 'aws-kms-signers'}];

    const kmsClient = AwsKmsAccount.createKmsClient(options.region);
    if (options.tags) {
      for (const tagName in options.tags) {
        tags.push({TagKey: tagName, TagValue: options.tags[tagName]});
      }
    }

    const keyCreation = await kmsClient
      .createKey({
        KeySpec: 'ECC_SECG_P256K1',
        KeyUsage: 'SIGN_VERIFY',
        // TODO allow HSM
        Origin: 'AWS_KMS',
        Description: 'Ethereum Account Address',
        Policy: policy,
        Tags: tags,
      })
      .promise();

    console.log('Created key: ', keyCreation.KeyMetadata.KeyId);

    let aliasName: string;
    if (options.alias) {
      aliasName = options.alias.startsWith('alias/') ? options.alias : `alias/${options.alias}`;
      await kmsClient
        .createAlias({
          AliasName: aliasName,
          TargetKeyId: keyCreation.KeyMetadata.KeyId,
        })
        .promise();
    }

    const address = await new EthereumWallet(keyCreation.KeyMetadata.KeyId, kmsClient).getAddress();
    return {
      alias: aliasName,
      keyId: keyCreation.KeyMetadata.KeyId,
      region: options.region || getRegionFromArn(keyCreation.KeyMetadata.Arn),
      address,
    };
  }

  public static createWallet(keyId: string, region?: string): EthereumWallet {
    return new EthereumWallet(keyId, this.createKmsClient(region));
  }
}
