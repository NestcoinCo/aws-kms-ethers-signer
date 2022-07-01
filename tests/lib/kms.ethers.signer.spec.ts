import {BigNumber, ethers} from 'ethers';
import {randomBytes, randomInt} from 'crypto';
import * as os from 'os';

import * as ethUtil from 'ethereumjs-util';
import * as childProcess from 'child_process';

import {AwsKmsAccount, AccountDetails, KmsEthersSigner} from '../../src';
import {BN, bnToHex} from 'ethereumjs-util';
import {TransactionRequest} from '@ethersproject/providers';
import {exec} from 'child_process';

const knownAlias = 'test-kms-signer-' + Date.now();
const region = <string>process.env.AWS_DEFAULT_REGION;

const recoverAddressFromPersonalMsg = (message: string, signature) => {
  const msgHash = ethUtil.hashPersonalMessage(Buffer.from(message));
  const sigParams = ethUtil.fromRpcSig(signature);
  const publicKey = ethUtil.ecrecover(msgHash, sigParams.v, sigParams.r, sigParams.s);
  return ethUtil.bufferToHex(ethUtil.publicToAddress(publicKey));
};

let childDaemon: childProcess.ChildProcess;

const portNumber = 40000 + randomInt(20000);
const provider = new ethers.providers.JsonRpcProvider(`http://localhost:${portNumber}`);
const HARDHAT_START_DELAY = 5000;
// Create buffer
jest.setTimeout(HARDHAT_START_DELAY + 5000);

describe('KmsSigner Tests', () => {
  let accountDetails: AccountDetails;

  beforeAll(async () => {
    return new Promise((resolve, reject) => {
      console.log('Starting hardhat node');
      let resolved = false;
      childDaemon = childProcess.spawn('npx', ['hardhat', 'node', '--port', `${portNumber}`]);

      childDaemon.on('error', (err) => {
        console.error('Child process failure:', err);
        reject(err);
      });

      childDaemon.on('spawn', () => {
        // wait for hardhat to start
        setTimeout(() => {
          if (!resolved) {
            resolved = true;
            console.log('Hardhat started');
            resolve(childDaemon);
          }
        }, HARDHAT_START_DELAY);
      });

      childDaemon.stdout.on('data', (chunk) => {
        console.log('Hardhat:::', chunk);
        if (/Private Key/.test(chunk.toString()) && !resolved) {
          resolved = true;
          console.log('Hardhat started early');
          resolve(childDaemon);
        }
      });

      childDaemon.stderr.on('data', (chunk) => {
        console.error('HardhatERR:::', chunk);
      });
    });
  });

  afterAll(async () => {
    if (childDaemon) {
      if (os.type() === 'Linux') {
        console.log('Stopping hardhat using pkill');
        exec(`pkill -TERM -P ${childDaemon.pid}`);
      } else {
        console.log('Stopping hardhat using .kill()');
        childDaemon.kill();
      }
    }
  });

  beforeEach(async () => {
    if (!accountDetails) {
      // creating know account here so others can reuse.
      accountDetails = await AwsKmsAccount.createNewAccount({
        region,
        alias: knownAlias,
      });

      const newBalance = new BN('10000000000000000000');
      const result = await provider.send('hardhat_setBalance', [accountDetails.address, bnToHex(newBalance)]);
      console.log('Balance Request Result :: ', result);
    }
  });

  describe('Address Test', () => {
    it('should return the address from accountDetails', async () => {
      expect(accountDetails).not.toBeNull();
      const signer = new KmsEthersSigner({
        region: accountDetails.region,
        address: accountDetails.address,
        keyId: accountDetails.alias,
      });

      expect(signer.isVerified()).toStrictEqual(false);
      await expect(signer.getAddress()).resolves.toEqual(accountDetails.address);
      expect(signer.isVerified()).toStrictEqual(true);
    });

    it('should fail when the address does not match key address', async () => {
      expect(accountDetails).not.toBeNull();
      const signer = new KmsEthersSigner({
        region: accountDetails.region,
        address: '0x' + randomBytes(20).toString('hex'),
        keyId: accountDetails.alias,
      });

      expect(signer.isVerified()).toStrictEqual(false);
      await expect(signer.getAddress()).rejects.toThrow(/specified does not match derived address/);
      expect(signer.isVerified()).toStrictEqual(false);
    });
  });

  describe('Message Signing Tests', () => {
    it('Signed message should be recoverable', async () => {
      const signer = new KmsEthersSigner({
        region: accountDetails.region,
        keyId: accountDetails.alias,
      });

      const message = 'An awesome test today! ' + Date.now();

      const address = await signer.getAddress();
      const signature = await signer.signMessage(message);

      const recoveredAddress = recoverAddressFromPersonalMsg(message, signature);

      console.log('Recovered Address =', recoveredAddress, 'signature =', signature, 'message =', message);
      expect(recoveredAddress).toEqual(address);
    });
  });

  describe('Connect test', () => {
    it('should connect with verified account', async () => {
      const signer = new KmsEthersSigner({
        region: accountDetails.region,
        keyId: accountDetails.alias,
      });

      const address = await signer.getAddress();
      expect(signer.isVerified()).toStrictEqual(true);
      expect(signer.provider).toBeNull();

      // ensure the provider was connected
      const connectedSigner = signer.connect(provider);
      expect(connectedSigner.isVerified()).toStrictEqual(true);
      await expect(connectedSigner.getAddress()).resolves.toEqual(address);
      expect(connectedSigner.provider).toEqual(provider);
    });

    it('should return rpc information when connected*', async () => {
      const signer = new KmsEthersSigner({
        region: accountDetails.region,
        keyId: accountDetails.alias,
      });

      const connectedSigner = signer.connect(provider);

      const nonce = await connectedSigner.getTransactionCount('latest');
      expect(nonce).toStrictEqual(0);
    });
  });

  describe('Sign Transactions Test', () => {
    it('should sign transaction with hardhat', async () => {
      const newBalance = '0x52b7d2dcc80cd2e4000000';
      const result = await provider.send('hardhat_setBalance', [accountDetails.address, newBalance]);
      console.log('Balance Request Result :: ', result);

      const signer = new KmsEthersSigner(
        {
          region: accountDetails.region,
          keyId: accountDetails.alias,
        },
        provider,
      );

      const balance = await signer.getBalance();
      console.log('Balance =', balance);
      expect(balance.toHexString()).toEqual(newBalance);
    });

    it('should send funds to new address', async () => {
      const signerPrimaryAccount = new KmsEthersSigner(
        {
          region: accountDetails.region,
          keyId: accountDetails.alias,
        },
        provider,
      );

      console.log('Creating secondary account!');
      const secondaryAcctDetails = await AwsKmsAccount.createNewAccount({region});

      console.log('Done!');
      const signerSecondaryAccount = new KmsEthersSigner(
        {
          region: secondaryAcctDetails.region,
          keyId: secondaryAcctDetails.keyId,
          address: secondaryAcctDetails.address,
        },
        provider,
      );

      const oldPrimaryBalance = await signerPrimaryAccount.getBalance('latest');
      expect(oldPrimaryBalance.gt(0)).toStrictEqual(true);

      const oldSecondaryBalance = await signerSecondaryAccount.getBalance('latest');
      expect(oldSecondaryBalance.eq(0)).toStrictEqual(true);

      const nonce = await signerPrimaryAccount.getTransactionCount(0);
      const gasPrice = await signerPrimaryAccount.getGasPrice();
      const chain = await provider.detectNetwork();

      console.log('Chain information:', chain);

      const amountToTransfer = new BN('1000000000000000000');
      const txnRequest = <TransactionRequest>{
        nonce,
        gasLimit: 21000,
        gasPrice,
        chainId: chain.chainId, //
        value: bnToHex(amountToTransfer),
        to: secondaryAcctDetails.address,
      };

      const sendTxResult = await signerPrimaryAccount.sendTransaction(txnRequest);
      console.log('Sent transaction:::', JSON.stringify(sendTxResult));

      const newPrimaryBalance = await signerPrimaryAccount.getBalance('latest');
      expect(newPrimaryBalance.lt(oldPrimaryBalance)).toStrictEqual(true);

      const newSecondaryBalance = await signerSecondaryAccount.getBalance('latest');

      const amountTransferredBigN = BigNumber.from(bnToHex(amountToTransfer));

      expect(newSecondaryBalance.eq(amountTransferredBigN)).toStrictEqual(true);
    });
  });
});
