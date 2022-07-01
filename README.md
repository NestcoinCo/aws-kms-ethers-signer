# AWS KMS EthersJS Signer

This is a Node.JS package for using [AWS KMS](https://aws.amazon.com/kms/) keys as Ethereum Accounts with ability to
sign transactions for any EVM based network and messages.

This packaged is based off the work done by [@lucashenning](https://github.com/lucashenning/aws-kms-ethereum-signing),
with a walkthrough available in
this [medium article](https://luhenning.medium.com/the-dark-side-of-the-elliptic-curve-signing-ethereum-transactions-with-aws-kms-in-javascript-83610d9a6f81)
.

## What can you do with this package?

The package enables you to do the following:

* Create new ETH Addresses using AWS KMS
* Sign transactions and messages using AWS KMS ECC keys
* Create an [EthersJS](https://docs.ethers.io/v5/) compatible [signer](https://docs.ethers.io/v5/api/signer/).

## Pre-requisite

1. Create AWS IAM user with programmatic access to AWS KMS.
2. Configure your AWS environment.The package
   uses [aws-sdk](https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/welcome.html) V2. The package does
   not provide a way to configure your AWS credentials, so you need to use environment variables, instance profiles or
   AWS CLI credentials file.

## Usage

### Account Creation

When you create a new account, a new KMS key with specified alias (optional) is created in the specified region, and
then the package attempts to get the ARN of the current user in order to grant them permission to use the created key.

```typescript
import {AwsKmsAccount} from '@nestcoinoss/aws-kms-ethers-signer';

const accountDetails = await AwsKmsAccount.createNewAccount({
    alias: 'alias/my-awesome-key', // optional string;
    tags: {
        accountLabel: 'my-savings-key'
    }, // optional
    region: 'eu-west-2' //optional string if AWS_REGION env variable is set
});

console.log(accountDetails);
/** sample output
{
  alias: 'alias/my-awesome-key',
  keyId: '1eede8b7-9b02-43e0-a050-08f58b1fbdf4',
  region: 'eu-west-2',
  address: '0x094d948596ecbb2c257d79169ad1e7871172448f'
}
 */
```

### Getting Address from Key
To get the address associated with a KMS key, you can either use the Ether signer or call `IWallet` interface.

1. Using Wallet Interface
   ```typescript
   import {AwsKmsAccount, IWallet} from '@nestcoinoss/aws-kms-ethers-signer';
   
   const keyId = 'alias/my-awesome-key'; // can be replaced with keyId
   const region = 'eu-west-2';
   const wallet: IWallet = AwsKmsAccount.createWallet(keyId, region);
   // get address
   const address = await wallet.getAddress();
   console.log('Address:', address); // Address: 0x094d948596ecbb2c257d79169ad1e7871172448f
   ```

2. Using Ethers Signer
   ```typescript
   import {KmsEthersSigner} from '@nestcoinoss/aws-kms-ethers-signer';
   
   const keyId = 'alias/my-awesome-key'; // can be replaced with keyId
   const region = 'eu-west-2'; 
   // using wallet interface
   const signer =  new KmsEthersSigner({
        region,
        keyId,
        // address: '',///optional, only use if address is known 
   });
   
   // get address
   const address = await signer.getAddress();
   console.log('Address:', address); // Address: 0x094d948596ecbb2c257d79169ad1e7871172448f
   ```


### Signing Messages
To sign personal messages, you need to use the ethers signer for convenience. 

> You can also use the IWallet.signDigest(hash, chainId) interface method directly.

```typescript
   import {KmsEthersSigner} from '@nestcoinoss/aws-kms-ethers-signer';
   
   const keyId = 'alias/my-awesome-key'; // can be replaced with keyId
   const region = 'eu-west-2'; 
   // using wallet interface
   const signer =  new KmsEthersSigner({
        region,
        keyId,
        // address: '',///optional, only use if address is known 
   });
    
   // sign message
   const message = 'Awesome App!';
   const signature = await signer.signMessage(message);
   console.log(signature); 
   // 0xcd3d1dc773b9926de6bd47c84e889e2e4434e9c2ee8594c7dbb8690d5285603e3172867bd15e8a9b84e1f32bf02cd7035d491e3e1247cdcb5c3de5de6657d7e41b
```

### Signing Transaction
Signing and sending transactions is straightforward, ensue to use the right EIP-155  chain ID.

```typescript
import {KmsEthersSigner} from '@nestcoinoss/aws-kms-ethers-signer';
import {ethers, BigNumber} from 'ethers';

const provider = new ethers.providers.JsonRpcProvider(`https://your-rpc-url`);

const keyId = 'alias/my-awesome-key'; // can be replaced with keyId
const region = 'eu-west-2';

// using wallet interface
const signer = new KmsEthersSigner({
   region,
   keyId,
   // address: '',///optional, only use if address is known 
}).connect(provider);

const chain = await provider.detectNetwork();
const amountToTransfer = BigNumber('1000000000000000000');
const gasPrice = await signerPrimaryAccount.getGasPrice();
const nonce = await signerPrimaryAccount.getTransactionCount();

// sign transaction alone:
const txnRequest = <TransactionRequest>{
   nonce,
   gasLimit: 21000,
   gasPrice,
   chainId: chain.chainId, // can be hardcoded if known
   value: amountToTransfer,
   to: '0x169c69318c4e2b0aa8c8268dd7a9fcc59c3e4d07',
};


const sendTxResult = await signerPrimaryAccount.sendTransaction(txnRequest);
console.log('Sent transaction:::', JSON.stringify(sendTxResult));
//Sent transaction:::  {"type":2,"chainId":31337,"nonce":0,"maxPriorityFeePerGas":{"type":"BigNumber","hex":"0x6fc23ac0"},"maxFeePerGas":{"type":"BigNumber","hex":"0x6fc23ac0"},"gasPrice":null,"gasLimit":{"type":"BigNumber","hex":"0x5208"},"to":"0x169C69318c4E2B0aa8C8268dD7A9FCc59c3E4D07","value":{"type":"BigNumber","hex":"0x0de0b6b3a7640000"},"data":"0x","accessList":[],"hash":"0x033cf36ed32e0f056a9109e9c91d9c9e433bf9a3fc48ff02b8af02700f30d107","v":1,"r":"0x2132578809c2f37d7d857ca0b9f4efa0c8cf002c5792fcc91d4e1a1b94863334","s":"0x3bcb74b341ffaae568ea4ba4e3502b9dcd805d2e9ba01915b09d5109e20af86b","from":"0xC05AaA0D58841c7170deCd6105e9891702e49ccA","confirmations":0}


// To sign transaction alone, use:
// const signedTxHex = await signerPrimaryAccount.signTransaction(txnRequest);

```


## Testing Locally

For local development, you can test against a Local KMS endpoint, this will avoid incurring costs for Customer Managed
Keys on AWS KMS. To test locally, you need to run a KMS compatible service like (
local-kms)[https://github.com/nsmithuk/local-kms], then pass an environment variable with the URL of the local-kms
service to your app.

```shell
## Start Local KMS, see the repo for more info on seeding values.
docker run -p 9000:8080 --rm --name kms-local -d nsmithuk/local-kms

## Set environment variable
export LOCAL_KMS_ENDPOINT='http://localhost:9000'

## Test this package
npm run test 

## OR: Start you Node app:
node /path/to/your-app
```

## Using with HardHat Contract Deployment

_This section is work in progress_
