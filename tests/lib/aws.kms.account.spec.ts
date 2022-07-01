import {AwsKmsAccount, AccountDetails} from '../../src';

const knownAlias = 'test-kms-key-' + Date.now();
const region = <string>process.env.AWS_DEFAULT_REGION;
describe('AWSKmsAccount Tests', () => {
  let accountDetails: AccountDetails;

  beforeEach(async () => {
    if (!accountDetails) {
      // creating know account here so others can reuse.
      accountDetails = await AwsKmsAccount.createNewAccount({
        region,
        alias: knownAlias,
      });
    }
  });

  describe('Account Tests', () => {
    it('Should create account with appropriate data', async () => {
      // check UUID is valid
      console.log('Account created:', accountDetails);
      expect(accountDetails).not.toBeNull();
      expect(accountDetails.keyId).toMatch(/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
      expect(accountDetails.address).toMatch(/^0x[a-f0-9]{40}$/);
      expect(accountDetails.alias).toEqual(`alias/${knownAlias}`);
      expect(accountDetails.region).toEqual(region);
    });

    it('Should fail when trying to create key with known alias', async () => {
      const accountDetailsPromise = AwsKmsAccount.createNewAccount({
        region,
        alias: knownAlias,
      });
      await expect(accountDetailsPromise).rejects.toThrow(/already exists with given alias/);
    });

    it('Should create wallet with correct address', async () => {
      expect(accountDetails).not.toBeNull();
      const wallet = AwsKmsAccount.createWallet(accountDetails.keyId, accountDetails.region);
      const address = await wallet.getAddress();
      expect(address).toEqual(accountDetails.address);
    });
  });
});
