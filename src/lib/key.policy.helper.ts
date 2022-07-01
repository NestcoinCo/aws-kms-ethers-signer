import {STS} from 'aws-sdk';

let accountId;
let arn;
export const getKeyPolicy = async (isLocal = false) => {
  if (!accountId) {
    if (!isLocal) {
      const identityInfo = await new STS().getCallerIdentity().promise();
      accountId = identityInfo.Account;
      arn = identityInfo.Arn;
    } else {
      // TODO allow customization of this in the future.
      accountId = '111122223333';
      arn = `arn:aws:iam::${accountId}:user/local-user`;
    }
  }

  const policyDocument = {
    Id: 'key-policy',
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'Enable IAM User Permissions',
        Effect: 'Allow',
        Principal: {
          AWS: `arn:aws:iam::${accountId}:root`,
        },
        Action: ['kms:*'],
        Resource: '*',
      },
    ],
  };

  // Grant key usage to creator
  policyDocument.Statement.push({
    Sid: 'Allow use of the key',
    Effect: 'Allow',
    Principal: {
      AWS: `${arn}`,
    },
    Action: ['kms:Sign', 'kms:GetPublicKey'],
    Resource: '*',
  });

  return JSON.stringify(policyDocument);
};
