const ISSUER_URL = process.env.ISSUER_URL || 'http://localhost:3000';
const VERIFIER_URL = process.env.VERIFIER_URL || ISSUER_URL;
const PROJECT_NAME = process.env.PROJECT_NAME || 'Decide';

const environment = {
  AUTH_CODE_TTL: parseInt(process.env.AUTH_CODE_TTL || '60000'), // 10 minutes
  AUTHORIZATION_REQUEST_TTL: parseInt(
    process.env.AUTHORIZATION_REQUEST_TTL || '600000',
  ), // 10 minutes
  CARD_BACKGROUND_COLOR: process.env.CARD_BACKGROUND_COLOR || '#12107c',
  CARD_TEXT_COLOR: process.env.CARD_TEXT_COLOR || '#FFFFFF',
  CLEANUP_CRON_PATTERN: process.env.CLEANUP_CRON_PATTERN || '51 * * * *', // Every hour
  CREDENTIAL_NAME:
    process.env.CREDENTIAL_NAME || `${PROJECT_NAME} Roles Credential`,

  CREDENTIAL_TYPE: process.env.CREDENTIAL_TYPE || `${PROJECT_NAME}Roles`,
  CREDENTIAL_URI_BASE:
    process.env.CREDENTIAL_URI_BASE || `${ISSUER_URL}/credentials/`,
  ISSUER_DID: process.env.ISSUER_DID,
  ISSUER_KEY_ID: process.env.ISSUER_KEY_ID,
  ISSUER_PUBLIC_KEY: process.env.ISSUER_PUBLIC_KEY,
  ISSUER_PRIVATE_KEY: process.env.ISSUER_PRIVATE_KEY,
  ISSUER_NAME: process.env.ISSUER_NAME || `${PROJECT_NAME} OID4VC Issuer`,
  ISSUER_URL,
  LOGO_URL: process.env.logo_URL || `${ISSUER_URL}/assets/logo.png`,
  NO_DID_PREFIX: process.env.NO_DID_PREFIX === 'true', // because of old spec versions, some wallets break without this
  PROJECT_NAME,
  SINGLE_CREDENTIAL_RESPONSE: process.env.SINGLE_CREDENTIAL_RESPONSE === 'true', // because of old spec versions, some wallets break without this
  TOKEN_TTL: parseInt(process.env.TOKEN_TTL || '86400'), // 24 hours
  VERIFIER_DID: process.env.VERIFIER_DID,
  VERIFIER_KEY_ID: process.env.VERIFIER_KEY_ID,
  VERIFIER_URL,
};

console.log('Environment:', JSON.stringify(environment, null, 2));
const requiredVars = [
  'ISSUER_DID',
  'ISSUER_KEY_ID',
  'ISSUER_PUBLIC_KEY',
  'ISSUER_PRIVATE_KEY',
  'VERIFIER_DID',
  'VERIFIER_KEY_ID',
];
for (const varName of requiredVars) {
  if (!environment[varName as keyof typeof environment]) {
    console.error(`Error: ${varName} environment variable is not set`);
    process.exit(1);
  }
}

export default environment;
