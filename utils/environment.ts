const ISSUER_URL = process.env.ISSUER_URL || 'http://localhost:3000';
const PROJECT_NAME = process.env.PROJECT_NAME || 'Decide';

const environment = {
  PROJECT_NAME,
  ISSUER_NAME: process.env.ISSUER_NAME || `${PROJECT_NAME} OID4VC Issuer`,
  ISSUER_SERVICE_PATH: process.env.ISSUER_SERVICE_PATH || 'vc-issuer',
  VERIFIER_SERVICE_PATH: process.env.VERIFIER_SERVICE_PATH || 'vc-verifier',
  ISSUER_URL,
  LOGO_URL: process.env.logo_URL || `${ISSUER_URL}/assets/logo.png`,
  CARD_BACKGROUND_COLOR: process.env.CARD_BACKGROUND_COLOR || '#12107c',
  CARD_TEXT_COLOR: process.env.CARD_TEXT_COLOR || '#FFFFFF',
  CREDENTIAL_TYPE: process.env.CREDENTIAL_TYPE || `${PROJECT_NAME}Roles`,
  CREDENTIAL_NAME:
    process.env.CREDENTIAL_NAME || `${PROJECT_NAME} Roles Credential`,
  SINGLE_CREDENTIAL_RESPONSE: process.env.SINGLE_CREDENTIAL_RESPONSE === 'true', // because of old spec versions, some wallets break without this
  CREDENTIAL_URI_BASE:
    process.env.CREDENTIAL_URI_BASE || `${ISSUER_URL}/credentials/`,
  AUTH_CODE_TTL: parseInt(process.env.AUTH_CODE_TTL || '60000'), // 10 minutes
  TOKEN_TTL: parseInt(process.env.TOKEN_TTL || '86400'), // 24 hours
};

console.log('Environment:', JSON.stringify(environment, null, 2));

export default environment;
