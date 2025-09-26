import * as Crypto from 'node:crypto';
import { getPrivateKeyAsCryptoKey, getPublicKeyAsCryptoKey } from './crypto';
import * as jose from 'jose';
import { encode } from 'node:punycode';

export class VCVerifier {
  ready = false;
  async setup() {
    this.ready = true;
  }

  async buildAuthorizationRequestUri(session: string) {
    const clientId = `decentralized_identifier:${process.env.ISSUER_DID}`;
    const requestUri = `${process.env.ISSUER_URL}/vc-issuer/authorization-request`; // TODO change to verifier? we're both atm
    const authorizationRequestUri = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;

    return {
      authorizationRequestUri,
    };
  }

  async buildAuthorizationRequestData(
    session: string,
    wallet_metadata: string,
    wallet_nonce: string,
  ) {
    const walletMetadata = JSON.parse(wallet_metadata);
    const walletNonce = wallet_nonce;

    const dcqlQuery = {
      credentials: [
        {
          id: `${process.env.ISSUER_URL}`,
          format: 'dc+sd-jwt',
          meta: {
            vct_values: [process.env.ISSUER_URL],
          },
          claims: [{ path: ['decideGroups'] }, { path: ['id'] }],
        },
      ],
    };
    const transactionData = {
      type: 'DecideVerifiablePresentationRequest',
      credential_ids: [`${process.env.ISSUER_URL}`], // TODO still using issuer url as credential id, should probably change this.
    }; // TODO define transaction data if needed
    const clientId = `decentralized_identifier:${process.env.ISSUER_DID}`;
    const nonce = Crypto.randomBytes(16).toString('base64url');
    // request is jwt signed with our private key
    const request = await new jose.SignJWT({
      iss: process.env.ISSUER_DID, // TODO separate issuer did?
      aud: 'https://self-issued.me/v2',
      response_type: 'vp_token',
      client_id: clientId,
      dcql_query: dcqlQuery,
      transaction_data: transactionData,
      wallet_nonce: walletNonce,
      nonce,
    })
      .setProtectedHeader({ alg: 'EdDSA' })
      .sign(getPrivateKeyAsCryptoKey()); // TODO cache?

    return request;
    // TODO not great. if they have the session they can generate a request... do we mind?
  }
}
