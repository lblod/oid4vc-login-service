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
    const walletMetadata = wallet_metadata
      ? JSON.parse(wallet_metadata)
      : undefined;
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
      credential_sets: [
        {
          options: [[`${process.env.ISSUER_URL}`]],
          purpose:
            'We require these credentials to verify your decide group memberships.',
        },
      ],
    };
    const transactionData = {
      type: 'DecideVerifiablePresentationRequest',
      credential_ids: [`${process.env.ISSUER_URL}`], // TODO still using issuer url as credential id, should probably change this.
    }; // TODO define transaction data if needed
    const clientId = `decentralized_identifier:${process.env.ISSUER_DID}`;
    const nonce = Crypto.randomBytes(16).toString('base64url');
    const payload = {
      response_type: 'vp_token',
      client_id: clientId,
      response_uri: `${process.env.ISSUER_URL}/vc-issuer/presentation-response`, // TODO change to verifier? we're both atm
      response_mode: 'direct_post.jwt',
      nonce,
      dcql_query: dcqlQuery,
      aud: 'https://self-issued.me/v2',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600, // 10 minutes
      state: session, // use the session as state so we can verify it on the response
    };
    if (walletNonce) {
      payload['wallet_nonce'] = walletNonce;
    }
    // request is jwt signed with our private key
    const request = await new jose.SignJWT(payload)
      .setProtectedHeader({
        alg: 'EdDSA',
        iss: process.env.ISSUER_DID, // TODO separate issuer did?
      })
      .sign(getPrivateKeyAsCryptoKey()); // TODO cache?

    return request;
    // TODO not great. if they have the session they can generate a request... do we mind?
  }
}
