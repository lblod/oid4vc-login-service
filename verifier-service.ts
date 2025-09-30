import * as Crypto from 'node:crypto';
import {
  createEphemeralKeyPair,
  getPrivateKeyAsCryptoKey,
  getPublicKeyAsCryptoKey,
  getPublicKeyAsJwk,
} from './crypto';
import * as jose from 'jose';
import { encode } from 'node:punycode';
import { updateSudo } from '@lblod/mu-auth-sudo';
import {
  sparqlEscapeDateTime,
  sparqlEscapeString,
  sparqlEscapeUri,
  uuid,
} from 'mu';

export class VCVerifier {
  ready = false;
  async setup() {
    this.ready = true;
  }

  async buildAuthorizationRequestUri(session: string) {
    //const clientId = `decentralized_identifier:${process.env.ISSUER_DID}`; // TODO older spec doesn't use a prefix and using it breaks paradym
    const clientId = `${process.env.ISSUER_DID}`;
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
          id: '0',
          format: 'dc+sd-jwt',
          meta: {
            vct_values: [process.env.ISSUER_URL],
          },
          claims: [{ path: ['decideGroups'] }, { path: ['id'] }],
        },
      ],
      credential_sets: [
        {
          options: [['0']],
          purpose:
            'We require these credentials to verify your decide group memberships.',
        },
      ],
    };
    const transactionData = {
      type: 'DecideVerifiablePresentationRequest',
      credential_ids: [`${process.env.ISSUER_URL}`], // TODO still using issuer url as credential id, should probably change this.
    }; // TODO define transaction data if needed
    //const clientId = `decentralized_identifier:${process.env.ISSUER_DID}`; // TODO older spec doesn't use a prefix and using it breaks paradym
    const clientId = `${process.env.ISSUER_DID}`;
    const nonce = Crypto.randomBytes(16).toString('base64url');
    const ephemeralKey = createEphemeralKeyPair(); // TODO we need to store this
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
      client_metadata: {
        jwks: {
          // we could in theory add multiple jwks here to support multiple algorithms, no need now
          // no need to have multiple keys for key rotation because we generate a key per client
          keys: [ephemeralKey.jwk],
        },
        authorization_encrypted_response_alg: 'ECDH-ES',
        authorization_encrypted_response_enc: 'A128GCM',
      },
    };
    if (walletNonce) {
      payload['wallet_nonce'] = walletNonce;
    }
    await this.storeAuthorizationRequest(
      session,
      nonce,
      ephemeralKey.privateKey,
    );
    // request is jwt signed with our private key
    const request = await new jose.SignJWT(payload)
      .setProtectedHeader({
        alg: 'EdDSA',
        kid: process.env.ISSUER_KEY_ID as string,
        iss: process.env.ISSUER_DID, // TODO separate issuer did?
        typ: 'oauth-authz-req+jwt',
      })
      .sign(getPrivateKeyAsCryptoKey()); // TODO cache?

    return request;
    // TODO not great. if they have the session they can generate a request... do we mind?
  }

  async storeAuthorizationRequest(
    session: string,
    nonce: string,
    privateKey: Crypto.KeyObject,
  ) {
    const id = crypto.randomUUID();
    const uri = `http://mu.semte.ch/vocabularies/ext/authorization-request/${id}`;
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>
      INSERT DATA {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ${sparqlEscapeUri(uri)} a ext:AuthorizationRequest ;
            ext:session ${sparqlEscapeUri(session)} ;
            ext:nonce ${sparqlEscapeString(nonce)} ;
            ext:ephemeralPrivateKey ${sparqlEscapeString(privateKey.export({ format: 'jwk' }).toString())} ;
            dct:created ${sparqlEscapeDateTime(new Date())} .
        }
      }
    `);
  }
}
