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

  async handlePresentationResponse(session: string, body) {
    const { response } = body;
    if (!response) {
      throw new Error('No response field in presentation response');
    }
    const { nonce, privateKey } = await this.fetchAuthorizationRequest(session);
    const { payload: vpTokenPayload } = await jose.jwtVerify(
      response,
      getPublicKeyAsCryptoKey(),
      {
        audience: process.env.ISSUER_DID,
        issuer: 'https://self-issued.me/v2',
      },
    );
    if (vpTokenPayload.nonce !== nonce) {
      throw new Error('Invalid nonce in vp_token');
    }
    // vp_token is encrypted with our ephemeral public key, we need to decrypt it with our ephemeral private key
    const { plaintext: vpTokenPlaintext } = await jose.compactDecrypt(
      response,
      privateKey,
    );
    const vpToken = JSON.parse(new TextDecoder().decode(vpTokenPlaintext));
    console.log('vpToken:', vpToken);

    // TODO verify the vpToken contents, e.g. check the dcql_query is satisfied

    return vpToken;
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
            ext:ephemeralPrivateKey ${sparqlEscapeString(JSON.stringify(privateKey.export({ format: 'jwk' })))} ;
            dct:created ${sparqlEscapeDateTime(new Date())} .
        }
      }
    `);
  }

  async fetchAuthorizationRequest(session: string) {
    const result = await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      SELECT ?nonce ?privateKey WHERE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest a ext:AuthorizationRequest ;
            ext:session ${sparqlEscapeUri(session)} ;
            ext:nonce ?nonce ;
            ext:ephemeralPrivateKey ?privateKey .
        }
      } LIMIT 1
    `);
    if (result.results.bindings.length === 0) {
      throw new Error(`No authorization request found for session ${session}`);
    }
    const binding = result.results.bindings[0];
    return {
      nonce: binding.nonce.value,
      privateKey: Crypto.createPrivateKey({
        key: JSON.parse(binding.privateKey.value),
        format: 'jwk',
      }),
    };
  }
}
