import { querySudo, updateSudo } from '@lblod/mu-auth-sudo';
import * as jose from 'jose';
import { sparqlEscapeDateTime, sparqlEscapeString, sparqlEscapeUri } from 'mu';
import * as Crypto from 'node:crypto';
import { createEphemeralKeyPair, getPrivateKeyAsCryptoKey } from './crypto';
import { SDJwtVCService } from './sd-jwt-vc';

const EPHEMERAL_KEY_TTL = 10 * 60 * 1000; // 10 minutes
export class VCVerifier {
  ready = false;
  sdJwtService: SDJwtVCService;
  async setup({ sdJwtService }: { sdJwtService: SDJwtVCService }) {
    this.ready = true;
    this.sdJwtService = sdJwtService;
  }

  async buildAuthorizationRequestUri(session: string) {
    //const clientId = `decentralized_identifier:${process.env.ISSUER_DID}`; // TODO older spec doesn't use a prefix and using it breaks paradym
    const clientId = `${process.env.ISSUER_DID}`;
    const requestUri = `${process.env.ISSUER_URL}/vc-issuer/authorization-request?original-session=${encodeURIComponent(session)}`; // TODO change to verifier? we're both atm
    const authorizationRequestUri = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
    await this.removeAllAuthorizationRequestsForSession(session);
    await this.createPendingAuthorizationRequest(session);

    return {
      authorizationRequestUri,
    };
  }

  async createPendingAuthorizationRequest(session: string) {
    const id = crypto.randomUUID();
    const uri = `http://mu.semte.ch/vocabularies/ext/authorization-request/${id}`;

    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>
      INSERT DATA {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ${sparqlEscapeUri(uri)} a ext:AuthorizationRequest ;
            ext:session ${sparqlEscapeUri(session)} ;
            ext:status "pending" ;
            dct:modified ${sparqlEscapeDateTime(new Date())} ;
            dct:created ${sparqlEscapeDateTime(new Date())} .
        }
      }`);
  }

  async removeAllAuthorizationRequestsForSession(session: string) {
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      DELETE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest ?p ?o .
        }
      } WHERE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest a ext:AuthorizationRequest ;
            ext:session ${sparqlEscapeUri(session)} ;
            ?p ?o .
        }
      }
    `);
  }

  async getAuthorizationRequestStatus(session: string) {
    const result = await querySudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      SELECT ?status WHERE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest a ext:AuthorizationRequest ;
            ext:session ${sparqlEscapeUri(session)} ;
            ext:status ?status .
        }
      } LIMIT 1
    `);
    if (result.results.bindings.length === 0) {
      return null;
    }
    return result.results.bindings[0].status.value;
  }

  async updateAuthorizationRequestStatus(session: string, status: string) {
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>
      DELETE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest ext:status ?oldStatus .
          ?authRequest dct:modified ?oldMod .
        }
      } INSERT {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest ext:status ${sparqlEscapeString(status)} ;
            dct:modified ${sparqlEscapeDateTime(new Date())} .
        }
      } WHERE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest a ext:AuthorizationRequest ;
            ext:session ${sparqlEscapeUri(session)} ;
            dct:modified ?oldMod ;
            ext:status ?oldStatus .
        }
      }
    `);
  }

  async buildAuthorizationRequestData(
    session: string,
    originalSession: string,
    wallet_metadata: string,
    wallet_nonce: string,
  ) {
    // TODO ignoring for now
    const _walletMetadata = wallet_metadata
      ? JSON.parse(wallet_metadata)
      : undefined;
    const walletNonce = wallet_nonce;

    const dcqlQuery = {
      credentials: [
        {
          id: 'decide_credential', // this string can be anything, it's just an identifier to refer to this credential set in the credential_sets section
          format: 'dc+sd-jwt',
          meta: {
            vct_values: [process.env.ISSUER_URL],
          },
          claims: [{ path: ['decideGroups'] }, { path: ['id'] }],
        },
      ],
      credential_sets: [
        {
          options: [['decide_credential']],
          purpose:
            'We require these credentials to verify your decide group memberships.',
        },
      ],
    };
    //const clientId = `decentralized_identifier:${process.env.ISSUER_DID}`; // TODO older spec doesn't use a prefix and using it breaks paradym
    const clientId = `${process.env.ISSUER_DID}`;
    const nonce = Crypto.randomBytes(16).toString('base64url');
    const ephemeralKey = await createEphemeralKeyPair();
    const payload = {
      response_type: 'vp_token',
      client_id: clientId,
      response_uri: `${process.env.ISSUER_URL}/vc-issuer/presentation-response?original-session=${encodeURIComponent(originalSession)}`, // TODO change to verifier? we're both atm
      response_mode: 'direct_post.jwt',
      nonce,
      dcql_query: dcqlQuery,
      aud: 'https://self-issued.me/v2',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600, // 10 minutes
      client_metadata: {
        client_name: 'Decide VC Verifier',
        logo_uri: `${process.env.ISSUER_URL}/assets/logo.png`,
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
    await this.storeAuthorizationRequestKey(
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

    await this.updateAuthorizationRequestStatus(originalSession, 'received');

    return request;
    // TODO not great. if they have the session they can generate a request... do we mind?
  }

  async handlePresentationResponse(
    session: string,
    originalSession: string,
    body,
  ) {
    const { response } = body;
    if (!response) {
      throw new Error('No response field in presentation response');
    }
    const { nonce, privateKey } =
      await this.fetchAuthorizationRequestKey(session);
    const { payload, protectedHeader } = await jose.jwtDecrypt(
      response,
      privateKey,
      {
        contentEncryptionAlgorithms: ['A128GCM'],
        keyManagementAlgorithms: ['ECDH-ES'],
        // we could verify the audience here if we wanted to be sure it's meant for us
      },
    );
    const vp_token = payload.vp_token as { decide_credential?: string };
    if (!vp_token?.decide_credential) {
      throw new Error('No decide_credential in vp_token');
    }
    const credential = vp_token.decide_credential;

    console.log('payload:', payload);
    console.log('protectedHeader:', protectedHeader);

    const verified = await this.sdJwtService
      .validateAndDecodeCredential(credential, nonce)
      .then(async (res) => {
        console.log('Credential verified successfully', res);
        await this.updateAuthorizationRequestStatus(
          originalSession,
          'accepted',
        );

        return res;
      })
      .catch(async (e) => {
        console.log('Error verifying credential:', e);
        await this.updateAuthorizationRequestStatus(
          originalSession,
          'rejected',
        );
        throw new Error('Could not verify the credential');
      });

    return verified;
  }

  async storeAuthorizationRequestKey(
    session: string,
    nonce: string,
    privateKey: jose.CryptoKey,
  ) {
    const id = crypto.randomUUID();
    const uri = `http://mu.semte.ch/vocabularies/ext/authorization-request-data/${id}`;
    const privateJwk = await jose.exportJWK(privateKey);
    privateJwk.alg = 'ECDH-ES';
    privateJwk.use = 'enc';
    privateJwk.kid = 'eph';
    await this.removeExistingKeysForSession(session);
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>
      INSERT DATA {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ${sparqlEscapeUri(uri)} a ext:AuthorizationRequestEphemeralKey ;
            ext:session ${sparqlEscapeUri(session)} ;
            ext:nonce ${sparqlEscapeString(nonce)} ;
            ext:ephemeralPrivateKey ${sparqlEscapeString(JSON.stringify(privateJwk))} ;
            dct:created ${sparqlEscapeDateTime(new Date())} .
        }
      }
    `);
  }

  async removeExistingKeysForSession(session: string) {
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      DELETE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest ext:ephemeralPrivateKey ?privateKey .
        }
      } WHERE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest a ext:AuthorizationRequestEphemeralKey ;
            ext:session ${sparqlEscapeUri(session)} ;
            ext:ephemeralPrivateKey ?privateKey .
        }
      }
    `);
  }

  async fetchAuthorizationRequestKey(session: string) {
    const result = await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>
      SELECT ?nonce ?privateKey WHERE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest a ext:AuthorizationRequestEphemeralKey ;
            ext:session ${sparqlEscapeUri(session)} ;
            ext:nonce ?nonce ;
            dct:created ?created ;
            ext:ephemeralPrivateKey ?privateKey .
            FILTER(?created > ${sparqlEscapeDateTime(new Date(Date.now() - EPHEMERAL_KEY_TTL))})
        }
      } LIMIT 1
    `);
    if (result.results.bindings.length === 0) {
      throw new Error(`No authorization request found for session ${session}`);
    }
    const binding = result.results.bindings[0];
    return {
      nonce: binding.nonce.value,
      privateKey: await jose.importJWK(
        JSON.parse(binding.privateKey.value),
        'ECDH-ES',
      ),
    };
  }
}
