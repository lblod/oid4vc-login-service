import { querySudo, updateSudo } from '@lblod/mu-auth-sudo';
import * as jose from 'jose';
import { sparqlEscapeDateTime, sparqlEscapeString, sparqlEscapeUri } from 'mu';
import * as Crypto from 'node:crypto';
import {
  createEphemeralKeyPair,
  getPrivateKeyAsCryptoKey,
} from '../utils/crypto';
import { SDJwtVCService } from './sd-jwt-vc';
import env from '../utils/environment';
import {
  getDcqlClaims,
  SessionInfo,
  updateSessionWithCredentialInfo,
} from '../utils/credential-format';
import { logger } from '../utils/logger';

export class VCVerifier {
  ready = false;
  sdJwtService: SDJwtVCService;
  async setup({ sdJwtService }: { sdJwtService: SDJwtVCService }) {
    this.ready = true;
    this.sdJwtService = sdJwtService;
  }

  async buildAuthorizationRequestUri(session: string) {
    const clientId = this.buildClientId();
    const requestUri = `${env.VERIFIER_URL}/authorization-request?original-session=${encodeURIComponent(session)}`;
    const authorizationRequestUri = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
    await this.removeAllAuthorizationRequestsForSession(session);
    await this.createPendingAuthorizationRequest(session);

    return {
      authorizationRequestUri,
    };
  }

  buildClientId() {
    let clientId = `decentralized_identifier:${env.VERIFIER_DID}`;
    // because of old spec versions, some wallets break without this
    if (env.NO_DID_PREFIX) {
      clientId = env.VERIFIER_DID;
    }
    return clientId;
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
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
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
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
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
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
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
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
            ext:session ${sparqlEscapeUri(session)} ;
            dct:modified ?oldMod ;
            ext:status ?oldStatus .
        }
      }
    `);
  }

  async removeOldAuthorizationRequests() {
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>
      DELETE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest ?p ?o .
        }
      } WHERE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest a ext:AuthorizationRequest ;
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
            dct:created ?created ;
            ?p ?o .
            FILTER(?created < ${sparqlEscapeDateTime(new Date(Date.now() - env.AUTHORIZATION_REQUEST_TTL))})
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
    // ignoring for now, we only support a small set of algorithms so no need to negotiate
    const _walletMetadata = wallet_metadata
      ? JSON.parse(wallet_metadata)
      : undefined;
    const walletNonce = wallet_nonce;

    const dcqlQuery = {
      credentials: [
        {
          id: 'roles_credential', // this string can be anything, it's just an identifier to refer to this credential set in the credential_sets section
          format: 'dc+sd-jwt',
          meta: {
            vct_values: [env.ISSUER_URL],
          },
          claims: getDcqlClaims(),
        },
      ],
      credential_sets: [
        {
          options: [['roles_credential']],
          purpose:
            'We require these credentials to verify your decide group memberships.',
        },
      ],
    };
    const clientId = this.buildClientId();
    const nonce = Crypto.randomBytes(16).toString('base64url');
    const ephemeralKey = await createEphemeralKeyPair();
    const payload = {
      response_type: 'vp_token',
      client_id: clientId,
      response_uri: `${env.VERIFIER_URL}/presentation-response?original-session=${encodeURIComponent(originalSession)}`,
      response_mode: 'direct_post.jwt',
      nonce,
      dcql_query: dcqlQuery,
      aud: 'https://self-issued.me/v2',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600, // 10 minutes
      client_metadata: {
        client_name: `${env.PROJECT_NAME} VC Verifier`,
        logo_uri: env.LOGO_URL,
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
        kid: env.VERIFIER_KEY_ID,
        iss: env.VERIFIER_DID,
        typ: 'oauth-authz-req+jwt',
      })
      .sign(getPrivateKeyAsCryptoKey());

    await this.updateAuthorizationRequestStatus(originalSession, 'received');

    return request;
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
    const vp_token = payload.vp_token as { roles_credential?: string };
    if (!vp_token?.roles_credential) {
      throw new Error('No roles_credential in vp_token');
    }
    const credential = vp_token.roles_credential;

    logger.debug('payload:', payload);
    logger.debug('protectedHeader:', protectedHeader);

    const verified = await this.sdJwtService
      .validateAndDecodeCredential(credential, nonce)
      .then(async (res) => {
        const payload = res.payload;
        await updateSessionWithCredentialInfo(
          originalSession,
          payload as SessionInfo,
        );
        logger.debug('Credential verified successfully', res);
        await this.updateAuthorizationRequestStatus(
          originalSession,
          'accepted',
        );

        return res;
      })
      .catch(async (e) => {
        logger.error('Error verifying credential:', e);
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
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
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
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
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
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
            ext:session ${sparqlEscapeUri(session)} ;
            ext:nonce ?nonce ;
            dct:created ?created ;
            ext:ephemeralPrivateKey ?privateKey .
            FILTER(?created > ${sparqlEscapeDateTime(new Date(Date.now() - env.AUTHORIZATION_REQUEST_TTL))})
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

  async removeOldAuthorizationRequestKeys() {
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>
      DELETE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest ext:ephemeralPrivateKey ?privateKey .
        }
      } WHERE {
        GRAPH <http://mu.semte.ch/graphs/decide/verifier> {
          ?authRequest a ext:AuthorizationRequestEphemeralKey ;
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
            dct:created ?created ;
            ext:ephemeralPrivateKey ?privateKey .
            FILTER(?created < ${sparqlEscapeDateTime(new Date(Date.now() - env.AUTHORIZATION_REQUEST_TTL))})
        }
      }
    `);
  }
}
