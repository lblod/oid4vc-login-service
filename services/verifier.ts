import { querySudo, updateSudo } from '@lblod/mu-auth-sudo';
import * as jose from 'jose';
import { sparqlEscapeDateTime, sparqlEscapeString, sparqlEscapeUri } from 'mu';
import * as Crypto from 'node:crypto';
import {
  createEphemeralKeyPair,
  getPrivateES256KeyAsCryptoKey,
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
import jwt from 'jsonwebtoken';

export class VCVerifier {
  ready = false;
  sdJwtService: SDJwtVCService;
  async setup({ sdJwtService }: { sdJwtService: SDJwtVCService }) {
    this.ready = true;
    this.sdJwtService = sdJwtService;
  }

  async buildAuthorizationRequestUri(session: string) {
    const clientId = this.buildClientId(session);
    const requestUri = `${env.VERIFIER_URL}/authorization-request?original-session=${encodeURIComponent(session)}`;
    const authorizationRequestUri = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}&client_id=${encodeURIComponent(clientId)}`;
    await this.removeAllAuthorizationRequestsForSession(session);
    await this.createPendingAuthorizationRequest(session);

    return {
      authorizationRequestUri,
    };
  }

  buildClientId(session) {
    let clientId = `decentralized_identifier:${env.VERIFIER_DID}`;
    // because of old spec versions, some wallets break without this
    if (env.NO_DID_PREFIX) {
      clientId = env.VERIFIER_DID;
    }
    if (env.VERIFIER_UNSIGNED) {
      clientId = `redirect_uri:${env.VERIFIER_URL}/presentation-response?original-session=${encodeURIComponent(session)}`;
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
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
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
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?authRequest ?p ?o .
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
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
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
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
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?authRequest ext:status ?oldStatus .
          ?authRequest dct:modified ?oldMod .
        }
      } INSERT {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?authRequest ext:status ${sparqlEscapeString(status)} ;
            dct:modified ${sparqlEscapeDateTime(new Date())} .
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
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
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?authRequest ?p ?o .
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
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
    const clientId = this.buildClientId(originalSession);
    const nonce = Crypto.randomBytes(16).toString('base64url');
    const ephemeralKey = await createEphemeralKeyPair();
    const payload = {
      response_type: 'vp_token',
      client_id: clientId,
      // todo should add randomness here according to spec
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
      } as unknown,
    };
    if (env.VERIFIER_UNSIGNED) {
      payload.response_mode = 'direct_post';
      payload.client_metadata = {
        client_name: `${env.PROJECT_NAME} VC Verifier`,
        logo_uri: env.LOGO_URL,
      };
    } else {
      if (walletNonce) {
        payload['wallet_nonce'] = walletNonce;
      }
      await this.storeAuthorizationRequestKey(
        session,
        nonce,
        ephemeralKey.privateKey,
      );
    }
    let key = null;
    let keyId = null;
    let alg = null;
    if (env.VERIFIER_ES256_PRIVATE_KEY) {
      key = getPrivateES256KeyAsCryptoKey(env.VERIFIER_ES256_PRIVATE_KEY);
      keyId = env.VERIFIER_ES256_KEY_ID;
      alg = 'ES256';
    } else {
      key = getPrivateKeyAsCryptoKey(env.VERIFIER_PRIVATE_KEY);
      keyId = env.VERIFIER_KEY_ID;
      alg = 'EdDSA';
    }
    let request = null;
    if (env.VERIFIER_UNSIGNED) {
      // can't use jose's unsecuredjwt as it doesn't allow setting typ header atm and can't use signJWT as it requires an alg and none isn't an option
      request = jwt.sign(payload, 'fakekeyunused', {
        algorithm: 'none',
        header: { typ: 'oauth-authz-req+jwt' },
      });
    } else {
      // request is jwt signed with our private key
      request = await new jose.SignJWT(payload)
        .setProtectedHeader({
          alg: alg,
          kid: keyId,
          iss: env.VERIFIER_DID,
          typ: 'oauth-authz-req+jwt',
        })
        .sign(key);
    }
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

    logger.debug(`payload: ${JSON.stringify(payload, null, 2)}`);
    logger.debug(
      `protectedHeader: ${JSON.stringify(protectedHeader, null, 2)}`,
    );

    // old specs don't provide an array here.
    // we only use the first credential we receive
    const safeCredential = credential.split ? credential : credential[0];

    const verified = await this.sdJwtService
      .validateAndDecodeCredential(safeCredential, nonce)
      .then(async (res) => {
        const payload = res.payload;
        await updateSessionWithCredentialInfo(
          originalSession,
          payload as SessionInfo,
        );

        if (!(await this.isTrustedIssuer(res))) {
          throw new Error('Credential issuer is not trusted');
        }
        logger.debug(
          `Credential verified successfully: ${JSON.stringify(res, null, 2)}`,
        );
        await this.updateAuthorizationRequestStatus(
          originalSession,
          'accepted',
        );

        return res;
      })
      .catch(async (e) => {
        logger.error(`Error verifying credential: ${e}`);
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
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
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
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?authRequest ext:ephemeralPrivateKey ?privateKey .
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
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
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
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
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?authRequest ext:ephemeralPrivateKey ?privateKey .
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?authRequest a ext:AuthorizationRequestEphemeralKey ;
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
            dct:created ?created ;
            ext:ephemeralPrivateKey ?privateKey .
            FILTER(?created < ${sparqlEscapeDateTime(new Date(Date.now() - env.AUTHORIZATION_REQUEST_TTL))})
        }
      }
    `);
  }

  async isTrustedIssuer(credentialVerificationResult) {
    // async in case we ever want to make this more complex

    return env.TRUSTED_ISSUERS.includes(
      credentialVerificationResult.payload.iss,
    );
  }
}
