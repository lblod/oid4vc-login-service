import { querySudo, updateSudo } from '@lblod/mu-auth-sudo';
import * as jose from 'jose';
import { sparqlEscapeDateTime, sparqlEscapeString, sparqlEscapeUri } from 'mu';
import * as Crypto from 'node:crypto';
import {
  buildX5CFromChain,
  createEphemeralKeyPair,
  getPrivateES256KeyAsCryptoKey,
  getPrivateKeyAsCryptoKey,
  getPrivateX509KeyAsCryptoKey,
  pemToX509Hash,
} from '../utils/crypto';
import { SDJwtVCService } from './sd-jwt-vc';
import env from '../utils/environment';
import {
  getDcqlClaims,
  SessionInfo,
  updateSessionWithCredentialInfo,
} from '../utils/credential-format';
import {
  storeCredentialVerificationFailedEvent,
  storeCredentialVerificationStartedEvent,
  storeCredentialVerificationSucceededEvent,
} from '../utils/flow-event-store';
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
    if (env.VERIFIER_USE_X509) {
      clientId = `x509_hash:${pemToX509Hash()}`;
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

  async buildAndSignAuthorizationRequestData(
    originalSession: string,
    wallet_metadata: string,
    wallet_nonce: string,
  ) {
    const payload = await this.buildAuthorizationRequestData(
      originalSession,
      wallet_metadata,
      wallet_nonce,
    );
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
    if (env.VERIFIER_USE_X509) {
      alg = 'ES256';
      key = getPrivateX509KeyAsCryptoKey();
      request = await new jose.SignJWT(payload)
        .setProtectedHeader({
          alg,
          iss: env.VERIFIER_DID,
          x5c: buildX5CFromChain(),
          typ: 'oauth-authz-req+jwt',
        })
        .sign(key);
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

  async buildAuthorizationRequestData(
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
    const responseCode = Crypto.randomBytes(16).toString('base64url');
    const payload = {
      response_type: 'vp_token',
      client_id: clientId,
      response_uri: `${env.VERIFIER_URL}/presentation-response?original-session=${encodeURIComponent(originalSession)}&response_code=${encodeURIComponent(responseCode)}`,
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
        vp_formats_supported: {
          'dc+sd-jwt': {
            'sd-jwt_alg_values': ['ES256', 'EdDSA'],
            'kb-jwt_alg_values': ['ES256', 'EdDSA'],
          },
        },
        authorization_encrypted_response_alg: 'ECDH-ES',
        authorization_encrypted_response_enc: 'A128GCM',
      },
    };

    if (walletNonce) {
      payload['wallet_nonce'] = walletNonce;
    }
    await this.storeAuthorizationRequestKey(
      originalSession,
      responseCode,
      nonce,
      ephemeralKey.privateKey,
    );
    return payload;
  }

  async handlePresentationResponse(
    originalSession: string,
    responseCode: string,
    body,
  ) {
    try {
      const validated = await this.unsafeHandlePresentationResponse(
        originalSession,
        responseCode,
        body,
      );
      await this.updateAuthorizationRequestStatus(originalSession, 'accepted');
      return validated;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (e: any) {
      logger.error(
        `Verification failed — session: ${originalSession}, error: ${e.message || e}`,
      );
      await this.updateAuthorizationRequestStatus(originalSession, 'rejected');
      await storeCredentialVerificationFailedEvent(
        originalSession,
        e.message || e,
      );
      throw new Error('Could not verify the credential');
    }
  }

  async unsafeHandlePresentationResponse(
    originalSession: string,
    responseCode: string,
    body,
  ) {
    const { response } = body;
    if (!response) {
      throw new Error('No response field in presentation response');
    }

    await storeCredentialVerificationStartedEvent(originalSession);
    logger.info(`Verification started — session: ${originalSession}`);

    const { nonce, privateKey } = await this.fetchAuthorizationRequestKey(
      originalSession,
      responseCode,
    );

    const { payload, protectedHeader } = await jose
      .jwtDecrypt(response, privateKey, {
        contentEncryptionAlgorithms: ['A128GCM'],
        keyManagementAlgorithms: ['ECDH-ES'],
        // we could verify the audience here if we wanted to be sure it's meant for us
      })
      .catch(async (e) => {
        const errorMessage = e instanceof Error ? e.message : String(e);
        const message = `Error decrypting presentation response: ${errorMessage}`;
        logger.error(
          `Verification failed — session: ${originalSession}, error: ${message}`,
        );
        await this.updateAuthorizationRequestStatus(
          originalSession,
          'rejected',
        );
        await storeCredentialVerificationFailedEvent(originalSession, message);
        throw e;
      });

    const vp_token = payload.vp_token as { roles_credential?: string };
    if (!vp_token?.roles_credential) {
      const message = 'No roles_credential in vp_token';
      logger.error(
        `Verification failed — session: ${originalSession}, error: ${message}`,
      );
      await this.updateAuthorizationRequestStatus(originalSession, 'rejected');
      await storeCredentialVerificationFailedEvent(originalSession, message);
      throw new Error(message);
    }
    const credential = vp_token.roles_credential;

    logger.debug(`payload: ${JSON.stringify(payload, null, 2)}`);
    logger.debug(
      `protectedHeader: ${JSON.stringify(protectedHeader, null, 2)}`,
    );

    const firstCredential = credential[0];
    const credentialHeader = jose.decodeProtectedHeader(firstCredential) as {
      kid?: string;
    };
    const credentialPayload = jose.decodeJwt(
      firstCredential.split('.').slice(0, 3).join('.'),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ) as any;
    const iss = credentialPayload?.iss;

    if (!(await this.isTrustedIssuer(iss))) {
      throw new Error('Credential issuer is not trusted');
    }

    const validatedCredential =
      await this.sdJwtService.validateAndDecodeCredential(
        iss,
        firstCredential,
        nonce,
        credentialHeader.kid,
      );
    const validatedPayload = validatedCredential.payload;

    logger.debug(
      `Credential verified successfully: ${JSON.stringify(validatedCredential, null, 2)}`,
    );

    await updateSessionWithCredentialInfo(
      originalSession,
      validatedPayload as unknown as SessionInfo,
    ).catch(async (e) => {
      const errorMessage = e instanceof Error ? e.message : String(e);
      const message = `Error updating session with credential info: ${errorMessage}`;
      logger.error(
        `Verification failed — session: ${originalSession}, error: ${message}`,
      );
      await this.updateAuthorizationRequestStatus(originalSession, 'rejected');
      await storeCredentialVerificationFailedEvent(originalSession, message);
      throw e;
    });

    await this.updateAuthorizationRequestStatus(originalSession, 'accepted');

    const sessionInfo = validatedPayload as unknown as SessionInfo;
    await storeCredentialVerificationSucceededEvent(
      originalSession,
      sessionInfo,
    );
    logger.info(
      `Verification succeeded — session: ${originalSession}, account: ${sessionInfo.accountUri}, group: ${sessionInfo.group}, roles: ${sessionInfo.roles}`,
    );

    return validatedCredential;
  }

  async storeAuthorizationRequestKey(
    session: string,
    responseCode: string,
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
            ext:responseCode ${sparqlEscapeString(responseCode)} ;
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

  async fetchAuthorizationRequestKey(session: string, responseCode: string) {
    const result = await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>
      SELECT ?nonce ?privateKey WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?authRequest a ext:AuthorizationRequestEphemeralKey ;
            ext:verifierUrl ${sparqlEscapeString(env.VERIFIER_URL)} ;
            ext:session ${sparqlEscapeUri(session)} ;
            ext:responseCode ${sparqlEscapeString(responseCode)} ;
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

  async isTrustedIssuer(issuer: string) {
    // async in case we ever want to make this more complex

    return env.TRUSTED_ISSUERS.includes(issuer);
  }
}
