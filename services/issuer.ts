import * as jose from 'jose';
import jsonld from 'jsonld';

// Required to set up a suite instance with private key
import * as didJwk from '@digitalbazaar/did-method-jwk';
import * as didKey from '@digitalbazaar/did-method-key';
import * as didWeb from '@digitalbazaar/did-method-web';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { securityLoader } from '@digitalbazaar/security-document-loader';
import { updateSudo, querySudo } from '@lblod/mu-auth-sudo';
import * as crypto from 'crypto';
import { randomBytes } from 'crypto';
import {
  sparqlEscapeDateTime,
  sparqlEscapeString,
  sparqlEscapeUri,
  uuid,
} from 'mu';
import { resolveDid } from '../utils/crypto';
import env from '../utils/environment';
import { SDJwtVCService } from './sd-jwt-vc';
import { SessionInfo } from '../utils/credential-format';
import { logger } from '../utils/logger';

export class VCIssuer {
  ready = false;
  suite;
  keyPair;
  documentLoader: (url: string) => Promise<unknown>;
  issuerDid: string;
  sdJwtService: SDJwtVCService;

  get isReady() {
    return this.ready && this.sdJwtService?.ready;
  }

  async setup({
    issuerDid,
    issuerKeyId,
    publicKey,
    privateKey,
    sdJwtService,
  }: {
    issuerDid: string;
    issuerKeyId: string;
    publicKey: string;
    privateKey: string;
    sdJwtService?: SDJwtVCService;
  }) {
    const keyPair = await Ed25519VerificationKey2020.from({
      type: 'Ed25519VerificationKey2020',
      controller: issuerDid,
      id: issuerKeyId,
      publicKeyMultibase: publicKey,
      privateKeyMultibase: privateKey,
    });
    this.sdJwtService = sdJwtService;

    const loader = securityLoader();
    loader.setProtocolHandler({
      protocol: 'https',
      handler: {
        get: async ({ url }) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const result = await (jsonld as any).get(url, {});

          return result.document;
        },
      },
    });
    const didKeyDriver = didKey.driver();
    const didWebDriver = didWeb.driver();
    const didJwkDriver = didJwk.driver();
    // did:key is included by default, but let's be explicit
    loader.protocolHandlers.get('did').use(didKeyDriver);
    loader.protocolHandlers.get('did').use(didWebDriver);
    loader.protocolHandlers.get('did').use(didJwkDriver);

    this.issuerDid = issuerDid;
    this.documentLoader = loader.build();
    this.keyPair = keyPair;
    this.suite = new Ed25519Signature2020({ key: keyPair });
    this.ready = true;
  }

  // jwk is the public key that corresponds to the did (we already resolved it during verification, so let's not do so again)
  async issueCredential(
    holderDid: string,
    jwk,
    sessionInfo: SessionInfo,
    walletSession: string,
  ) {
    const res = this.sdJwtService.buildCredential(holderDid, jwk, sessionInfo);
    await this.updateIssuanceStatusForWalletSession(walletSession, 'issued');
    return res;
  }

  async buildCredentialOfferUri(sessionUri: string) {
    const randomUuid = crypto.randomUUID(); // use proper random algorithm instead of mu version
    const credentialOffer = {
      credential_issuer: env.ISSUER_URL as string,
      credential_configuration_ids: [`${env.CREDENTIAL_TYPE}_sd_jwt`],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': randomUuid,
        },
      },
    };
    await this.storeCredentialOfferAuthCode(randomUuid, sessionUri);
    const credentialOfferUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credentialOffer))}`;
    return {
      credentialOfferUri,
    };
  }

  credentialTokenUriPrefix = 'http://data.lblod.info/credential-offer-token/';
  authCodeTTL = env.AUTH_CODE_TTL;
  tokenTTL = env.TOKEN_TTL;

  async storeCredentialOfferAuthCode(token, sessionUri) {
    const tokenUri = `${this.credentialTokenUriPrefix}${token}`;

    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      DELETE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?s ?p ?o.
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?s a ext:IssuanceStatus ;
            ext:session ${sparqlEscapeUri(sessionUri)} .
        }
      }`);

    // need to use the token for the issuance status as we need to link walletsession to it later
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX dct: <http://purl.org/dc/terms/>

      INSERT DATA {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ${sparqlEscapeUri(tokenUri)} a ext:CredentialOfferAuthCode, ext:IssuanceStatus ;
            ext:issuerUrl ${sparqlEscapeString(env.ISSUER_URL)} ;
            mu:uuid ${sparqlEscapeString(token)} ;
            ext:session ${sparqlEscapeUri(sessionUri)} ;
            dct:modified ${sparqlEscapeDateTime(new Date())} ;
            dct:created ${sparqlEscapeDateTime(new Date())} .
        }
      }`);
  }

  async getSessionForAuthCode(token) {
    const result = await querySudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX dct: <http://purl.org/dc/terms/>

      SELECT ?session {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?token a ext:CredentialOfferAuthCode .
          ?token ext:issuerUrl ${sparqlEscapeString(env.ISSUER_URL)} .
          ?token mu:uuid ${sparqlEscapeString(token)} .
          ?token dct:created ?created .
          ?token ext:session ?session .
          FILTER(?created > ${sparqlEscapeDateTime(new Date(Date.now() - this.authCodeTTL))})
        }
      } LIMIT 1`);
    return result.results.bindings[0]?.session.value;
  }

  async removeOldCredentialAuthCodes() {
    // note: using tokenTTL here instead of authCodeTTL to be sure we don't remove codes that are still in use by wallets
    // we need them for session tracking
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>

      DELETE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?token ?p ?o.
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?token a ext:CredentialOfferAuthCode .
          ?token ext:issuerUrl ${sparqlEscapeString(env.ISSUER_URL)} .
          ?token dct:created ?created .
          FILTER(?created < ${sparqlEscapeDateTime(new Date(Date.now() - this.tokenTTL))})
          ?token ?p ?o.
        }
      }`);
  }

  async generateCredentialOfferToken(
    sessionUri: string,
    walletSession: string,
  ) {
    const token = randomBytes(512).toString('hex');
    await this.storeCredentialOfferToken(token, sessionUri);
    await this.markIssuanceStatusReceived(sessionUri, walletSession);
    return token;
  }

  async storeCredentialOfferToken(token, sessionUri) {
    const id = uuid();
    const tokenUri = `${this.credentialTokenUriPrefix}${id}`;

    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX dct: <http://purl.org/dc/terms/>

      INSERT DATA {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ${sparqlEscapeUri(tokenUri)} a ext:CredentialOfferToken ;
            ext:issuerUrl ${sparqlEscapeString(env.ISSUER_URL)} ;
            mu:uuid ${sparqlEscapeString(id)} ;
            ext:authToken ${sparqlEscapeString(token)} ;
            ext:session ${sparqlEscapeUri(sessionUri)} ;
            dct:created ${sparqlEscapeDateTime(new Date())} .
        }
      }`);
  }

  async removeOldCredentialOfferTokens() {
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>

      DELETE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?token ?p ?o.
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?token a ext:CredentialOfferToken .
          ?token ext:issuerUrl ${sparqlEscapeString(env.ISSUER_URL)} .
          ?token dct:created ?created .
          FILTER(?created < ${sparqlEscapeDateTime(new Date(Date.now() - this.tokenTTL))})
          ?token ?p ?o.
        }
      }`);
  }

  async generateNonce(session: string) {
    const nonce = randomBytes(16).toString('hex');
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

      DELETE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ${sparqlEscapeUri(session)} ext:nonce ?oldNonce ;
            ext:nonceCreated ?created .
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ${sparqlEscapeUri(session)} ext:nonce ?oldNonce ;
            ext:nonceCreated ?created .
        }
      }`);
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      INSERT DATA {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ${sparqlEscapeUri(session)} ext:nonce ${sparqlEscapeString(nonce)} ;
            ext:nonceCreated ${sparqlEscapeDateTime(new Date())} .
        }
      }`);
    return nonce;
  }

  async getExpectedNonceForSession(session: string) {
    const result = await querySudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

      SELECT ?nonce WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ${sparqlEscapeUri(session)} ext:nonce ?nonce ;
            ext:nonceCreated ?created .
          FILTER(?created > ${sparqlEscapeDateTime(new Date(Date.now() - env.NONCE_TTL))})
        }
      } LIMIT 1`);
    return result.results.bindings[0]?.nonce.value;
  }

  async removeOldNonces() {
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

      DELETE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?session ext:nonce ?nonce ;
            ext:nonceCreated ?created .
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?session ext:nonce ?nonce ;
            ext:nonceCreated ?created .
          FILTER(?created < ${sparqlEscapeDateTime(new Date(Date.now() - env.NONCE_TTL))})
        }
      }`);
  }

  async validateProofAndGetHolderDid(jwt: string, expectedNonce: string) {
    const [jwtHeader, jwtPayload] = jwt.split('.');
    const decodedJwtHeader = JSON.parse(atob(jwtHeader));
    const decodedJwtPayload = JSON.parse(atob(jwtPayload));
    if (decodedJwtPayload.nonce !== expectedNonce) {
      logger.debug(`expected nonce: ${expectedNonce}`);
      throw new Error('invalid_nonce');
    }
    const did = decodedJwtHeader.kid;
    if (!did || !did.startsWith('did:')) {
      throw new Error('invalid_proof');
    }
    // validate signature:
    const result = await resolveDid(did).catch((e) => {
      logger.error(`failed to resolve did: ${e}`);
      return null;
    });
    if (!result || !result.didDocument) {
      throw new Error('invalid_proof');
    }
    // validate signature:
    const jwk = await this.verifyJwtSignature(
      decodedJwtHeader,
      jwt,
      result.didDocument,
    ).catch((e) => {
      logger.error(`failed to verify signature: ${e}`);
      throw new Error('invalid_proof');
    });

    return { did, jwk };
  }

  async verifyJwtSignature(decodedJwtHeader, originalJwt: string, didDocument) {
    if (!didDocument.verificationMethod) {
      throw new Error('No verification method found in DID document');
    }
    const verificationMethod = didDocument.verificationMethod.find(
      (vm) => vm.id === decodedJwtHeader.kid,
    );
    if (!verificationMethod) {
      throw new Error('No matching verification method found in DID document');
    }
    if (verificationMethod.type !== 'JsonWebKey2020') {
      throw new Error(
        `Unsupported verification method type: ${verificationMethod.type}`,
      );
    }
    const publicKeyJwk = verificationMethod.publicKeyJwk;
    if (!publicKeyJwk) {
      throw new Error('No public key JWK found in verification method');
    }
    // verify the signature
    const alg = decodedJwtHeader.alg;
    // only EdDSA and ES256 for now
    if (alg !== 'EdDSA' && alg !== 'ES256') {
      throw new Error(`Unsupported algorithm: ${alg}`);
    }
    const jwtKey = await jose.importJWK(publicKeyJwk, alg);
    await jose.jwtVerify(originalJwt, jwtKey);
    return publicKeyJwk;
  }

  async markIssuanceStatusReceived(sessionUri: string, walletSession: string) {
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>

      DELETE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?s a ext:IssuanceStatus ;
            ext:status ?status ;
            ext:walletSession ?ws ;
            dct:modified ?modified .
        }
      } INSERT {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?s a ext:IssuanceStatus ;
            ext:walletSession ${sparqlEscapeUri(walletSession)} ;
            ext:status "received" ;
            dct:modified ${sparqlEscapeDateTime(new Date())} .
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?s a ext:IssuanceStatus ;
            ext:session ${sparqlEscapeUri(sessionUri)} ;
            ext:status ?status ;
            dct:modified ?modified .
          OPTIONAL { ?s ext:walletSession ?ws . }
        }
      }`);
  }

  async updateIssuanceStatusForWalletSession(
    walletSession: string,
    status: 'issued' | 'error',
  ) {
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>

      DELETE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?s a ext:IssuanceStatus ;
            ext:status ?status ;
            dct:modified ?modified .
        }
      } INSERT {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?s a ext:IssuanceStatus ;
            ext:status ${sparqlEscapeString(status)} ;
            dct:modified ${sparqlEscapeDateTime(new Date())} .
        }
      } WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?s a ext:IssuanceStatus ;
            ext:walletSession ${sparqlEscapeUri(walletSession)} ;
            ext:status ?status ;
            dct:modified ?modified .
        }
      }`);
  }

  async getIssuanceStatus(sessionUri: string) {
    const result = await querySudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>

      SELECT ?status ?created ?modified WHERE {
        GRAPH ${sparqlEscapeUri(env.WORKING_GRAPH)} {
          ?s a ext:IssuanceStatus ;
            ext:session ${sparqlEscapeUri(sessionUri)} ;
            ext:status ?status ;
            dct:modified ?modified ;
            dct:created ?created .
        }
      }`);
    if (result.results.bindings.length === 0) {
      return null;
    }
    const { status, created, modified } = result.results.bindings[0];
    return {
      status: status.value,
      created: created.value,
      modified: modified.value,
    };
  }
}
