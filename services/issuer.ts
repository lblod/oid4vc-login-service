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
  async issueCredential(holderDid: string, jwk, sessionInfo: SessionInfo) {
    return this.sdJwtService.buildCredential(holderDid, jwk, sessionInfo);
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
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX dct: <http://purl.org/dc/terms/>

      INSERT DATA {
        GRAPH <http://mu.semte.ch/graphs/verifiable-credential-tokens> {
          ${sparqlEscapeUri(tokenUri)} a ext:CredentialOfferAuthCode ;
            ext:issuerUrl ${sparqlEscapeString(env.ISSUER_URL)} ;
            mu:uuid ${sparqlEscapeString(token)} ;
            ext:session ${sparqlEscapeUri(sessionUri)} ;
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
        GRAPH <http://mu.semte.ch/graphs/verifiable-credential-tokens> {
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
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>

      DELETE {
        GRAPH ?g {
          ?token ?p ?o.
        }
      } WHERE {
        GRAPH ?g {
          ?token a ext:CredentialOfferAuthCode .
          ?token ext:issuerUrl ${sparqlEscapeString(env.ISSUER_URL)} .
          ?token dct:created ?created .
          FILTER(?created < ${sparqlEscapeDateTime(new Date(Date.now() - this.authCodeTTL))})
          ?token ?p ?o.
        }
      }`);
  }

  async generateCredentialOfferToken(sessionUri) {
    const token = randomBytes(512).toString('hex');
    await this.storeCredentialOfferToken(token, sessionUri);
    return token;
  }

  async storeCredentialOfferToken(token, sessionUri) {
    const id = uuid();
    const tokenUri = `${this.credentialTokenUriPrefix}${id}`;
    // TODO i think we should use the account here as the session may be fleeting
    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX dct: <http://purl.org/dc/terms/>

      INSERT DATA {
        GRAPH <http://mu.semte.ch/graphs/verifiable-credential-tokens> {
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
      DELETE {
        GRAPH ?g {
          ?token ?p ?o.
        }
      } WHERE {
        GRAPH ?g {
          ?token a ext:CredentialOfferToken .
          ?token ext:issuerUrl ${sparqlEscapeString(env.ISSUER_URL)} .
          ?token dct:created ?created .
          FILTER(?created < ${sparqlEscapeDateTime(new Date(Date.now() - this.tokenTTL))})
          ?token ?p ?o.
        }
      }`);
  }

  async generateNonce() {
    // TODO store and check nonce. we just generate a random nonce for now, we should store and verify it to protect against replay attacks
    return randomBytes(16).toString('hex');
  }

  async validateProofAndGetHolderDid(jwt: string) {
    const [jwtHeader] = jwt.split('.');
    const decodedJwtHeader = JSON.parse(atob(jwtHeader));
    const did = decodedJwtHeader.kid;
    if (!did || !did.startsWith('did:')) {
      throw new Error('invalid_proof');
    }
    // validate signature:
    const result = await resolveDid(did).catch((e) => {
      console.error('failed to resolve did:', e);
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
      console.error('failed to verify signature:', e);
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
}
