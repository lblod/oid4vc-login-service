import jsonld from 'jsonld';
import * as jose from 'jose';

import * as vc from '@digitalbazaar/vc';

// Required to set up a suite instance with private key
import * as didJwk from '@digitalbazaar/did-method-jwk';
import * as didKey from '@digitalbazaar/did-method-key';
import * as didWeb from '@digitalbazaar/did-method-web';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { securityLoader } from '@digitalbazaar/security-document-loader';
import { updateSudo } from '@lblod/mu-auth-sudo';
import { randomBytes, randomUUID } from 'crypto';
import * as crypto from 'crypto';
import {
  sparqlEscapeDateTime,
  sparqlEscapeString,
  sparqlEscapeUri,
  uuid,
} from 'mu';
import { SDJwtVCService } from './sd-jwt-vc';
import { resolveDid } from './crypto';

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
  }: {
    issuerDid: string;
    issuerKeyId: string;
    publicKey: string;
    privateKey: string;
  }) {
    const keyPair = await Ed25519VerificationKey2020.from({
      type: 'Ed25519VerificationKey2020',
      controller: issuerDid,
      id: issuerKeyId,
      publicKeyMultibase: publicKey,
      privateKeyMultibase: privateKey,
    });
    this.sdJwtService = new SDJwtVCService();
    await this.sdJwtService.setup();

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

  async issueCredential(holderDid: string) {
    // TODO ldpvc has no support atm
    return this.issueCredentialSdJwtVc(holderDid);
  }

  // for demo purposes for now, we will need to issue a credential containing the roles in the data space
  async issueCredentialLdpVc(holderDid: string) {
    // Sample unsigned credential
    const credentialBase =
      process.env.CREDENTIAL_URI_BASE || 'http://localhost/credential/';
    const credentialUri = `${credentialBase}${randomUUID()}`;
    const credential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://www.w3.org/2018/credentials/examples/v1',
      ],
      id: credentialUri,
      type: ['VerifiableCredential', 'AlumniCredential'],
      issuer: this.issuerDid,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: holderDid,
        alumniOf: 'Example University',
      },
    };
    const signedVC = await vc.issue({
      credential,
      suite: this.suite,
      documentLoader: this.documentLoader,
    });

    // normally you'd verify the presentation, but let's already verify the credential
    const verificationResult = await this.verifyLdpCredential(signedVC);
    console.log(verificationResult);

    return signedVC;
  }

  async issueCredentialSdJwtVc(holderDid: string) {
    return this.sdJwtService.buildCredential(holderDid);
  }

  // for demo purposes, normally the verifier would do this
  // ignore ts for now as vc library does not have types support
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async verifyLdpCredential(signedVC: any) {
    const verificationResult = await vc.verifyCredential({
      credential: signedVC,
      suite: this.suite,
      documentLoader: this.documentLoader,
    });

    return verificationResult;
  }
  async buildCredentialOfferUri(sessionUri: string) {
    // const pin = randomInt(0, 9999);
    const randomUuid = crypto.randomUUID(); // this one is important to use proper random libs though
    const credentialOffer = {
      credential_issuer: process.env.ISSUER_URL as string,
      credential_configuration_ids: [`${process.env.CREDENTIAL_TYPE}_sd_jwt`],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': randomUuid,
          // tx_code: {
          //   // might be better to leave this out entirely as we won't be mailing it
          //   length: 4,
          //   input_mode: 'numeric',
          //   description: 'Enter the 4-digit code shown on your screen', // we should send by mail/text message in a real example to have multiple channels
          // },
        },
      },
    };
    await this.storeCredentialOfferAuthCode(randomUuid, sessionUri);
    const credentialOfferUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credentialOffer))}`;
    return {
      credentialOfferUri,
    };
  }

  async validateAuthToken(token: string) {
    const result = await this.getSessionInfoForCredentialOfferToken(token);

    if (result.results.bindings.length === 0) {
      return null;
    }
    const groups = {};
    result.results.bindings.forEach(async (binding) => {
      const group = binding.group.value;
      const role = binding.role.value;
      if (!groups[group]) {
        groups[group] = [];
      }
      groups[group].push(role);
    });
    return groups;
  }

  credentialTokenUriPrefix = 'http://data.lblod.info/credential-offer-token/';
  authCodeTTL = parseInt(process.env.AUTH_CODE_TTL || '60000'); // 1min
  tokenTTL = parseInt(process.env.TOKEN_TTL || '86400'); // 24h

  async storeCredentialOfferAuthCode(token, sessionUri, pinCode?: number) {
    const tokenUri = `${this.credentialTokenUriPrefix}${token}`;
    let pinCodeData = '';
    if (pinCode !== undefined) {
      const paddedPinCode = ('0000' + pinCode).slice(-4);
      pinCodeData = `ext:pinCode ${sparqlEscapeString(paddedPinCode)} ;`;
    }

    await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX dct: <http://purl.org/dc/terms/>

      INSERT DATA {
        GRAPH <http://mu.semte.ch/graphs/verifiable-credential-tokens> {
          ${sparqlEscapeUri(tokenUri)} a ext:CredentialOfferAuthCode ;
            mu:uuid ${sparqlEscapeString(token)} ;
            ext:session ${sparqlEscapeUri(sessionUri)} ;
            ${pinCodeData}
            dct:created ${sparqlEscapeDateTime(new Date())} .
        }
      }`);
  }

  async getSessionForAuthCode(token, pinCode?: string) {
    let pinCodeCheck = 'FILTER NOT EXISTS { ?token ext:pinCode ?pinCode . }';
    if (pinCode) {
      pinCodeCheck = `?token ext:pinCode ${sparqlEscapeString(pinCode)} .`;
    }
    const result = await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX dct: <http://purl.org/dc/terms/>

      SELECT ?session {
        GRAPH <http://mu.semte.ch/graphs/verifiable-credential-tokens> {
          ?token a ext:CredentialOfferAuthCode .
          ?token mu:uuid ${sparqlEscapeString(token)} .
          ?token dct:created ?created .
          ?token ext:session ?session .
          ${pinCodeCheck}
          FILTER(?created > ${sparqlEscapeDateTime(new Date(Date.now() - this.authCodeTTL))})
        }
      } LIMIT 1`);
    return result.results.bindings[0]?.session.value;
  }

  async deleteCredentialOfferAuthCode(token) {
    await updateSudo(`
      DELETE {
        GRAPH ?g {
          ?token ?p ?o.
        }
      } WHERE {
        GRAPH ?g {
          ?token a ext:CredentialOfferAuthCode ;
          ?token mu:uuid ${token} ;
          ?token ?p ?o.
        }
      }`);
  }

  async generateCredentialOfferToken(sessionUri) {
    const token = randomBytes(32).toString('hex');
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
            mu:uuid ${sparqlEscapeString(id)} ;
            ext:authToken ${sparqlEscapeString(token)} ;
            ext:session ${sparqlEscapeUri(sessionUri)} ;
            dct:created ${sparqlEscapeDateTime(new Date())} .
        }
      }`);
  }

  async getSessionInfoForCredentialOfferToken(token) {
    const result = await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX dct: <http://purl.org/dc/terms/>

      SELECT ?session ?group ?role {
        GRAPH <http://mu.semte.ch/graphs/verifiable-credential-tokens> {
          ?token a ext:CredentialOfferToken .
          ?token ext:authToken ${sparqlEscapeString(token)} .
          ?token ext:session ?session .
          ?token dct:created ?created .
          ?session ext:sessionGroup ?group .
          ?session ext:sessionRole ?role .

          FILTER(?created > ${sparqlEscapeDateTime(new Date(Date.now() - this.tokenTTL))})
        }
      }`);
    return result;
  }

  async deleteCredentialOfferToken(token) {
    await updateSudo(`
      DELETE {
        GRAPH ?g {
          ?token ?p ?o.
        }
      } WHERE {
        GRAPH ?g {
          ?token a ext:CredentialOfferToken .
          ?token mu:uuid ${token} .
          ?token ?p ?o.
        }
      }`);
  }

  async generateNonce() {
    // we just generate a random nonce for now, we should store and verify it to protect against replay attacks
    return randomBytes(16).toString('hex');
  }

  async validateProofAndGetHolderDid(jwt: string) {
    const [jwtHeader] = jwt.split('.');
    const decodedJwtHeader = JSON.parse(atob(jwtHeader));
    // todo we should validate the proof, but for now let's trust it
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
    await this.verifyJwtSignature(
      decodedJwtHeader,
      jwt,
      result.didDocument,
    ).catch((e) => {
      console.error('failed to verify signature:', e);
      throw new Error('invalid_proof');
    });

    return did;
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
  }
}
