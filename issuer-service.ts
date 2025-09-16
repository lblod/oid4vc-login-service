import jsonld from 'jsonld';

import * as vc from '@digitalbazaar/vc';

// Required to set up a suite instance with private key
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { securityLoader } from '@digitalbazaar/security-document-loader';
import * as didKey from '@digitalbazaar/did-method-key';
import * as didWeb from '@digitalbazaar/did-method-web';
import * as didJwk from '@digitalbazaar/did-method-jwk';
import { randomUUID, randomInt, randomBytes } from 'crypto';
import { updateSudo } from '@lblod/mu-auth-sudo';
import {
  sparqlEscapeDateTime,
  sparqlEscapeString,
  sparqlEscapeUri,
  uuid,
} from 'mu';

export class VCIssuer {
  suite;
  documentLoader: (url: string) => Promise<unknown>;
  issuerDid: string;

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

    this.suite = new Ed25519Signature2020({ key: keyPair });
  }

  // for demo purposes for now, we will need to issue a credential containing the roles in the data space
  async issueCredential(holderDid: string) {
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
    return signedVC;
  }

  // for demo purposes, normally the verifier would do this
  // ignore ts for now as vc library does not have types support
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async verifyCredential(signedVC: any) {
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
      credential_configuration_ids: ['DECIDE_EXAMPLE_CREDENTIAL'],
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
          ?token a ext:CredentialOfferToken ;
          ?token ext:authToken ${token} ;
          ?token ext:session ?session ;
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
          ?token a ext:CredentialOfferToken ;
          ?token mu:uuid ${token} ;
          ?token ?p ?o.
        }
      }`);
  }
}
