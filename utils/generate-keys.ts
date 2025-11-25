import * as jose from 'jose';
import {
  driver,
  didUrlToHttpsUrl,
  httpsUrlToDidUrl,
} from '@digitalbazaar/did-method-web';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020';
const didWebDriver = driver();
didWebDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey2020.from,
});
didWebDriver.use({
  multibaseMultikeyHeader: 'z6LS',
  fromMultibase: X25519KeyAgreementKey2020.from,
});

export async function generateKeys(did: string) {
  if (did.startsWith('http')) {
    did = httpsUrlToDidUrl(did).didUrl;
  }
  if (!did.startsWith('did:web:')) {
    throw new Error('Only did:web DIDs are supported');
  }
  return createDidWebEdDSAAndES256(did);
}

export async function createDidWebEdDSAAndES256(did) {
  const verificationKey = await Ed25519VerificationKey2020.generate();
  const agreementKey = await X25519KeyAgreementKey2020.generate();
  const didDocument = await didWebDriver.fromKeyPair({
    url: didUrlToHttpsUrl(did).fullUrl,
    verificationKeyPair: verificationKey,
    keyAgreementKeyPair: agreementKey,
  });

  const joseKeys = await generateES256KeysAndJwk('ES256');
  didDocument.didDocument.verificationMethod.push({
    id: `${did}#es256-1`,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk: joseKeys.publicJwk,
  });
  didDocument.didDocument.authentication.push(`${did}#es256-1`);
  didDocument.didDocument.assertionMethod.push(`${did}#es256-1`);
  didDocument.didDocument.capabilityDelegation.push(`${did}#es256-1`);
  didDocument.didDocument.capabilityInvocation.push(`${did}#es256-1`);
  didDocument.didDocument['@context'].push(
    'https://w3id.org/security/suites/jws-2020/v1',
  );

  console.log(JSON.stringify(didDocument, null, 2));

  return {
    did,
    didDocument: didDocument.didDocument,
    verificationKey: verificationKey.export({
      publicKey: true,
      privateKey: true,
    }),
    agreementKey: agreementKey.export({ publicKey: true, privateKey: true }),
    es256PublicKey: joseKeys.publicPem,
    es256PrivateKey: joseKeys.privatePem,
  };
}

export async function generateES256KeysAndJwk(algorithm) {
  const { publicKey, privateKey, privatePem, publicPem } =
    await generateJoseKey(algorithm);
  const publicJwk = await jose.exportJWK(publicKey);
  publicJwk.alg = algorithm;
  return { publicKey, privateKey, privatePem, publicPem, publicJwk };
}

export async function generateJoseKey(algorithm) {
  const { publicKey, privateKey } = await jose.generateKeyPair(algorithm, {
    extractable: true,
  });

  const publicPem = await jose.exportSPKI(publicKey);
  console.log(publicPem);
  const privatePem = await jose.exportPKCS8(privateKey);
  console.log(privatePem);
  return { publicKey, privateKey, privatePem, publicPem };
}
