import { bases } from 'multiformats/basics';
import * as Crypto from 'node:crypto';
import { Resolver } from 'did-resolver';
import { getResolver as getWebResolver } from 'web-did-resolver';
import { getResolver as getKeyResolver } from '@sphereon/did-resolver-key';
import * as jose from 'jose';
import env from './environment';

const MULTICODEC_ED25519_PUB_HEADER = new Uint8Array([0xed, 0x01]);
const MULTICODEC_ED25519_PRIV_HEADER = new Uint8Array([0x80, 0x26]);
const DER_PRIVATE_KEY_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex',
);
// used to turn public key bytes into a buffer in DER format
const DER_PUBLIC_KEY_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function getPublicKeyBuffer(publicKeyMultibase: string) {
  // remove multibase header
  const publicKeyMulticodec = bases.base58btc.decode(publicKeyMultibase);
  // remove multicodec header
  const publicKeyBytes = publicKeyMulticodec.slice(
    MULTICODEC_ED25519_PUB_HEADER.length,
  );

  return publicKeyBytes;
}

function getPrivateKeyBuffer(privateKeyMultibase: string) {
  // remove multibase header
  const privateKeyMulticodec = bases.base58btc.decode(privateKeyMultibase);

  // remove multicodec header
  const privateKeyBytes = privateKeyMulticodec.slice(
    MULTICODEC_ED25519_PRIV_HEADER.length,
  );

  return privateKeyBytes;
}

function assertKeyBytes({ bytes, expectedLength = 32 }) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('"bytes" must be a Uint8Array.');
  }
  if (bytes.length !== expectedLength) {
    const error = new Error(
      `"bytes" must be a ${expectedLength}-byte Uint8Array.`,
    );
    // we need DataError for invalid byte length
    error.name = 'DataError';

    throw error;
  }
}

function privateKeyDerEncode({
  privateKeyBytes,
  seedBytes,
}: {
  privateKeyBytes: Uint8Array;
  seedBytes?: Uint8Array;
}) {
  if (!(privateKeyBytes || seedBytes)) {
    throw new TypeError('`privateKeyBytes` or `seedBytes` is required.');
  }
  if (!privateKeyBytes) {
    assertKeyBytes({
      bytes: seedBytes,
      expectedLength: 32,
    });
  }
  if (!seedBytes) {
    assertKeyBytes({
      bytes: privateKeyBytes,
      expectedLength: 64,
    });
  }
  let p;
  if (seedBytes) {
    p = seedBytes;
  } else {
    // extract the first 32 bytes of the 64 byte private key representation
    p = privateKeyBytes.slice(0, 32);
  }
  return Buffer.concat([DER_PRIVATE_KEY_PREFIX, p]);
}

function publicKeyDerEncode({ publicKeyBytes }) {
  assertKeyBytes({
    bytes: publicKeyBytes,
    expectedLength: 32,
  });
  return Buffer.concat([DER_PUBLIC_KEY_PREFIX, publicKeyBytes]);
}

const privateKeyAsCryptoKey: { [key: string]: Crypto.KeyObject | null } = {};

export function getPrivateES256KeyAsCryptoKey(
  key = env.VERIFIER_ES256_PRIVATE_KEY,
) {
  if (!key) {
    throw new Error(
      'No Key provided when asking for private ES256 key as CryptoKey',
    );
  }

  if (privateKeyAsCryptoKey[key]) {
    return privateKeyAsCryptoKey[key];
  }
  const privateKey = Crypto.createPrivateKey({
    key,
  });
  privateKeyAsCryptoKey[key] = privateKey;
  return privateKey;
}

export function getPrivateKeyAsCryptoKey(key = env.ISSUER_PRIVATE_KEY) {
  if (!key) {
    throw new Error('No Key provided when asking for private key as CryptoKey');
  }
  if (privateKeyAsCryptoKey[key]) {
    return privateKeyAsCryptoKey[key];
  }
  const privateKey = Crypto.createPrivateKey({
    key: privateKeyDerEncode({
      privateKeyBytes: getPrivateKeyBuffer(key),
    }),
    format: 'der',
    type: 'pkcs8',
  });
  privateKeyAsCryptoKey[key] = privateKey;
  return privateKey;
}

const publicKeyAsCryptoKey: { [key: string]: Crypto.KeyObject } = {};

export function getPublicKeyAsCryptoKey(key = env.ISSUER_PUBLIC_KEY) {
  if (!key) {
    throw new Error('No key provided when asking for public key as CryptoKey');
  }
  if (publicKeyAsCryptoKey[key]) {
    return publicKeyAsCryptoKey[key];
  }
  publicKeyAsCryptoKey[key] = Crypto.createPublicKey({
    key: publicKeyDerEncode({
      publicKeyBytes: getPublicKeyBuffer(key),
    }),
    format: 'der',
    type: 'spki',
  });
  return publicKeyAsCryptoKey[key];
}

const publicKeyAsJwk: { [key: string]: JsonWebKey } = {};

export function getPublicKeyAsJwk(key = env.ISSUER_PUBLIC_KEY) {
  if (!key) {
    throw new Error('No key provided when asking for public key as JWK');
  }

  if (publicKeyAsJwk[key]) {
    return publicKeyAsJwk[key];
  }
  const publicKeyBytes = getPublicKeyBuffer(key!);
  publicKeyAsJwk[key] = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(publicKeyBytes).toString('base64url'),
  };
  return publicKeyAsJwk[key];
}

const webResolver = getWebResolver();
const keyResolver = getKeyResolver();

const didResolver = new Resolver({
  ...webResolver,
  ...keyResolver,
});

export async function resolveDid(did: string) {
  const result = await didResolver.resolve(did);
  return result;
}

export async function createEphemeralKeyPair() {
  const { publicKey, privateKey } = await jose.generateKeyPair('ECDH-ES', {
    extractable: true,
    crv: 'P-256',
  });
  const jwk = await jose.exportJWK(publicKey);
  jwk.kid = 'eph'; // we can use a static kid as we only have one key per request, this is mostly for debugging
  jwk.use = 'enc';
  jwk.alg = 'ECDH-ES';

  return { publicKey, privateKey, jwk };
}

function pemToBase64Der(pem: string) {
  return pem
    .replace('-----BEGIN CERTIFICATE-----', '')
    .replace('-----END CERTIFICATE-----', '')
    .replace(/\s+/g, '');
}

const pemHashCache: { [pem: string]: string } = {};
export function pemToX509Hash(pem = env.VERIFIER_X509_PUBLIC_KEY) {
  if (pemHashCache[pem]) {
    return pemHashCache[pem];
  }
  const base64 = pemToBase64Der(pem);
  const der = Buffer.from(base64, 'base64');
  const hash = Crypto.createHash('sha256').update(der).digest('base64');
  const hashBase64Url = hash
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  pemHashCache[pem] = hashBase64Url;
  return hashBase64Url;
}

export function buildX5CFromChain(
  pemChain = env.VERIFIER_X509_CHAIN,
): string[] {
  // Split into individual certificates
  const certs = pemChain
    .split(/-----END CERTIFICATE-----/)
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => part + '-----END CERTIFICATE-----');

  // Convert each cert to Base64 DER
  return certs.map(pemToBase64Der);
}

export function getPrivateX509KeyAsCryptoKey(
  key = env.VERIFIER_X509_PRIVATE_KEY,
) {
  return Crypto.createPrivateKey({
    key,
  });
}

export async function jwkToCryptoKey(
  jwk: JsonWebKey,
): Promise<Crypto.KeyObject> {
  if (jwk.kty === 'oct') {
    throw new Error('Unsupported kty');
  }
  const cryptoKey = (await jose.importJWK(jwk)) as unknown as CryptoKey; // kty oct not supported, so should return cryptokey
  const spkiDer = await crypto.subtle.exportKey('spki', cryptoKey);

  // 3. Convert the ArrayBuffer to a Buffer
  const spkiBuffer = Buffer.from(spkiDer);

  // 4. Create a KeyObject from the SPKI buffer
  return Crypto.createPublicKey({
    key: spkiBuffer,
    format: 'der',
    type: 'spki',
  });
}
