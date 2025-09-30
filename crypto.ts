import { bases } from 'multiformats/basics';
import * as Crypto from 'node:crypto';
import { Resolver } from 'did-resolver';
import { getResolver as getWebResolver } from 'web-did-resolver';
import { getResolver as getKeyResolver } from '@sphereon/did-resolver-key';
import * as jose from 'jose';

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

export function getPrivateKeyAsCryptoKey() {
  return Crypto.createPrivateKey({
    key: privateKeyDerEncode({
      privateKeyBytes: getPrivateKeyBuffer(process.env.ISSUER_PRIVATE_KEY),
    }),
    format: 'der',
    type: 'pkcs8',
  });
}

export function getPublicKeyAsCryptoKey() {
  return Crypto.createPublicKey({
    key: publicKeyDerEncode({
      publicKeyBytes: getPublicKeyBuffer(process.env.ISSUER_PUBLIC_KEY),
    }),
    format: 'der',
    type: 'spki',
  });
}

export function getPublicKeyAsJwk() {
  const publicKeyBytes = getPublicKeyBuffer(process.env.ISSUER_PUBLIC_KEY);
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(publicKeyBytes).toString('base64url'),
  };
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
  });
  const jwk = await jose.exportJWK(publicKey);

  return { publicKey, privateKey, jwk };
}
