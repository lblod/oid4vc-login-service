import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { DisclosureFrame, Signer, Verifier } from '@sd-jwt/types';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import * as Crypto from 'node:crypto';
import { bases } from 'multiformats/basics';

const MULTICODEC_ED25519_PUB_HEADER = new Uint8Array([0xed, 0x01]);
const MULTICODEC_ED25519_PRIV_HEADER = new Uint8Array([0x80, 0x26]);
const DER_PRIVATE_KEY_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex',
);
// used to turn public key bytes into a buffer in DER format
const DER_PUBLIC_KEY_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function _publicKeyBuffer(publicKeyMultibase: string) {
  // remove multibase header
  const publicKeyMulticodec = bases.base58btc.decode(publicKeyMultibase);
  // remove multicodec header
  const publicKeyBytes = publicKeyMulticodec.slice(
    MULTICODEC_ED25519_PUB_HEADER.length,
  );

  return publicKeyBytes;
}

function _privateKeyBuffer(privateKeyMultibase: string) {
  // remove multibase header
  const privateKeyMulticodec = bases.base58btc.decode(privateKeyMultibase);

  // remove multicodec header
  const privateKeyBytes = privateKeyMulticodec.slice(
    MULTICODEC_ED25519_PRIV_HEADER.length,
  );

  return privateKeyBytes;
}

export function assertKeyBytes({ bytes, expectedLength = 32 }) {
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

const createSignerVerifier = () => {
  const privateKey = Crypto.createPrivateKey({
    key: privateKeyDerEncode({
      privateKeyBytes: _privateKeyBuffer(process.env.ISSUER_PRIVATE_KEY),
    }),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = Crypto.createPublicKey({
    key: publicKeyDerEncode({
      publicKeyBytes: _publicKeyBuffer(process.env.ISSUER_PUBLIC_KEY),
    }),
    format: 'der',
    type: 'spki',
  });
  const signer: Signer = async (data: string) => {
    const sig = Crypto.sign(null, Buffer.from(data), privateKey);
    return Buffer.from(sig).toString('base64url');
  };
  const verifier: Verifier = async (data: string, sig: string) => {
    return Crypto.verify(
      null,
      Buffer.from(data),
      publicKey,
      Buffer.from(sig, 'base64url'),
    );
  };
  return { signer, verifier };
};

export class SDJwtVCService {
  ready = false;
  sdjwt = null;

  constructor() {}

  async setup() {
    if (this.ready) {
      return;
    }
    const { signer, verifier } = await createSignerVerifier();

    this.sdjwt = new SDJwtVcInstance({
      signer,
      verifier,
      signAlg: ES256.alg,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    });
    this.ready = true;
  }

  async buildCredential(ownerDid: string) {
    // Issuer Define the claims object with the user's information
    const claims = {
      decideGroups: 'Foo,Bar,Baz',
      id: ownerDid,
    };

    // Issuer Define the disclosure frame to specify which claims can be disclosed
    const disclosureFrame: DisclosureFrame<typeof claims> = {
      _sd: ['decideGroups', 'id'],
    };

    // Issue a signed JWT credential with the specified claims and disclosures
    // Return a Encoded SD JWT. Issuer send the credential to the holder
    const credential = await this.sdjwt.issue(
      {
        iss: process.env.ISSUER_DID,
        iat: Math.floor(Date.now() / 1000),
        vct: process.env.ISSUER_URL,
        ...claims,
      },
      disclosureFrame,
      {
        header: {
          kid: process.env.ISSUER_KEY_ID as string,
        },
      },
    );
    console.log('encodedJwt:', credential);

    // Holder Receive the credential from the issuer and validate it
    // Return a result of header and payload
    const validated = await this.sdjwt.validate(credential);
    console.log('validated:', validated);

    // You can decode the SD JWT to get the payload and the disclosures
    const sdJwtToken = await this.sdjwt.decode(credential);
    console.log('jwt:', sdJwtToken.jwt);
    console.log('kbJwt:', sdJwtToken.kbJwt);

    // You can get the keys of the claims from the decoded SD JWT
    const keys = await sdJwtToken.keys(digest);
    console.log({ keys });

    // You can get the claims from the decoded SD JWT
    const payloads = await sdJwtToken.getClaims(digest);

    // You can get the presentable keys from the decoded SD JWT
    const presentableKeys = await sdJwtToken.presentableKeys(digest);

    console.log({
      payloads: JSON.stringify(payloads, null, 2),
      disclosures: JSON.stringify(sdJwtToken.disclosures, null, 2),
      claim: JSON.stringify(sdJwtToken.jwt?.payload, null, 2),
      presentableKeys,
    });

    console.log(
      '================================================================',
    );
    return credential;
  }
}
