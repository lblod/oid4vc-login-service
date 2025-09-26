import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { DisclosureFrame, Signer, Verifier } from '@sd-jwt/types';
import * as Crypto from 'node:crypto';
import { getPrivateKeyAsCryptoKey, getPublicKeyAsCryptoKey } from './crypto';

const createSignerVerifier = () => {
  const privateKey = getPrivateKeyAsCryptoKey();
  const publicKey = getPublicKeyAsCryptoKey();

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
      signAlg: 'EdDSA',
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
