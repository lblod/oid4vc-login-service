import Router from 'express-promise-router';
import env from '../utils/environment';
import {
  getCredentialDisplay,
  getCredentialMetadataClaims,
  getOldCredentialClaims,
  getSessionInfoForCredentialOfferToken,
  getVctClaims,
  getVctDisplay,
  getVctSchema,
} from '../utils/credential-format';
import { VCIssuer } from '../services/issuer';

export async function getIssuerRouter(issuer: VCIssuer) {
  const router = Router();

  router.get('/build-credential-offer-uri', async function (req, res) {
    const sessionUri = req.get('mu-session-id') as string;
    const { credentialOfferUri } =
      await issuer.buildCredentialOfferUri(sessionUri);
    res.send({
      credentialOfferUri,
    });
  });

  router.get('/issuer_metadata', async function (req, res) {
    // to be configured in the dispatcher, the path is forced to be issuer_url.well-known/openid-credential-issuer/something/something
    // if the issuer is exposed at issuer_url/something/something
    // we can send signed metadata, but we are required to send unsigned for sure, let's start with that
    const issuerUrl = env.ISSUER_URL;
    res.send({
      credential_issuer: `${issuerUrl}`,
      authorization_servers: [`${issuerUrl}`], // so we also act as an authorization server, should be the default
      credential_endpoint: `${issuerUrl}/credential`,
      nonce_endpoint: `${issuerUrl}/nonce`,
      display: [
        {
          name: env.ISSUER_NAME,
          locale: 'en-US',
          logo: {
            uri: env.LOGO_URL,
            url: env.LOGO_URL,
            alt_text: `${env.ISSUER_NAME} Logo`,
          },
        },
      ],
      credential_configurations_supported: {
        // this is NOT linked data, which is sad
        [`${env.CREDENTIAL_TYPE}_sd_jwt`]: {
          format: 'vc+sd-jwt', // latest spec actually says dc+sd-jwt
          scope: env.CREDENTIAL_TYPE,
          credential_signing_alg_values_supported: ['EdDSA'], // may need to fall back to ES256?
          cryptographic_binding_methods_supported: ['did:key', 'did:web'], // jwk not supported, we want a did to link to the user
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ['ES256'],
            },
          },
          // repeated for older specs
          display: getCredentialDisplay(),
          // repeated for older specs
          claims: getOldCredentialClaims(),

          vct: `${env.ISSUER_URL}`,
          credential_metadata: {
            display: getCredentialDisplay(),
            claims: getCredentialMetadataClaims(),
          },
        },
      },
    });
  });

  // should be exposed at issuer_url/.well-known/oauth-authorization-server/issuer_path
  router.get('/authorization_metadata', async function (req, res) {
    const issuerUrl = env.ISSUER_URL;
    res.send({
      issuer: issuerUrl,
      scopes_supported: [env.CREDENTIAL_TYPE],
      authorization_endpoint: `${issuerUrl}/authorize`,
      token_endpoint: `${issuerUrl}/token`,
      response_types_supported: ['code'],
      grant_types_supported: [
        'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      ],
    });
  });

  // should be exposed at issuer_url/.well-known/vct/issuer_path
  // as per: datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-11#name-retrieving-type-metadata
  router.get('/vct', function (req, res) {
    res.send({
      vct: `${env.ISSUER_URL}`,
      name: env.CREDENTIAL_NAME,
      claims: getVctClaims(),
      display: getVctDisplay(),
      schema: getVctSchema(),
    });
  });

  router.post('/token', async function (req, res) {
    let preAuthorizedCode = req.query['pre-authorized_code'] as string;
    if (req.body['pre-authorized_code']) {
      preAuthorizedCode = req.body['pre-authorized_code'] as string;
    }

    const sessionUri = await issuer.getSessionForAuthCode(preAuthorizedCode);
    if (!sessionUri) {
      res.status(403).send({ error: 'invalid_grant' });
      return;
    }

    // generate proper token here
    const token = await issuer.generateCredentialOfferToken(sessionUri);
    res.send({
      access_token: token,
      token_type: 'Bearer',
      expires_in: issuer.tokenTTL,
    });
  });

  router.post('/nonce', async function (req, res) {
    const session = req.get('mu-session-id') as string;
    const nonce = await issuer.generateNonce(session);
    res.set('Cache-Control', 'no-store'); // as per spec
    res.send({
      c_nonce: nonce,
    });
  });

  router.post('/credential', async function (req, res) {
    const walletSession = req.get('mu-session-id') as string;
    const expectedNonce =
      await issuer.getExpectedNonceForSession(walletSession);

    console.log('body', req.body);
    const { credential_configuration_id, proofs, proof } = req.body;

    // 'proof' is because our wallet follows an old version of the spec
    const jwt = proofs?.jwt ? proofs.jwt[0] : proof?.jwt;
    // TODO logging everything for now to see how far we get with our wallets
    console.log('Credential config id\n', credential_configuration_id);
    console.log('Proofs:\n', proofs);
    const auth = req.get('authorization') as string;
    console.log('Authorization:\n', auth);
    if (!auth || !auth.startsWith('Bearer ')) {
      res.status(401).send({ error: 'invalid_token' });
      return;
    }
    const token = auth.split(' ')[1];
    const sessionInfo = await getSessionInfoForCredentialOfferToken(token);
    if (!sessionInfo) {
      res.status(401).send({ error: 'invalid_token' });
      return;
    }
    // we don't actually have multiple credential types yet, so even if the wallet sends this, we can ignore it
    // if (credential_configuration_id !== env.CREDENTIAL_TYPE) {
    //   res.status(400).send({ error: 'invalid_credential_configuration_id' });
    //   return;
    // }
    if (!jwt) {
      res.status(400).send({ error: 'missing_proof' });
      return;
    }
    const payload = jwt.split('.')[1];
    if (!payload) {
      res.status(400).send({ error: 'invalid_proof' });
      return;
    }
    const decodedPayload = JSON.parse(
      Buffer.from(payload, 'base64').toString(),
    );
    const nonce = decodedPayload.c_nonce;
    if (!nonce || nonce !== expectedNonce) {
      res.status(400).send({ error: 'invalid_nonce' });
      return;
    }
    const { did, jwk } = await issuer
      .validateProofAndGetHolderDid(jwt, expectedNonce)
      .catch((e) => {
        console.error('Error validating proof', e);
        res.status(400).send({ error: e.message });
        return { did: null, jwk: null };
      });
    if (!did) {
      return; // we already sent a response in the catch block
    }

    console.log('holder did:', did);
    console.log('holder jwk:', jwk);

    const signedVC = await issuer.issueCredential(did, jwk, sessionInfo);

    const response = {
      c_nonce: await issuer.generateNonce(walletSession), // for old specs
      c_nonce_expires_in: 300, // yeah... it really doesn't, for old specs
      format: 'vc+sd-jwt', // for old specs
    };

    // old specs want a single credential, newer specs want an array of credentials. paradym breaks if it receives credentials as an array
    if (env.SINGLE_CREDENTIAL_RESPONSE) {
      response['credential'] = signedVC;
    } else {
      response['credentials'] = [{ credential: signedVC }];
    }

    res.send(response);
  });

  return router;
}
