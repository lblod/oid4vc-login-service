import Router from 'express-promise-router';

export async function getIssuerRouter(issuer) {
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
    // to be configured in the dispatcher, the path is forced to be .well-known/openid-credential-issuer/something/something
    // we can send signed metadata, but we are required to send unsigned for sure, let's start with that
    const issuerUrl = process.env.ISSUER_URL as string;
    res.send({
      credential_issuer: issuerUrl,
      authorization_servers: [`${issuerUrl}`], // so we also act as an authorization server, should be the default
      credential_endpoint: `${issuerUrl}/vc-issuer/credential`,
      nonce_endpoint: `${issuerUrl}/vc-issuer/nonce`,
      display: [
        {
          name: 'Decide Data Space',
          locale: 'en-US',
          logo: {
            uri: `${issuerUrl}/assets/logo.png`,
            url: `${issuerUrl}/assets/logo.png`,
            alt_text: 'the square decide logo',
          },
        },
      ],
      credential_configurations_supported: {
        // this is NOT linked data, which is sad
        [`${process.env.CREDENTIAL_TYPE}_sd_jwt`]: {
          format: 'vc+sd-jwt', // latest spec actually says dc+sd-jwt
          scope: 'JWT_VC_DECIDE_ROLES',
          credential_signing_alg_values_supported: ['EdDSA'], // may need to fall back to ES256?
          cryptographic_binding_methods_supported: ['did:key', 'did:web'], // jwk not supported, we want a did to link to the user
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ['ES256'],
            },
          },
          display: [
            // repeated for older specs
            {
              name: 'Decide Roles Credential',
              locale: 'en-US',
              logo: {
                uri: `${issuerUrl}/assets/logo.png`, // TODO this is super temporary and ugly, but the app crashes if it's not there
                url: `${issuerUrl}/assets/logo.png`, // TODO this is super temporary and ugly, but the app crashes if it's not there
                alt_text: 'the square decide logo',
              },
              description:
                'A credential that holds the groups you have access to in Decide',
              background_color: '#12107c',
              text_color: '#FFFFFF',
            },
          ],
          claims: {
            // repeated for older specs
            decideGroups: {
              en: {
                name: 'Decide Groups',
                locale: 'en-US',
              },
            },
            otherProjectGroups: {
              en: {
                name: 'Other Project Groups',
                locale: 'en-US',
              },
            },
            id: {
              en: {
                name: 'id',
                locale: 'en-US',
              },
            },
          },

          vct: `${process.env.ISSUER_URL}`,
          credential_metadata: {
            display: [
              {
                name: 'Decide Roles Credential',
                locale: 'en-US',
                logo: {
                  uri: `${issuerUrl}/assets/logo.png`, // TODO this is super temporary and ugly, but the app crashes if it's not there
                  url: `${issuerUrl}/assets/logo.png`, // TODO this is super temporary and ugly, but the app crashes if it's not there
                  alt_text: 'the square decide logo',
                },
                description:
                  'A credential that holds the groups you have access to in Decide',
                background_color: '#12107c',
                text_color: '#FFFFFF',
              },
            ],
            claims: [
              {
                path: ['decideGroups'],
                display: [
                  {
                    name: 'Decide Groups',
                    locale: 'en-US',
                  },
                ],
              },
              {
                path: ['otherProjectGroups'],
                display: [
                  {
                    name: 'Other Project Groups',
                    locale: 'en-US',
                  },
                ],
              },
              {
                path: ['id'],
                display: [
                  {
                    name: 'ID',
                    locale: 'en-US',
                  },
                ],
              },
            ],
          },
        },
      },
    });
  });

  router.get('/authorization_metadata', async function (req, res) {
    const issuerUrl = process.env.ISSUER_URL as string;
    res.send({
      issuer: issuerUrl,
      scopes_supported: ['JWT_VC_DECIDE_ROLES'],
      authorization_endpoint: `${issuerUrl}/authorize`, // we don't have this yet, we don't have grant types that require it
      token_endpoint: `${issuerUrl}/vc-issuer/token`,
      response_types_supported: ['code'],
      grant_types_supported: [
        'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      ],
    });
  });

  router.get('/vct', function (req, res) {
    res.send({
      vct: `${process.env.ISSUER_URL}`,
      name: 'Decide Data Space Roles Credential',
      claims: [
        {
          path: 'decideGroups',
          display: { name: 'Groups', locale: 'en-US' },
          sd: 'allowed',
        },
        {
          path: 'otherProjectGroups',
          display: { name: 'Other Project Groups', locale: 'en-US' },
          sd: 'allowed',
        },
        {
          path: 'id',
          display: { name: 'ID', locale: 'en-US' },
          sd: 'allowed',
        },
      ],
      schema: {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        type: 'object',
        properties: {
          decideGroups: {
            type: 'string',
          },
          otherProjectGroups: {
            type: 'string',
          },
          id: {
            type: 'string',
          },
        },
        required: ['id'],
      },
    });
  });

  router.post('/token', async function (req, res) {
    let preAuthorizedCode = req.query['pre-authorized_code'] as string;
    if (req.body['pre-authorized_code']) {
      preAuthorizedCode = req.body['pre-authorized_code'] as string;
    }
    // const transactionCode = req.query.tx_code as string | undefined;

    const sessionUri = await issuer.getSessionForAuthCode(
      preAuthorizedCode,
      // transactionCode,
    );
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

    // TODO we may want to offer a nonce endpoint
  });

  router.post('/nonce', async function (req, res) {
    const nonce = await issuer.generateNonce();
    res.set('Cache-Control', 'no-store');
    res.send({
      c_nonce: nonce,
    });
  });

  router.post('/credential', async function (req, res) {
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
    const sessionInfo = await issuer.validateAuthToken(token);
    if (!sessionInfo) {
      // TODO we don't have actual session info yet, ignore this for now
      // res.status(401).send({ error: 'invalid_token' });
      // return;
    }
    // we don't actually have multiple credential types yet, so the wallet won't send this property
    // if (credential_configuration_id !== process.env.CREDENTIAL_TYPE) {
    //   res.status(400).send({ error: 'invalid_credential_configuration_id' });
    //   return;
    // }
    // we don't require a proof for now, the wallet sends one anyway, it helps us figure out the did though
    if (!jwt) {
      res.status(400).send({ error: 'missing_proof' });
      return;
    }
    const { did, jwk } = await issuer.validateProofAndGetHolderDid(jwt);

    const signedVC = await issuer.issueCredential(did, jwk);
    // credential because our wallet follows an old version of the spec
    res.send({
      //credentials: [{ credential: signedVC }], // commented as paradym fails with this property present T_T, it is correct according to the spec though
      credential: signedVC, // for old specs
      c_nonce: await issuer.generateNonce(), // for old specs
      c_nonce_expires_in: 300, // yeah... it really doesn't, for old specs
      format: 'vc+sd-jwt', // for old specs
    });
  });

  return router;
}
