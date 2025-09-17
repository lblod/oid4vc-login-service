import bodyParser from 'body-parser';
import { app } from 'mu';

// Required to set up a suite instance with private key
import Router from 'express-promise-router';
import { VCIssuer } from './issuer-service';

const router = Router();
app.use(
  bodyParser.json({
    limit: '500mb',
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    type: function (req: any) {
      return /^application\/json/.test(req.get('content-type') as string);
    },
  }),
);
app.use('/', function (req, res, next) {
  // mandated by the spec
  res.type('application/json');
  next();
});

app.use(router);

const issuer = new VCIssuer();
issuer
  .setup({
    issuerDid: process.env.ISSUER_DID as string,
    issuerKeyId: process.env.ISSUER_KEY_ID as string,
    publicKey: process.env.ISSUER_PUBLIC_KEY as string,
    privateKey: process.env.ISSUER_PRIVATE_KEY as string,
  })
  .catch(() => {
    console.error('Error setting up issuer');
    process.exit(1);
  });

router.get('/status', function (req, res) {
  res.send({
    service: 'vc-issuer-service',
    status: 'ok',
  });
});

router.post('/issue-credential', async function (req, res) {
  const holderDid = req.body.holderDid;
  const signedVC = await issuer.issueCredential(holderDid);
  console.log(JSON.stringify(signedVC, null, 2));

  // normally you'd verify the presentation, but let's already verify the credential
  const verificationResult = await issuer.verifyCredential(signedVC);
  console.log(verificationResult);
  res.send(signedVC);
});

router.get('/build-credential-offer-uri', async function (req, res) {
  const sessionUri = req.get('mu-session-id') as string;
  const { pin, credentialOfferUri } =
    await issuer.buildCredentialOfferUri(sessionUri);
  res.send({
    credentialOfferUri,
    pin: pin,
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
    display: [
      {
        name: 'Decide Data Space',
        locale: 'en-US',
        logo: {
          uri: `${issuerUrl}/logo.png`,
          alt_text: 'the square decide logo',
        },
      },
    ],
    credential_configurations_supported: {
      // this is NOT linked data, which is sad
      [`${process.env.CREDENTIAL_TYPE}_sd_jwt`]: {
        format: 'vc+sd-jwt', // latest spec actually says dc+sd-jwt
        scope: 'JWT_VC_DECIDE_ROLES',
        credential_signing_alg_values_supported: ['ES256'],
        // cryptographic_binding_methods_supported: ['did:key', 'did:web'], we probably want to add this and require key binding, but for now lets try without
        vct: `${process.env.ISSUER_URL}/vc-issuer/vct`, // TODO this should be properly resolvable see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-10
        credential_metadata: {
          display: [
            {
              name: 'Decide Roles Credential',
              locale: 'en-US',
              logo: {
                uri: `${issuerUrl}/assets/logo.png`, // TODO this is super temporary and ugly, but the app crashes if it's not there
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
              path: ['alumniOf'],
              display: [
                {
                  name: 'Degree',
                  locale: 'en-US',
                },
              ],
            },
          ],
        },
      },
      // note: not a single wallet found that supports ldp_vc and works
      [`${process.env.CREDENTIAL_TYPE}`]: {
        format: 'ldp_vc',
        scope: 'JWT_VC_DECIDE_ROLES',
        credential_signing_alg_values_supported: ['EdDSA'], // may need to fall back to ES256 for sphereon wallet TODO
        // cryptographic_binding_methods_supported: ['did:key', 'did:web'], we probably want to add this and require key binding, but for now lets try without
        credential_definition: {
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://www.w3.org/2018/credentials/examples/v1', // TODO we want to change this to our true context
          ],
          type: ['VerifiableCredential', 'AlumniCredential'],
        },
        credential_metadata: {
          display: [
            {
              name: 'Decide Roles Credential',
              locale: 'en-US',
              logo: {
                uri: `${issuerUrl}/assets/logo.png`, // TODO this is super temporary and ugly, but the app crashes if it's not there
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
              path: ['credentialSubject', 'alumniOf'],
              display: [
                {
                  name: 'Degree',
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
    id: `${process.env.ISSUER_URL}/vc-issuer/vct`,
    name: 'Decide Data Space Roles Credential',
    claims: [
      {
        path: 'alumniOf',
        display: { name: 'Degree', locale: 'en-US' },
        sd: 'allowed',
      },
    ],
    schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      properties: {
        alumniOf: {
          type: 'string',
        },
      },
      required: ['alumniOf'],
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

router.post('/credential', async function (req, res) {
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
  const decodedJwt = JSON.parse(atob(jwt.split('.')[0]));
  // todo we should validate the proof, but for now let's trust it
  const did = decodedJwt.kid;
  if (!did || !did.startsWith('did:')) {
    res.status(400).send({ error: 'invalid_proof' });
    return;
  }
  const signedVC = await issuer.issueCredential(did);
  // credential because our wallet follows an old version of the spec
  res.send({ credentials: [{ credential: signedVC }], credential: signedVC });
});
