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
      DECIDE_EXAMPLE_CREDENTIAL: {
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
    issuer: `${issuerUrl}/vc-issuer/token`,
    scopes_supported: ['JWT_VC_DECIDE_ROLES'],
    authorization_endpoint: `${issuerUrl}/authorize`, // we don't have this yet, we don't have grant types that require it
    token_endpoint: `${issuerUrl}/vc-issuer/token`,
    response_types_supported: ['code'],
    grant_types_supported: [
      'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    ],
  });
});

router.post('/token', async function (req, res) {
  console.log('query', req.query);
  console.log('body', req.body);
  const preAuthorizedCode = req.query['pre-authorized_code'] as string;
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
  const { credential_configuration_id, proofs } = req.body;
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
  if (credential_configuration_id !== process.env.CREDENTIAL_TYPE) {
    res.status(400).send({ error: 'invalid_credential_configuration_id' });
    return;
  }
  if (!proofs || proofs.jwt) {
    res.status(400).send({ error: 'missing_proof' });
    return;
  }
  const jwt = proofs.jwt[0];
  const decodedJwt = JSON.parse(atob(jwt));
  const did = decodedJwt.kid;
  if (!did || !did.startsWith('did:')) {
    res.status(400).send({ error: 'invalid_proof' });
    return;
  }
  const signedVC = await issuer.issueCredential(did);
  res.send({ credentials: [{ credential: signedVC }] });
});
