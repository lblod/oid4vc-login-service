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
    authorization_servers: [`${issuerUrl}/vc-issuer/token`], // so we also act as an authorization server
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
      SD_JWT_VC_example_in_OpenID4VCI: {
        format: 'ldp_vc',
        scope: 'JWT_VC_DECIDE_ROLES',
        credential_signing_alg_values_supported: ['Ed25519Signature2020'],
        // cryptographic_binding_methods_supported: ['did:key', 'did:web'], we probably want to add this and require key binding, but for now lets try without
        credentials_definition: {
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
                uri: `${issuerUrl}/logo.png`,
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

router.get('/token', async function (req, res) {
  const preAuthorizedCode = req.query.pre_authorized_code as string;
  const transactionCode = req.query.transaction_code as string | undefined;

  const sessionUri = await issuer.getSessionForAuthCode(
    preAuthorizedCode,
    transactionCode,
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
