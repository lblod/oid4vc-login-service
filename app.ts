import bodyParser from 'body-parser';
import { app } from 'mu';

// Required to set up a suite instance with private key
import { VCIssuer } from './services/issuer-service';
import { SDJwtVCService } from './services/sd-jwt-vc';
import { VCVerifier } from './services/verifier-service';
import { getIssuerRouter } from './routers/issuer';
import { getVerifierRouter } from './routers/verifier';

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
  // mandated by the spec, by default we get application/vnd.api+json in the template
  res.type('application/json');
  next();
});

app.get('/status', function (req, res) {
  res.send({
    service: 'vc-issuer-service',
    status: 'ok',
  });
});

const issuer = new VCIssuer();
const verifier = new VCVerifier();
const sdJwtService = new SDJwtVCService();

async function setup() {
  await sdJwtService.setup();
  await issuer.setup({
    sdJwtService: sdJwtService,
    issuerDid: process.env.ISSUER_DID as string,
    issuerKeyId: process.env.ISSUER_KEY_ID as string,
    publicKey: process.env.ISSUER_PUBLIC_KEY as string,
    privateKey: process.env.ISSUER_PRIVATE_KEY as string,
  });

  verifier
    .setup({
      sdJwtService: sdJwtService,
    })
    .catch((e) => {
      console.error('Error setting up verifier', e);
      process.exit(1);
    });
}
setup()
  .catch((e) => {
    console.error('Error setting up services', e);
    process.exit(1);
  })
  .then(async () => {
    const issuerRouter = await getIssuerRouter(issuer);
    const verifierRouter = await getVerifierRouter(verifier);
    app.use('/issuer', issuerRouter);
    app.use('/verifier', verifierRouter);
  });
