import bodyParser from 'body-parser';
import { app } from 'mu';

// Required to set up a suite instance with private key
import { VCIssuer } from './services/issuer';
import { SDJwtVCService } from './services/sd-jwt-vc';
import { VCVerifier } from './services/verifier';
import { getIssuerRouter } from './routers/issuer';
import { getVerifierRouter } from './routers/verifier';
import { startCleanupCron } from './utils/cleanup-cron';
import env from './utils/environment';
import { logger } from './utils/logger';

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

app.use(function (req, res, next) {
  logger.info(
    `Incoming request: ${req.method} ${req.originalUrl}, session: ${req.get('mu-session-id')}`,
  );

  next();
});

app.get('/status', function (req, res) {
  res.send({
    service: 'verifiable-credentials-service',
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
    issuerDid: env.ISSUER_DID as string,
    issuerKeyId: env.ISSUER_KEY_ID as string,
    publicKey: env.ISSUER_PUBLIC_KEY as string,
    privateKey: env.ISSUER_PRIVATE_KEY as string,
  });
  await verifier.setup({
    sdJwtService: sdJwtService,
  });
}
setup()
  .catch((e) => {
    logger.error(`Error setting up services: ${e}`);
    process.exit(1);
  })
  .then(async () => {
    startCleanupCron({ issuerService: issuer, verifierService: verifier });
    const issuerRouter = await getIssuerRouter(issuer);
    const verifierRouter = await getVerifierRouter(verifier);
    app.use('/issuer', issuerRouter);
    app.use('/verifier', verifierRouter);
  });
