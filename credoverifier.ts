import {
  Agent,
  DidKey,
  DidsApi,
  KeyDidCreateOptions,
  KeyType,
} from '@credo-ts/core';
// OpenID4VC issuer and verifier modules only work in Node.js
import { JwaSignatureAlgorithm } from '@credo-ts/core';
import { agentDependencies } from '@credo-ts/node';
import { Router } from 'express';

import { AskarModule } from '@credo-ts/askar';
import {
  OpenId4VcIssuanceSessionStateChangedEvent,
  OpenId4VcIssuerEvents,
  OpenId4VcIssuerModule,
  OpenId4VciCredentialFormatProfile,
} from '@credo-ts/openid4vc';
import { ariesAskar } from '@hyperledger/aries-askar-nodejs';
import { app } from 'mu';
// Create two express routers, all endpoints for the
// issuer and verifier will be added to these routers
const issuerRouter = Router();

// Register the routers on the express server. The path should match
// with the baseUrl you configure in the modules below.
app.use('/oid4vci', issuerRouter);

export const hack = {
  credentialOffer: null,
};

const issuer = new Agent({
  config: {
    label: 'Decide VC Issuer Service',
    walletConfig: {
      id: 'wallet-id',
      key: 'testkey0000000000000000000000000',
    },
  },
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({
      ariesAskar,
    }),

    openId4VcIssuer: new OpenId4VcIssuerModule({
      baseUrl: `${process.env.ISSUER_URL}/oid4vci`,

      // If no router is passed, one will be created.
      // you still have to register the router on your express server
      // but you can access it on agent.modules.openId4VcIssuer.config.router
      // It works the same for verifier: agent.modules.openId4VcVerifier.config.router
      router: issuerRouter,

      // Each of the endpoints can have configuration associated with it, such as the
      // path (under the baseUrl) to use for the endpoints.
      endpoints: {
        // The credentialRequestToCredentialMapper is the only required endpoint
        // configuration that must be provided. This method is called whenever a
        // credential request has been received for an offer we created. The callback should
        // return the issued credential to return in the credential response to the holder.
        credential: {
          credentialRequestToCredentialMapper: async ({
            // agent context for the current wallet / tenant
            agentContext,
            // the credential offer related to the credential request
            credentialOffer,
            // the received credential request
            credentialRequest,
            // the list of credentialsSupported entries
            credentialsSupported,
            // the cryptographic binding provided by the holder in the credential request proof
            holderBinding,
            // the issuance session associated with the credential request and offer
            issuanceSession,
          }) => {
            const firstSupported = credentialsSupported[0];

            // We only support vc+sd-jwt in this example, but you can add more formats
            if (
              firstSupported.format !==
              OpenId4VciCredentialFormatProfile.SdJwtVc
            ) {
              throw new Error('Only vc+sd-jwt is supported');
            }

            // We only support AcmeCorpEmployee in this example, but you can support any type
            if (firstSupported.vct !== process.env.ISSUER_URL) {
              throw new Error('Only AcmeCorpEmployee is supported');
            }

            // find the first did:key did in our wallet. You can modify this based on your needs
            const didsApi = agentContext.dependencyManager.resolve(DidsApi);
            const [didKeyDidRecord] = await didsApi.getCreatedDids({
              method: 'key',
            });

            const didKey = DidKey.fromDid(didKeyDidRecord.did);
            const didUrl = `${didKey.did}#${didKey.key.fingerprint}`;

            console.log('didUrl', didUrl);

            return {
              credentialSupportedId: firstSupported.id,
              format: 'vc+sd-jwt',
              // We can provide the holderBinding as is, if we don't want to make changes
              holder: holderBinding,
              payload: {
                vct: firstSupported.vct,
                firstName: 'John',
                lastName: 'Doe',
              },
              disclosureFrame: {
                _sd: ['lastName'],
              },
              issuer: {
                method: 'did',
                didUrl,
              },
            };
          },
        },
      },
    }),
  },
});

export async function setup() {
  await issuer.initialize();
  // Create an issuer with one supported credential: AcmeCorpEmployee

  const openid4vcIssuer = await issuer.modules.openId4VcIssuer.createIssuer({
    issuerId: 'foobar',
    display: [
      {
        name: 'ACME Corp.',
        description: 'ACME Corp. is a company that provides the best services.',
        text_color: '#000000',
        background_color: '#FFFFFF',
        logo: {
          url: 'https://acme.com/logo.png',
          alt_text: 'ACME Corp. logo',
        },
      },
    ],
    credentialsSupported: [
      {
        format: 'vc+sd-jwt',
        vct: process.env.ISSUER_URL,
        id: process.env.ISSUER_URL,
        cryptographic_binding_methods_supported: ['did:key'],
        cryptographic_suites_supported: [JwaSignatureAlgorithm.ES256],
      },
    ],
  });

  // Create a did:key that we will use for issuance
  const issuerDidResult = await issuer.dids.create<KeyDidCreateOptions>({
    method: 'key',
    options: {
      keyType: KeyType.Ed25519,
    },
  });

  if (issuerDidResult.didState.state !== 'finished') {
    throw new Error('DID creation failed.');
  }

  const { credentialOffer, issuanceSession } =
    await issuer.modules.openId4VcIssuer.createCredentialOffer({
      issuerId: openid4vcIssuer.issuerId,
      // values must match the `id` of the credential supported by the issuer
      offeredCredentials: [process.env.ISSUER_URL],

      // Only pre-authorized code flow is supported
      preAuthorizedCodeFlowConfig: {
        userPinRequired: false,
      },

      // You can store any metadata about the issuance here
      issuanceMetadata: {
        someKey: 'someValue',
      },
    });
  hack.credentialOffer = credentialOffer;

  // Listen and react to changes in the issuance session
  issuer.events.on<OpenId4VcIssuanceSessionStateChangedEvent>(
    OpenId4VcIssuerEvents.IssuanceSessionStateChanged,
    (event) => {
      if (event.payload.issuanceSession.id === issuanceSession.id) {
        console.log(
          'Issuance session state changed to ',
          event.payload.issuanceSession.state,
        );
      }
    },
  );
}

function logResponseBody(req, res, next) {
  const oldWrite = res.write,
    oldEnd = res.end;

  const chunks = [];

  res.write = function (chunk) {
    chunks.push(new Buffer(chunk));

    oldWrite.apply(res, arguments);
  };

  res.end = function (chunk) {
    if (chunk) chunks.push(new Buffer(chunk));

    const body = Buffer.concat(chunks).toString('utf8');
    console.log(req.path, body);

    oldEnd.apply(res, arguments);
  };

  next();
}

issuerRouter.use(logResponseBody);
