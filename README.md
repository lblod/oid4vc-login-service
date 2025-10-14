# OID4VCI login service

> [!WARNING]
> This service is currently under test and should not be used in a production context yet

This service implements [OID4VC Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) and [OID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

This means that the service has two uses. The first is allowing users that are signed in through another login service to obtain a Verifiable Credential that attests the group and roles they hold for this application. The second is to then interact with a wallet to verify such a credential and give the user access to the application.

This means that the credentials created by this service (as issuer) could be trusted by different applications maintained by different partners. The verifier can also receive a list of trusted issuer DIDs using the environment variables.

For the contents of the certificate, see the VCT in [./utils/credential-format.ts:certificateProperties](./blob/master/utils/credential-format.ts)

## Required environment variables:

- **ISSUER_DID**: the did of the issuer. Must be a did:web that is properly dereferenceable.
- **ISSUER_KEY_ID**: the key used for verification in this did:web
- **ISSUER_PUBLIC_KEY**: the issuer public key corresponding to this key id as a multibase encoded string
- **ISSUER_PRIVATE_KEY**: the issuer private key corresponding to this key as a multibase encoded string
- **ISSUER_URL**: the url at which the issuer is exposed, for example `https://www.example.com/vc-issuer`
- **VERIFIER_DID**: the did for the verifier. Must be a did:web that is properly dereferenceable.
- **VERIFIER_KEY_ID**: the key id in this did used by the verifier.
- **VERIFIER_PRIVATE_KEY**: the private key corresponding to this key id as a multibase encoded string.
- **VERIFIER_URL**: the url at which the verifier is exposed, for example `https://www.example.com/vc-verifier`

## Optional environment variables:

- **AUTH_CODE_TTL**: time to live in ms for the auth tokens as defined in oid4vci. Default 60000
- **AUTHORIZATION_REQUEST_TTL**: time to live in ms for the authorization requests as defined in oid4vci. Default 600000
- **CARD_BACKGROUND_COLOR**: background color of the card shown in the wallet. Default '#12107c'
- **CARD_TEXT_COLOR**: text color of the card shown in the wallet. Default '#FFFFFF'
- **CLEANUP_CRON_PATTERN**: cron pattern to use for cleaning up expired authorization requests, nonces and tokens. Default '51 \* \* \* \*' (every hour at minute 51)
- **CREDENTIAL_NAME**: name of the credential as shown in the wallet. Default '<PROJECT_NAME> Roles Credential'
- **CREDENTIAL_TYPE**: type of the credential. Default '<PROJECT_NAME>Roles'
- **CREDENTIAL_URI_BASE**: base uri for the credential as stored in the triplestore. Default '<ISSUER_URL>/credentials/'
- **ISSUER_NAME**: human readable name of the issuer. Default '<PROJECT_NAME> OID4VC Issuer'
- **LOG_LEVEL**: log level to use. Default 'info'
- **LOGO_URL**: url to a logo shown in the wallet. Default '<ISSUER_URL>/assets/logo.png'
- **NO_DID_PREFIX**: some wallets break without this due to old spec versions, set to true to omit the `decentralized_identifier:` prefix in the client_id during oid4vp. Default false
- **NONCE_TTL**: time to live in ms for the nonces as defined in oid4vci and oid4vcp. Default 600000
- **SINGLE_CREDENTIAL_RESPONSE**: some wallets break without this due to old oid4vci spec versions, set to true to return a single credential using the `credential` prop instead of an array with one element in `credentials`. Default false
- **TOKEN_TTL**: time to live in seconds for the access tokens as defined in oid4vci. Default 600000. Token AUTH_CODE_TTL must be <= TOKEN_TTL
- **TRUSTED_ISSUERS**: comma separated list of trusted issuer DIDs for verification. Defaults to ISSUER_DID
- **USER_GRAPH_TEMPLATE**: template for user graphs, must contain `{{groupId}}`. Default 'http://mu.semte.ch/graphs/organizations/{{groupId}}'
- **ACCOUNT_GRAPH_TEMPLATE**: template for account graphs, must contain `{{groupId}}`. Default 'http://mu.semte.ch/graphs/organizations/{{groupId}}'
- **SESSION_GRAPH**: graph to store session information in. Default 'http://mu.semte.ch/graphs/sessions'
- **SERVICE_HOMEPAGE**: the uri to use as foaf:accountServiceHomepage for the sessions being created by this service. Defaults to 'https://github.com/lblod/oid4vc-login-service'
- **WORKING_GRAPH**: the uri of the temporary graph to put data related to the issuance and verification of verifiable credentials. This data is always short-lived, you should be able to delete this graph at any time. Default 'http://mu.semte.ch/graphs/verifiable-credentials/temp'
