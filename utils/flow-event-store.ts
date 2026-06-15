import { updateSudo } from '@lblod/mu-auth-sudo';
import {
  sparqlEscapeDateTime,
  sparqlEscapeString,
  sparqlEscapeUri,
  uuid,
} from 'mu';
import type { SessionInfo } from './credential-format';
import env from './environment';

const FLOW_EVENT_URI_BASE = 'http://data.lblod.info/flow-event/';

const CREDENTIAL_ISSUANCE_EVENT = 'ext:CredentialIssuanceEvent' as const;
const CREDENTIAL_VERIFICATION_EVENT =
  'ext:CredentialVerificationEvent' as const;

type CredentialFlowEventType =
  | typeof CREDENTIAL_ISSUANCE_EVENT
  | typeof CREDENTIAL_VERIFICATION_EVENT;

async function storeCredentialFlowEvent(
  rdfType: CredentialFlowEventType,
  eventType: string,
  sessionUri: string,
  sessionInfo?: SessionInfo,
  errorMessage?: string,
): Promise<void> {
  const id = uuid();
  const uri = `${FLOW_EVENT_URI_BASE}${id}`;

  const extraTriples: string[] = [];
  if (sessionInfo) {
    extraTriples.push(
      `${sparqlEscapeUri(uri)} ext:account ${sparqlEscapeUri(sessionInfo.accountUri)} .`,
      `${sparqlEscapeUri(uri)} ext:group ${sparqlEscapeUri(sessionInfo.group)} .`,
      `${sparqlEscapeUri(uri)} ext:roles ${sparqlEscapeString(sessionInfo.roles)} .`,
    );
  }
  if (errorMessage) {
    extraTriples.push(
      `${sparqlEscapeUri(uri)} ext:errorMessage ${sparqlEscapeString(errorMessage)} .`,
    );
  }

  await updateSudo(`
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX dct: <http://purl.org/dc/terms/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    INSERT DATA {
      GRAPH ${sparqlEscapeUri(env.LOG_GRAPH)} {
        ${sparqlEscapeUri(uri)} a ${rdfType} ;
          mu:uuid ${sparqlEscapeString(id)} ;
          ext:session ${sparqlEscapeUri(sessionUri)} ;
          ext:eventType ${sparqlEscapeString(eventType)} ;
          dct:created ${sparqlEscapeDateTime(new Date())} .
        ${extraTriples.join('\n        ')}
      }
    }
  `);
}

export function storeCredentialIssuanceStartedEvent(
  sessionUri: string,
): Promise<void> {
  return storeCredentialFlowEvent(
    CREDENTIAL_ISSUANCE_EVENT,
    'issuance-started',
    sessionUri,
  );
}

export function storeCredentialIssuanceSucceededEvent(
  sessionUri: string,
  sessionInfo: SessionInfo,
): Promise<void> {
  return storeCredentialFlowEvent(
    CREDENTIAL_ISSUANCE_EVENT,
    'issuance-succeeded',
    sessionUri,
    sessionInfo,
  );
}

export function storeCredentialIssuanceFailedEvent(
  sessionUri: string,
  errorMessage: string,
): Promise<void> {
  return storeCredentialFlowEvent(
    CREDENTIAL_ISSUANCE_EVENT,
    'issuance-failed',
    sessionUri,
    undefined,
    errorMessage,
  );
}

export function storeCredentialVerificationStartedEvent(
  sessionUri: string,
): Promise<void> {
  return storeCredentialFlowEvent(
    CREDENTIAL_VERIFICATION_EVENT,
    'verification-started',
    sessionUri,
  );
}

export function storeCredentialVerificationSucceededEvent(
  sessionUri: string,
  sessionInfo: SessionInfo,
): Promise<void> {
  return storeCredentialFlowEvent(
    CREDENTIAL_VERIFICATION_EVENT,
    'verification-succeeded',
    sessionUri,
    sessionInfo,
  );
}

export function storeCredentialVerificationFailedEvent(
  sessionUri: string,
  errorMessage: string,
): Promise<void> {
  return storeCredentialFlowEvent(
    CREDENTIAL_VERIFICATION_EVENT,
    'verification-failed',
    sessionUri,
    undefined,
    errorMessage,
  );
}
