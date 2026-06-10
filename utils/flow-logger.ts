import { updateSudo } from '@lblod/mu-auth-sudo';
import crypto from 'node:crypto';
import { sparqlEscapeDateTime, sparqlEscapeString, sparqlEscapeUri } from 'mu';
import type { SessionInfo } from './credential-format';
import env from './environment';

const EVENT_URI_BASE = 'http://data.lblod.info/flow-event/';

const ISSUANCE_FLOW_EVENT = 'ext:VCIssuanceFlowEvent' as const;
const VERIFICATION_FLOW_EVENT = 'ext:VCVerificationFlowEvent' as const;

type FlowEventType =
  | typeof ISSUANCE_FLOW_EVENT
  | typeof VERIFICATION_FLOW_EVENT;

async function insertFlowEvent(
  rdfType: FlowEventType,
  eventType: string,
  sessionUri: string,
  sessionInfo?: SessionInfo,
  errorMessage?: string,
): Promise<void> {
  const id = crypto.randomUUID();
  const uri = `${EVENT_URI_BASE}${id}`;

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

export function logIssuanceStarted(sessionUri: string): Promise<void> {
  return insertFlowEvent(ISSUANCE_FLOW_EVENT, 'started', sessionUri);
}

export function logIssuanceSucceeded(
  sessionUri: string,
  sessionInfo: SessionInfo,
): Promise<void> {
  return insertFlowEvent(
    ISSUANCE_FLOW_EVENT,
    'credential-issued',
    sessionUri,
    sessionInfo,
  );
}

export function logIssuanceFailed(
  sessionUri: string,
  errorMessage: string,
): Promise<void> {
  return insertFlowEvent(
    ISSUANCE_FLOW_EVENT,
    'failed',
    sessionUri,
    undefined,
    errorMessage,
  );
}

export function logVerificationStarted(sessionUri: string): Promise<void> {
  return insertFlowEvent(VERIFICATION_FLOW_EVENT, 'started', sessionUri);
}

export function logVerificationSucceeded(
  sessionUri: string,
  sessionInfo: SessionInfo,
): Promise<void> {
  return insertFlowEvent(
    VERIFICATION_FLOW_EVENT,
    'accepted',
    sessionUri,
    sessionInfo,
  );
}

export function logVerificationFailed(
  sessionUri: string,
  errorMessage: string,
): Promise<void> {
  return insertFlowEvent(
    VERIFICATION_FLOW_EVENT,
    'failed',
    sessionUri,
    undefined,
    errorMessage,
  );
}
