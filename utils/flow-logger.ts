import { updateSudo } from '@lblod/mu-auth-sudo';
import {
  sparqlEscapeDateTime,
  sparqlEscapeString,
  sparqlEscapeUri,
  uuid,
} from 'mu';
import type { SessionInfo } from './credential-format';
import env from './environment';

const EVENT_URI_BASE = 'http://data.lblod.info/flow-event/';

type FlowEventType = 'ext:IssuanceFlowEvent' | 'ext:VerificationFlowEvent';

async function insertFlowEvent(
  rdfType: FlowEventType,
  eventType: string,
  sessionUri: string,
  sessionInfo?: SessionInfo,
  errorMessage?: string,
): Promise<void> {
  const uri = `${EVENT_URI_BASE}${uuid()}`;

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
    INSERT DATA {
      GRAPH ${sparqlEscapeUri(env.LOG_GRAPH)} {
        ${sparqlEscapeUri(uri)} a ${rdfType} ;
          ext:session ${sparqlEscapeUri(sessionUri)} ;
          ext:eventType ${sparqlEscapeString(eventType)} ;
          dct:created ${sparqlEscapeDateTime(new Date())} .
        ${extraTriples.join('\n        ')}
      }
    }
  `);
}

export function logIssuanceStarted(sessionUri: string): Promise<void> {
  return insertFlowEvent('ext:IssuanceFlowEvent', 'started', sessionUri);
}

export function logIssuanceSucceeded(
  sessionUri: string,
  sessionInfo: SessionInfo,
): Promise<void> {
  return insertFlowEvent(
    'ext:IssuanceFlowEvent',
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
    'ext:IssuanceFlowEvent',
    'failed',
    sessionUri,
    undefined,
    errorMessage,
  );
}

export function logVerificationStarted(sessionUri: string): Promise<void> {
  return insertFlowEvent('ext:VerificationFlowEvent', 'started', sessionUri);
}

export function logVerificationSucceeded(
  sessionUri: string,
  sessionInfo: SessionInfo,
): Promise<void> {
  return insertFlowEvent(
    'ext:VerificationFlowEvent',
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
    'ext:VerificationFlowEvent',
    'failed',
    sessionUri,
    undefined,
    errorMessage,
  );
}
