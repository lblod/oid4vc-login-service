import env from './environment';
import { sparqlEscapeDateTime, sparqlEscapeString, sparqlEscapeUri } from 'mu';
import { querySudo, updateSudo } from '@lblod/mu-auth-sudo';

export const certificateProperties = [
  { field: 'firstName', label: 'First name', type: 'string' },
  { field: 'lastName', label: 'Last name', type: 'string' },
  { field: 'did', label: 'DID', type: 'string', required: true },
  { field: 'userUri', label: 'User URI', type: 'string' },
  { field: 'accountUri', label: 'Account URI', type: 'string' },
  { field: 'userId', label: 'User ID', type: 'string' },
  { field: 'accountId', label: 'Account ID', type: 'string' },
  { field: 'group', label: 'Group', type: 'string', required: true },
  { field: 'roles', label: 'Roles', type: 'string', required: true },
];

export const getCredentialMetadataClaims = () => {
  return certificateProperties.map((prop) => {
    return {
      path: [prop.field],
      display: [
        {
          name: prop.label,
          local: 'en-US',
        },
      ],
    };
  });
};

export const getOldCredentialClaims = () => {
  const claims = {};
  certificateProperties.forEach((prop) => {
    claims[prop.field] = {
      en: {
        name: prop.label,
        locale: 'en-US',
      },
    };
  });
  return claims;
};

export const getCredentialDisplay = () => {
  return [
    {
      name: env.CREDENTIAL_NAME,
      locale: 'en-US',
      logo: {
        uri: env.LOGO_URL,
        url: env.LOGO_URL,
        alt_text: `${env.ISSUER_NAME} Logo`,
      },
      description: `A credential that holds your access rights in ${env.PROJECT_NAME}`,
      background_color: env.CARD_BACKGROUND_COLOR,
      text_color: env.CARD_TEXT_COLOR,
    },
  ];
};

export const getVctDisplay = () => {
  return [
    {
      lang: 'en',
      name: env.CREDENTIAL_NAME,
      description: `A credential that holds your access rights in ${env.PROJECT_NAME}`,
      rendering: {
        simple: {
          background_color: env.CARD_BACKGROUND_COLOR,
          text_color: env.CARD_TEXT_COLOR,
          logo: {
            url: env.LOGO_URL,
            uri: env.LOGO_URL,
            alt_text: `${env.PROJECT_NAME} Logo`,
          },
        },
      },
    },
  ];
};

export const getVctClaims = () => {
  return certificateProperties.map((prop) => {
    return {
      path: prop.field,
      display: {
        name: prop.label,
        locale: 'en-US',
      },
      sd: 'allowed',
    };
  });
};

export const getVctSchema = () => {
  const properties = {};
  certificateProperties.forEach((prop) => {
    properties[prop.field] = { type: prop.type };
  });
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    type: 'object',
    properties,
    required: ['did'],
  };
};

export const getDcqlClaims = () => {
  return certificateProperties.map((prop) => {
    return {
      path: [prop.field],
    };
  });
};

export const getRequiredClaimsForValidation = () => {
  return certificateProperties
    .filter((prop) => prop.required)
    .map((prop) => {
      return prop.field;
    });
};

export const getDisclosureFrame = () => {
  // type should be the keys of sessioninfo
  return [
    'did',
    ...certificateProperties.map((prop) => {
      return prop.field;
    }),
  ] as (keyof SessionInfo & 'did')[];
};

export type SessionInfo = {
  accountUri: string;
  accountId?: string;
  userUri?: string;
  userId?: string;
  firstName?: string;
  lastName?: string;
  group: string;
  roles: string;
};

export const getSessionInfoForCredentialOfferToken = async (token: string) => {
  const result = await querySudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX dct: <http://purl.org/dc/terms/>
      PREFIX foaf: <http://xmlns.com/foaf/0.1/>

      SELECT ?accountUri ?accountId ?userUri ?userId ?firstName ?lastName ?group ?role {
        GRAPH <http://mu.semte.ch/graphs/verifiable-credential-tokens> {
          ?token a ext:CredentialOfferToken .
          ?token ext:issuerUrl ${sparqlEscapeString(env.ISSUER_URL)} .
          ?token ext:authToken ${sparqlEscapeString(token)} .
          ?token ext:session ?session .
          ?token dct:created ?created .
        }
        FILTER(?created > ${sparqlEscapeDateTime(new Date(Date.now() - env.TOKEN_TTL))})

        ?session ext:sessionGroup ?group .
        ?session ext:sessionRole ?role .
        ?session <http://mu.semte.ch/vocabularies/session/account> ?accountUri .

        OPTIONAL {
          ?accountUri mu:uuid ?accountId .
          ?user foaf:account ?accountUri .
          ?user mu:uuid ?userId .
          ?user foaf:firstName ?firstName .
          ?user foaf:familyName ?lastName .
        }
      }`);

  if (result.results.bindings.length === 0) {
    return null;
  }
  const certificateInfo = {};

  const firstResult = result.results.bindings[0];
  certificateInfo['accountUri'] = firstResult.accountUri.value;
  if (firstResult.accountId) {
    certificateInfo['accountId'] = firstResult.accountId.value;
  }
  if (firstResult.userUri) {
    certificateInfo['userUri'] = firstResult.userUri.value;
  }
  if (firstResult.userId) {
    certificateInfo['userId'] = firstResult.userId.value;
  }
  if (firstResult.firstName) {
    certificateInfo['firstName'] = firstResult.firstName.value;
  }
  if (firstResult.lastName) {
    certificateInfo['lastName'] = firstResult.lastName.value;
  }

  const groups = new Set<string>();
  const roles = new Set<string>();
  result.results.bindings.forEach((binding) => {
    groups.add(binding.group.value);
    roles.add(binding.role.value);
  });
  if (groups.size > 0) {
    throw new Error('Multiple groups not supported');
  }
  certificateInfo['group'] = Array.from(groups).join(',');
  certificateInfo['roles'] = Array.from(roles).join(',');

  return certificateInfo as SessionInfo;
};

export const updateSessionWithCredentialInfo = async (
  session: string,
  sessionInfo: SessionInfo,
) => {
  const {
    group,
    roles,
    firstName,
    lastName,
    accountUri,
    accountId,
    userId,
    userUri,
  } = sessionInfo;
  const safeRolesString = roles
    .split(',')
    .map((role) => sparqlEscapeString(role))
    .join('\n');

  await updateSudo(`
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
      PREFIX dct: <http://purl.org/dc/terms/>
      DELETE {
        GRAPH ?g {
          ?session ext:sessionGroup ?oldGroup ;
            ext:sessionRole ?oldRoles ;
            dct:modified ?oldMod .
        }
      } INSERT {
        GRAPH ?g {
          ?session ext:sessionGroup ?newGroup ;
            ext:sessionRole ?newRoles ;
            dct:modified ?newMod .
        }
    }  WHERE {
        GRAPH ?g {
          VALUES ?session {
            ${sparqlEscapeUri(session)}
          }
          ?session a ext:Session .
          OPTIONAL {
            ?session ext:sessionGroup ?oldGroup .
          }
          OPTIONAL {
            ?session ext:sessionRole ?oldRoles .
          }
          OPTIONAL {
            ?session dct:modified ?oldMod .
          }
          VALUES ?newGroup { ${sparqlEscapeUri(group)} }
          VALUES ?newRoles {
            ${safeRolesString}
          }
          BIND(NOW() AS ?newMod)
        }
      }
    `);

  // we won't override the user info if it's already there, if it's not though, we add it
  const accountResult = await querySudo(`
      PREFIX foaf: <http://xmlns.com/foaf/0.1/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

      SELECT ?account WHERE {
        VALUES ?session { ${sparqlEscapeUri(session)} }
        ?session <http://mu.semte.ch/vocabularies/session/account> ?account .
      } LIMIT 1`);
  if (accountResult.results.bindings.length > 0) {
    return;
  }

  await updateSudo(`
      PREFIX foaf: <http://xmlns.com/foaf/0.1/>
      PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
      PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

      INSERT {
        GRAPH ?g {

          ?session <http://mu.semte.ch/vocabularies/session/account> ?account .
          ?account a foaf:OnlineAccount ;
            mu:uuid ?accountId .
          ?user a foaf:Person ;
            foaf:account ?account ;
            mu:uuid ?userId ;
            foaf:firstName ?firstName ;
            foaf:familyName ?lastName .
        }
      }
      WHERE {
        GRAPH ?g {
          ?session ext:sessionGroup ?group .
          VALUES ?session ?account ?accountId ?user ?userId ?firstName ?lastName {
            ${sparqlEscapeUri(session)} ${sparqlEscapeUri(accountUri)} ${sparqlEscapeString(accountId)} ${sparqlEscapeUri(userUri)} ${sparqlEscapeString(userId)} ${sparqlEscapeString(firstName)} ${sparqlEscapeString(lastName)}
          }
        }
      }`);
};
