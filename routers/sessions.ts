import Router from 'express-promise-router';
import { selectAccountBySession } from '../utils/credential-format';

export async function getSessionsRouter() {
  const router = Router();

  router.get('/current', async function (req, res) {
    const sessionUri = req.get('mu-session-id') as string;
    const { groupId, accountId, sessionId, roles } = await selectAccountBySession(sessionUri)

    res.send({
      links: {
        self: `https://${req.host}${req.baseUrl}`
      },
      data: {
        type: 'sessions',
        id: sessionId,
        attributes: {
          roles
        }
      },
      relationships: {
        account: {
          links: {
              related: `/accounts/${accountId}`
          },
          data: {
            type: 'accounts',
            id: accountId
          }
        },
        group: {
          links: {
            related: `/groups/${groupId}`
          },
          data: {
            type: 'groups',
            id: groupId
          }
        }
      }
    });
  });

  return router;
}
