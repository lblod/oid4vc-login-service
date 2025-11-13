import Router from 'express-promise-router';
import {
  selectAccountBySession,
  deleteSession,
} from '../utils/credential-format';

export async function getSessionsRouter() {
  const router = Router();

  router.get('/current', async function (req, res) {
    const sessionUri = req.get('mu-session-id');
    if (!sessionUri) throw new Error('Session header is missing');

    const { groupId, accountId, sessionId, roles } =
      await selectAccountBySession(sessionUri);

    res.send({
      links: {
        self: `https://${req.host}${req.baseUrl}`,
      },
      data: {
        type: 'sessions',
        id: sessionId,
        attributes: {
          roles,
        },
      },
      relationships: {
        account: {
          links: {
            related: `/accounts/${accountId}`,
          },
          data: {
            type: 'accounts',
            id: accountId,
          },
        },
        group: {
          links: {
            related: `/groups/${groupId}`,
          },
          data: {
            type: 'groups',
            id: groupId,
          },
        },
      },
    });
  });

  router.delete('/current', async function (req, res) {
    const sessionUri = req.get('mu-session-id');
    if (!sessionUri) throw new Error('Session header is missing');

    const { account } = await selectAccountBySession(sessionUri);
    await deleteSession(account);
    res.append('mu-auth-allowed-groups', 'CLEAR');
    res.sendStatus(204);
  });

  return router;
}
