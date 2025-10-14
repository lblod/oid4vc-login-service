import Router from 'express-promise-router';
import { logger } from '../utils/logger';

export async function getVerifierRouter(verifier) {
  const router = Router();

  router.get('/build-authorization-request-uri', async function (req, res) {
    const session = req.get('mu-session-id') as string;
    const { authorizationRequestUri } =
      await verifier.buildAuthorizationRequestUri(session);
    res.send({
      authorizationRequestUri,
    });
  });

  const handleAuthorizationRequest = async function (req, res) {
    logger.debug(`session: ${req.get('mu-session-id')}`);
    logger.debug(`body: ${JSON.stringify(req.body, null, 2)}`);
    logger.debug(`query params: ${JSON.stringify(req.query, null, 2)}`);
    const originalSession = req.query['original-session'] as string | undefined;
    if (!originalSession) {
      res
        .status(400)
        .send({ error: 'missing original-session query parameter' });
      return;
    }
    const { wallet_metadata, wallet_nonce } = req.body;
    const session = req.get('mu-session-id') as string;
    const authorizationRequestData =
      await verifier.buildAuthorizationRequestData(
        session,
        originalSession,
        wallet_metadata,
        wallet_nonce,
      );
    logger.debug(
      `Authorization request data: ${JSON.stringify(authorizationRequestData, null, 2)}`,
    );
    res.type('application/oauth-authz-req+jwt');
    res.send(authorizationRequestData);
  };

  router.post('/authorization-request', handleAuthorizationRequest);
  router.get('/authorization-request', handleAuthorizationRequest); // older specs use GET

  router.post('/presentation-response', async function (req, res) {
    const currentSession = req.get('mu-session-id') as string;
    const originalSession = req.query['original-session'] as string | undefined;
    logger.debug(`session: ${req.get('mu-session-id')}`);
    logger.debug(`body: ${JSON.stringify(req.body, null, 2)}`);

    if (!originalSession) {
      res
        .status(400)
        .send({ error: 'missing original-session query parameter' });
      return;
    }

    await verifier.handlePresentationResponse(
      currentSession,
      originalSession,
      req.body,
    );

    res.send({ status: 'ok' });
  });

  router.get('/authorization-request-status', async function (req, res) {
    const session = req.get('mu-session-id') as string;
    const status = await verifier.getAuthorizationRequestStatus(session);
    res.send({ status });
  });

  return router;
}
