import Router from 'express-promise-router';

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
    console.log('session:', req.get('mu-session-id'));
    console.log('body', req.body);
    console.log('query params', req.query);
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
    console.log(JSON.stringify(authorizationRequestData, null, 2));
    res.type('application/oauth-authz-req+jwt');
    res.send(authorizationRequestData);
  };

  router.post('/authorization-request', handleAuthorizationRequest);
  router.get('/authorization-request', handleAuthorizationRequest); // older specs use GET

  router.post('/presentation-response', async function (req, res) {
    const currentSession = req.get('mu-session-id') as string;
    const originalSession = req.query['original-session'] as string | undefined;
    console.log('session:', req.get('mu-session-id'));
    console.log('body', req.body);

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
