import { CronJob } from 'cron';
import env from './environment';
import { VCIssuer } from '../services/issuer';
import { VCVerifier } from '../services/verifier';

export function startCleanupCron({
  issuerService,
  verifierService,
}: {
  issuerService: VCIssuer;
  verifierService: VCVerifier;
}) {
  let running = false;
  const cronjob = CronJob.from({
    cronTime: env.CLEANUP_CRON_PATTERN,
    onTick: async () => {
      if (running) {
        return;
      }
      await issuerService.removeOldCredentialAuthCodes();
      await issuerService.removeOldCredentialOfferTokens();
      await issuerService.removeOldNonces();
      await verifierService.removeOldAuthorizationRequestKeys();
      await verifierService.removeOldAuthorizationRequests();

      running = false;
    },
  });
  cronjob.start();
}
