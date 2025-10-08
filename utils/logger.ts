import env from './environment';

import winston from 'winston';

export const logger = winston.createLogger({
  level: env.LOG_LEVEL,
  transports: [new winston.transports.Console()],
});
