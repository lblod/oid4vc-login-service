import winston from 'winston';

export const logger = winston.createLogger({
  level: (process.env.LOG_LEVEL || 'info').trim().toLowerCase(), // can't import env because we're using logger there
  format: winston.format.simple(),
  transports: [new winston.transports.Console()],
});
