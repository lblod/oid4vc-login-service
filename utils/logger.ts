import winston from 'winston';

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info', // can't import env because we're using logger there
  transports: [new winston.transports.Console()],
});
