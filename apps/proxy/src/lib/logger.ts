import { IncomingMessage } from 'node:http';
import pino from 'pino';
import pinoHttp from 'pino-http';
import { EnvSchemaType } from './env';

export const createLoggerMiddleware = (env: EnvSchemaType) =>
  pinoHttp({
    logger: pino(logtailTransport(env)),
    level: env.NODE_ENV === 'production' ? 'info' : 'debug',
    customLogLevel: function (_, res, error) {
      if (res.statusCode >= 400 && res.statusCode < 500) {
        return 'warn';
      } else if (res.statusCode >= 500 || error) {
        return 'error';
      } else if (res.statusCode >= 300 && res.statusCode < 400) {
        return 'silent';
      }
      return 'info';
    },
    customSuccessMessage: function (req, res) {
      return reqMessage(`${res.statusCode} ${res.statusMessage}`, req);
    },
    customReceivedMessage: function (req) {
      return reqMessage(`request received`, req);
    },
    customErrorMessage: function (req, res) {
      return reqMessage(`${res.statusCode} ${res.statusMessage}`, req);
    },
  });

const logtailTransport = (env: EnvSchemaType) => {
  if (env.LOGTAIL_SOURCE_TOKEN === null) {
    return;
  }

  return pino.transport({
    target: '@logtail/pino',
    options: { sourceToken: env.LOGTAIL_SOURCE_TOKEN },
  });
};

const reqMessage = (message: string, req: IncomingMessage) =>
  `[${req.method}] ${req.url} : ${message}`;
