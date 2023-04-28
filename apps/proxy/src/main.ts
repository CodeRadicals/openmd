import express from 'express';
import { injectEnv, parseEnv } from './lib/env';
import { proxyErrorHandler } from './lib/error';
import { createLoggerMiddleware } from './lib/logger';
import { createProxyApi } from './lib/proxy';

function run() {
  injectEnv();

  const env = parseEnv(process.env);
  const loggerMiddleware = createLoggerMiddleware(env);
  const proxyApi = createProxyApi(env);
  const app = express();

  app.use(loggerMiddleware);
  app.get('/auth', proxyErrorHandler(proxyApi.auth));
  app.get('/status', proxyErrorHandler(proxyApi.status));
  app.get('/', async (_, res) => {
    res.send({ version: env.npm_package_version });
  });

  const url = env.PROXY_URL;
  app.listen(Number(url.port), url.hostname, () => {
    console.log(`[ ready ] ${url.origin}`);
  });

  const logger = loggerMiddleware.logger;
  process.on('uncaughtException', (error) => {
    logger.fatal(error, 'uncaught exception detected');
  });
}

run();
