import { Request, Response } from 'express';
import { z } from 'zod';
import { authenticate } from './auth';
import { EnvSchemaType } from './env';
import { ProxyError } from './error';

export const createProxyApi = (env: EnvSchemaType) => ({
  async auth(req: Request, res: Response) {
    const { code, redirect_url } = authQuerySchema.parse(req.query);
    const redirectUrl = new URL(redirect_url || env.REDIRECT_URL);
    const { token } = await authenticate(code, env);

    req.log.info(`302 Redirect to ${redirectUrl.href}`);

    redirectUrl.searchParams.set('token', token);

    res.status(302).redirect(redirectUrl.href);
  },
  async status(_: Request, res: Response) {
    const result = {
      statusCode: 200,
      statusMessage: 'OK',
      timestamp: Date.now(),
      uptime: process.uptime(),
      hrtime: process.hrtime(),
    };
    try {
      res.send(result);
    } catch {
      throw new ProxyError(503, 'service unavailable');
    }
  },
});

const authQuerySchema = z.object({
  code: z.string(),
  redirect_url: z.string().url().optional(),
});
