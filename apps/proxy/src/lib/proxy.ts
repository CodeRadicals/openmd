import {
  OAuthAppAuthentication,
  createOAuthUserAuth,
} from '@octokit/auth-oauth-user';
import { Request, Response } from 'express';
import { z } from 'zod';
import { EnvSchemaType } from './env';
import { ProxyError } from './error';

export const createProxyApi = (env: EnvSchemaType) => ({
  async auth(req: Request, res: Response) {
    const { code } = authQuerySchema.parse(req.query);
    const response = await authenticate(code, env);
    res.status(200).send(response);
  },
  async redirect(req: Request, res: Response) {
    const { code } = authQuerySchema.parse(req.query);
    const { token } = await authenticate(code, env);

    req.log.info(`302 Redirect to ${env.REDIRECT_URL}`);

    const redirectUrl = new URL(env.REDIRECT_URL);
    redirectUrl.searchParams.set('token', token);

    res.status(302).redirect(redirectUrl.href);
  },
});

const authenticate = async (code: string, env: EnvSchemaType) => {
  const auth = createOAuthUserAuth({
    clientType: 'oauth-app',
    clientId: env.OAUTH_APP_CLIENT_ID,
    clientSecret: env.OAUTH_APP_SECRET,
    scopes: env.OAUTH_APP_SCOPES,
    code,
  });

  let authResult: OAuthAppAuthentication;
  try {
    authResult = await auth();
  } catch {
    throw new ProxyError(401, 'OAuth Authentication Failed');
  }

  return authResponseSchema.parse(authResult);
};

const authResponseSchema = z.object({
  token: z.string(),
});

const authQuerySchema = z.object({
  code: z.string(),
});
