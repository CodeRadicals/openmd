import {
  OAuthAppAuthentication,
  createOAuthUserAuth,
} from '@octokit/auth-oauth-user';
import { z } from 'zod';
import { EnvSchemaType } from './env';
import { ProxyError } from './error';

export const authenticate = async (code: string, env: EnvSchemaType) => {
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

  return oAuthAppAuthenticationSchema.parse(authResult);
};

const oAuthAppAuthenticationSchema = z.object({
  token: z.string(),
});
