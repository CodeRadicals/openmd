import { z } from 'zod';
import { parseURL } from './helpers/parse-url';
import { stringToArray } from './helpers/string-to-array';
import { withDevDefault } from './helpers/with-dev-default';

export const parseEnv = (env: typeof process.env) => {
  const parsedEnv = envSchema.safeParse(env);

  if (parsedEnv.success === false) {
    throw new Error(
      `❌ Invalid environment variables: ${JSON.stringify(
        parsedEnv.error.format(),
        null,
        4
      )}`
    );
  }

  return parsedEnv.data;
};

export const envSchema = z.object({
  NODE_ENV: z
    .union([z.literal('production'), z.literal('development')])
    .default('development'),
  PROXY_URL: withDevDefault(
    z.string().url(),
    'http://localhost:3333'
  ).transform(parseURL),
  REDIRECT_URL: z.string().url().transform(parseURL),
  OAUTH_APP_CLIENT_ID: z.string(),
  OAUTH_APP_SECRET: z.string(),
  OAUTH_APP_SCOPES: withDevDefault(z.string(), '').transform(stringToArray),
  LOGTAIL_SOURCE_TOKEN: withDevDefault(z.string().nullable(), null),
  npm_package_version: z.string(),
});
export type EnvSchemaType = z.infer<typeof envSchema>;
