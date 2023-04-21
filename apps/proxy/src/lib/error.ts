import { NextFunction, Request, RequestHandler, Response } from 'express';
import { ZodError } from 'zod';
import {
  ErrorMessageOptions as ZodErrorMessageOptions,
  generateErrorMessage as generateZodErrorMessage,
} from 'zod-error';

export class ProxyError extends Error {
  constructor(public code: number, message: string) {
    super(message);
    Object.setPrototypeOf(this, ProxyError.prototype);
  }

  toJSON(): ProxyErrorJSON {
    return {
      statusCode: this.code,
      statusMessage: this.message,
    };
  }

  toString() {
    return `${this.code} ${this.message}`;
  }
}

export const proxyErrorHandler =
  (call: (...a: Parameters<RequestHandler>) => void | Promise<void>) =>
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      await call(req, res, next);
    } catch (error) {
      let proxyError: ProxyError;

      if (error instanceof ProxyError) {
        proxyError = error;
      } else if (error instanceof ZodError) {
        proxyError = new ProxyError(
          400,
          generateZodErrorMessage(error.errors, options)
        );
      } else {
        proxyError = new ProxyError(500, (error as Error).message);
      }

      res.status(proxyError.code);
      res.send(proxyError.toJSON());
    }
  };

const options: ZodErrorMessageOptions = {
  maxErrors: 1,
  path: {
    type: 'objectNotation',
    enabled: true,
    transform: ({ value }) => value,
  },
  message: {
    enabled: true,
    transform: ({ value }) => value.toLowerCase(),
  },
  transform: ({ pathComponent, messageComponent }) =>
    `bad request param \`${pathComponent}\` (${messageComponent})`,
};

interface ProxyErrorJSON {
  statusCode: number;
  statusMessage: string;
}
