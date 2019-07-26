import * as http from "http";
import * as util from "util";

import Validator from "ajv";
import axios, { AxiosError, AxiosInstance } from "axios";
import * as fastify from "fastify";
import plugin from "fastify-plugin";
import httpErrors from "http-errors";
import * as jwt from "jsonwebtoken";
import memoize from "mem";
import * as jose from "node-jose";

const optionsSchema = {
  type: "object",
  required: ["region", "userPoolId"],
  properties: {
    region: {
      type: "string"
    },
    userPoolId: {
      type: "string"
    },
    allowedAudiences: {
      type: "array",
      items: {
        type: "string",
        format: "uri"
      }
    }
  }
};

const fastifyAwsCognitoPluginImplementation: fastify.Plugin<
  http.Server,
  http.IncomingMessage,
  http.ServerResponse,
  fastifyAwsCognitoPlugin.FastifyAwsCognitoPluginOptions
> = async (instance: fastify.FastifyInstance, options: fastifyAwsCognitoPlugin.FastifyAwsCognitoPluginOptions) => {
  await validateOptions(options);

  const issuer = `https://cognito-idp.${options.region}.amazonaws.com/${options.userPoolId}`;
  const axiosInstance =
    options.overrides && options.overrides.axiosInstance ? options.overrides.axiosInstance : axios.create();
  const requestVerifier = cognitoVerifier({
    issuer,
    withAllowedAudiences: options.allowedAudiences,
    withAxiosInstance: axiosInstance
  });
  const decoration: fastifyAwsCognitoPlugin.FastifyAwsCognitoDecoration = {
    verify: requestVerifier
  };

  instance.decorate("cognito", decoration);
  instance.decorateRequest("verifyCognito", function() {
    // @ts-ignore
    cognitoVerifier(this as fastify.FastifyRequest);
  });
};

interface AwsCognitoVerifierOptions {
  issuer: string;
  withAllowedAudiences?: string[];
  withAxiosInstance: AxiosInstance;
}

function cognitoVerifier(options: AwsCognitoVerifierOptions) {
  const verifyToken = util.promisify<string, string, jwt.VerifyOptions>(jwt.verify);
  const createKeyStoreFromWellKnownKeysOfOptimally = memoize(createKeyStoreFromWellKnownKeysOf, { maxAge: 60000 });

  return async function verifyWithCognito(request: fastify.FastifyRequest) {
    const header = getHeaderFromRequest(request);
    const token = getTokenFromHeader(header);
    const keyId = getKeyIdFromToken(token);
    const keyStore = await createKeyStoreFromWellKnownKeysOfOptimally(options.issuer, options.withAxiosInstance);
    const key = getKeyFromKeyStoreByKeyId(keyStore, keyId);
    const pem = await generatePemCertificateFrom(key);
    const extraVerificationOptions: jwt.VerifyOptions = options.withAllowedAudiences
      ? { audience: options.withAllowedAudiences }
      : {};

    try {
      request.token = await verifyToken(token, pem, {
        ...extraVerificationOptions,
        issuer: options.issuer
      });
    } catch (cause) {
      request.log.error(cause);

      if (/audience invalid/gi.test(cause.message)) {
        throw new httpErrors.Unauthorized("Token verification failed: audience is not allowed");
      } else if (/jwt expired/gi.test(cause.message)) {
        throw new httpErrors.Unauthorized("Token verification failed: token expired");
      }

      throw new httpErrors.Unauthorized("Token verification failed");
    }
  };
}

async function createKeyStoreFromWellKnownKeysOf(
  issuer: string,
  axiosInstance: AxiosInstance
): Promise<jose.JWK.KeyStore> {
  const wellKnownKeysUri = `${issuer}/.well-known/jwks.json`;
  const keys = await axiosInstance
    .get(wellKnownKeysUri)
    .then((r) => r.data)
    .catch((error: AxiosError) => {
      if (!(error.response && error.response.status < 500)) {
        return Promise.reject(
          new httpErrors.InternalServerError("An unknown error occurred while retrieving known keys")
        );
      }

      return Promise.resolve(null);
    });

  if (!keys) {
    throw new httpErrors.InternalServerError("Unable to retrieve known keys for user pool id");
  }

  return jose.JWK.asKeyStore(keys);
}

function getHeaderFromRequest(request: fastify.FastifyRequest): string {
  const header = request.headers.authorization;

  if (!header) {
    throw new httpErrors.Unauthorized("Authorization header is missing");
  }

  return header;
}

function getTokenFromHeader(header: string): string {
  const parts = header.split(" ");

  if (parts.length !== 2) {
    throw new httpErrors.Unauthorized("Authorization header is malformed");
  }

  const [, token] = parts;

  return token;
}

function getKeyIdFromToken(token: string): string {
  let keyInformation;

  try {
    const [encodedRawKeyInformation] = token.split(".");
    const rawKeyInformation = decodeBase64(encodedRawKeyInformation);
    keyInformation = JSON.parse(rawKeyInformation);
  } catch (error) {
    throw new httpErrors.Unauthorized("Unable to verify key of token");
  }

  if (!(keyInformation && keyInformation.kid)) {
    throw new httpErrors.Unauthorized("Unable to retrieve key id of token");
  }

  return keyInformation.kid;
}

function getKeyFromKeyStoreByKeyId(keyStore: jose.JWK.KeyStore, keyId: string): jose.JWK.RawKey {
  const key: jose.JWK.RawKey | null = keyStore.get(keyId);

  if (!key) {
    throw new httpErrors.Unauthorized("Token was signed with unknown key id");
  }

  return key;
}

async function generatePemCertificateFrom(rawKey: jose.JWK.RawKey): Promise<string> {
  const key = await jose.JWK.asKey(rawKey);

  return key.toPEM();
}

function decodeBase64(input: string): string {
  return Buffer.from(input, "base64").toString("ascii");
}

const validator = new Validator();

async function validateOptions(options: fastifyAwsCognitoPlugin.FastifyAwsCognitoPluginOptions): Promise<void> {
  const isInvalid = !(await validator.validate(optionsSchema, options));

  if (isInvalid) {
    const [error] = validator.errors!;
    const message = error.dataPath ? `options${error.dataPath} ${error.message}` : `options ${error.message}`;

    throw new Error(message);
  }
}

namespace fastifyAwsCognitoPlugin {
  export interface FastifyAwsCognitoPluginOptions {
    region: string;
    userPoolId: string;
    allowedAudiences?: string[];
    overrides?: {
      axiosInstance?: AxiosInstance;
    };
  }

  export interface FastifyAwsCognitoDecoration {
    verify: fastify.RequestHandler;
  }
}

const fastifyAwsCognitoPlugin = plugin(fastifyAwsCognitoPluginImplementation, {
  name: "fastify-aws-cognito"
});

export = fastifyAwsCognitoPlugin;
