import axios, { AxiosError, AxiosResponse } from "axios";
import fastify, { FastifyInstance } from "fastify";
import jwt from "jsonwebtoken";
import jose from "node-jose";

import fastifyAwsCognitoPlugin, { FastifyAwsCognitoPluginOptions } from "./.";

describe("FastifyAwsCognitoPlugin", () => {
  let instance: FastifyInstance;

  beforeEach(async () => {
    instance = fastify();
  });

  afterEach(async () => {
    await instance.close();
  });

  it("throws if `options` parameter is not an object", async () => {
    // @ts-ignore
    const options: FastifyAwsCognitoPluginOptions = 42;

    await expect(instance.register(fastifyAwsCognitoPlugin, options).ready()).rejects.toThrowError(
      "options should be object",
    );
  });

  it("throws if `options.region` is not provided", async () => {
    // @ts-ignore
    const options: FastifyAwsCognitoPluginOptions = { userPoolId: "us-east-1_foobar" };

    await expect(instance.register(fastifyAwsCognitoPlugin, options).ready()).rejects.toThrowError(
      "options should have required property 'region'",
    );
  });

  it("throws if `options.region` is not string", async () => {
    // @ts-ignore
    const options: FastifyAwsCognitoPluginOptions = { region: 12345, userPoolId: "us-east-1_foobar" };

    await expect(instance.register(fastifyAwsCognitoPlugin, options).ready()).rejects.toThrowError(
      "options.region should be string",
    );
  });

  it("throws if `options.userPoolId` is not provided", async () => {
    // @ts-ignore
    const options: FastifyAwsCognitoPluginOptions = { region: "us-east-1" };

    await expect(instance.register(fastifyAwsCognitoPlugin, options).ready()).rejects.toThrow(
      "options should have required property 'userPoolId'",
    );
  });

  it("throws if `options.userPoolId` is not string", async () => {
    // @ts-ignore
    const options: FastifyAwsCognitoPluginOptions = { region: "us-east-1", userPoolId: 12345 };

    await expect(instance.register(fastifyAwsCognitoPlugin, options).ready()).rejects.toThrow(
      "options.userPoolId should be string",
    );
  });

  it("throws if authorization header is missing", async () => {
    await registerAwsCognitoPluginTo(instance);

    const uri = await instance.listen(0);
    const response = await getUriAndReturnError(uri);

    expect(response).toBeDefined();
    expect(response.status).toBe(401);
    expect(response.data).toMatchObject({
      error: "Unauthorized",
      message: "Authorization header is missing",
      statusCode: 401,
    });
  });

  it("throws if authorization header value is malformed", async () => {
    await registerAwsCognitoPluginTo(instance);

    const uri = await instance.listen(0);
    const response = await getUriAndReturnError(uri, { withAuthorizationHeader: "malformed" });

    expect(response).toBeDefined();
    expect(response.status).toBe(401);
    expect(response.data).toMatchObject({
      error: "Unauthorized",
      message: "Authorization header is malformed",
      statusCode: 401,
    });
  });

  it("throws if unable to get key id from token", async () => {
    await registerAwsCognitoPluginTo(instance);

    const uri = await instance.listen(0);
    const user = { email: "foo@bar.net", sub: "12345" };
    const response = await getUriAndReturnError(uri, { withAuthorizationHeader: `Bearer ${jwt.sign(user, "foobar")}` });

    expect(response).toBeDefined();
    expect(response.status).toBe(401);
    expect(response.data).toMatchObject({
      error: "Unauthorized",
      message: "Unable to retrieve key id of token",
      statusCode: 401,
    });
  });

  it("throws if well known keys uri is unreachable", async () => {
    const axiosInstance = axios.create();
    axiosInstance.get = jest
      .fn(axiosInstance.get.bind(axiosInstance))
      .mockRejectedValueOnce(new Error("Expected error")) as any;

    await registerAwsCognitoPluginTo(instance, { overrides: { axiosInstance } });

    const uri = await instance.listen(0);
    const user = { email: "foo@bar.net", sub: "12345" };
    const signOptions: jwt.SignOptions = { keyid: "foobar" };
    const response = await getUriAndReturnError(uri, {
      withAuthorizationHeader: `Bearer ${jwt.sign(user, "foobar", signOptions)}`,
    });

    expect(response).toBeDefined();
    expect(response.status).toBe(500);

    expect(response.data).toMatchObject({
      error: "Internal Server Error",
      message: "An unknown error occurred while retrieving known keys",
      statusCode: 500,
    });
  });

  it("throws if well known keys uri returns not found", async () => {
    const axiosInstance = axios.create();
    const mockResponse: AxiosError = {
      message: "Expected error",
      code: "ExpectedError",
      name: "ExpectedError",
      config: {},
      isAxiosError: true,
      response: {
        status: 404,
        statusText: "Not Found",
        config: {},
        data: null,
        headers: {},
      },
    };
    axiosInstance.get = jest.fn(axiosInstance.get.bind(axiosInstance)).mockRejectedValueOnce(mockResponse) as any;

    await registerAwsCognitoPluginTo(instance, { overrides: { axiosInstance } });

    const uri = await instance.listen(0);
    const user = { email: "foo@bar.net", sub: "12345" };
    const signOptions: jwt.SignOptions = { keyid: "foobar" };
    const response = await getUriAndReturnError(uri, {
      withAuthorizationHeader: `Bearer ${jwt.sign(user, "foobar", signOptions)}`,
    });

    expect(response).toBeDefined();
    expect(response.status).toBe(500);

    expect(response.data).toMatchObject({
      error: "Internal Server Error",
      message: "Unable to retrieve known keys for user pool id",
      statusCode: 500,
    });
  });

  it("throws if key id of token is not in well known keys", async () => {
    const axiosInstance = axios.create();
    const mockResponse: AxiosResponse = {
      data: { keys: [] },
      statusText: "OK",
      status: 200,
      config: {},
      headers: {},
    };
    axiosInstance.get = jest.fn(axiosInstance.get.bind(axiosInstance)).mockResolvedValueOnce(mockResponse) as any;

    await registerAwsCognitoPluginTo(instance, { overrides: { axiosInstance } });

    const uri = await instance.listen(0);
    const user = { email: "foo@bar.net", sub: "12345" };
    const signOptions: jwt.SignOptions = { keyid: "foobar" };
    const response = await getUriAndReturnError(uri, {
      withAuthorizationHeader: `Bearer ${jwt.sign(user, "foobar", signOptions)}`,
    });

    expect(response).toBeDefined();
    expect(response.status).toBe(401);
    expect(response.data).toMatchObject({
      error: "Unauthorized",
      message: "Token was signed with unknown key id",
      statusCode: 401,
    });
  });

  it("throws if token was not issued by given user pool", async () => {
    const axiosInstance = axios.create();
    const keystore = jose.JWK.createKeyStore();
    const key = await keystore.generate("RSA", 2048, { kid: "foobar", alg: "RS256" });
    const mockResponse: AxiosResponse = {
      data: { keys: [key.toJSON()] },
      statusText: "OK",
      status: 200,
      config: {},
      headers: {},
    };
    axiosInstance.get = jest.fn(axiosInstance.get.bind(axiosInstance)).mockResolvedValueOnce(mockResponse) as any;

    await registerAwsCognitoPluginTo(instance, { overrides: { axiosInstance } });

    const uri = await instance.listen(0);
    const user = { email: "foo@bar.net", sub: "12345" };
    const signOptions: jwt.SignOptions = { keyid: "foobar" };
    const token = jwt.sign(user, "not-the-key-in-keystore", signOptions);
    const response = await getUriAndReturnError(uri, {
      withAuthorizationHeader: `Bearer ${token}`,
    });

    expect(response).toBeDefined();
    expect(response.status).toBe(401);
    expect(response.data).toMatchObject({
      error: "Unauthorized",
      message: "Token verification failed",
      statusCode: 401,
    });
  });

  it("throws if token audience is not allowed", async () => {
    const axiosInstance = axios.create();
    const keystore = jose.JWK.createKeyStore();
    const key = await keystore.generate("RSA", 2048, { kid: "foobar", alg: "RS256" });
    const mockResponse: AxiosResponse = {
      data: { keys: [key.toJSON()] },
      statusText: "OK",
      status: 200,
      config: {},
      headers: {},
    };
    axiosInstance.get = jest.fn(axiosInstance.get.bind(axiosInstance)).mockResolvedValueOnce(mockResponse) as any;

    await registerAwsCognitoPluginTo(instance, {
      overrides: { axiosInstance },
      allowedAudiences: ["http://localhost:3000"],
    });

    const uri = await instance.listen(0);
    const user = { email: "foo@bar.net", sub: "12345" };
    const signOptions: jwt.SignOptions = { keyid: "foobar", audience: "https://somewhere.net", algorithm: "RS256" };
    const token = jwt.sign(user, key.toPEM(true), signOptions);
    const response = await getUriAndReturnError(uri, {
      withAuthorizationHeader: `Bearer ${token}`,
    });

    expect(response).toBeDefined();
    expect(response.status).toBe(401);
    expect(response.data).toMatchObject({
      error: "Unauthorized",
      message: "Token verification failed: audience is not allowed",
      statusCode: 401,
    });
  });

  it("throws if token is expired", async () => {
    const axiosInstance = axios.create();
    const keystore = jose.JWK.createKeyStore();
    const key = await keystore.generate("RSA", 2048, { kid: "foobar", alg: "RS256" });
    const mockResponse: AxiosResponse = {
      data: { keys: [key.toJSON()] },
      statusText: "OK",
      status: 200,
      config: {},
      headers: {},
    };
    axiosInstance.get = jest.fn(axiosInstance.get.bind(axiosInstance)).mockResolvedValueOnce(mockResponse) as any;

    await registerAwsCognitoPluginTo(instance, {
      overrides: { axiosInstance },
    });

    const uri = await instance.listen(0);
    const user = { email: "foo@bar.net", sub: "12345" };
    const signOptions: jwt.SignOptions = {
      keyid: "foobar",
      algorithm: "RS256",
      expiresIn: "1ms",
      issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_foobar",
    };
    const token = jwt.sign(user, key.toPEM(true), signOptions);
    const response = await getUriAndReturnError(uri, {
      withAuthorizationHeader: `Bearer ${token}`,
    });

    expect(response).toBeDefined();
    expect(response.status).toBe(401);
    expect(response.data).toMatchObject({
      error: "Unauthorized",
      message: "Token verification failed: token expired",
      statusCode: 401,
    });
  });

  it("decorates requests with token property", async () => {
    const axiosInstance = axios.create();
    const keystore = jose.JWK.createKeyStore();
    const key = await keystore.generate("RSA", 2048, { kid: "foobar", alg: "RS256" });
    const mockResponse: AxiosResponse = {
      data: { keys: [key.toJSON()] },
      statusText: "OK",
      status: 200,
      config: {},
      headers: {},
    };
    axiosInstance.get = jest.fn(axiosInstance.get.bind(axiosInstance)).mockResolvedValueOnce(mockResponse) as any;

    await registerAwsCognitoPluginTo(instance, {
      overrides: { axiosInstance },
    });

    let request: fastify.FastifyRequest;

    instance.after(() => {
      instance.get("/decorated", { preValidation: instance.cognito.verify }, async (r) => {
        request = r;

        return { it: "works" };
      });
    });

    const uri = await instance.listen(0);
    const user = { email: "foo@bar.net", sub: "12345" };
    const signOptions: jwt.SignOptions = {
      keyid: "foobar",
      algorithm: "RS256",
      expiresIn: "1h",
      issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_foobar",
    };
    const token = jwt.sign(user, key.toPEM(true), signOptions);

    await getUriAndReturnError(`${uri}/decorated`, {
      withAuthorizationHeader: `Bearer ${token}`,
    });

    // @ts-ignore
    expect(request).toBeDefined();
    // @ts-ignore
    expect(request.token).toBeDefined();
  });
});

async function registerAwsCognitoPluginTo(
  instance: fastify.FastifyInstance,
  withOptions: Partial<FastifyAwsCognitoPluginOptions> = {},
) {
  await instance
    .register(fastifyAwsCognitoPlugin, { region: "us-east-1", userPoolId: "us-east-1_foobar", ...withOptions })
    .after(() => {
      instance.get(
        "/",
        {
          preValidation: instance.cognito.verify,
        },
        async () => "ok",
      );
    });
}

async function getUriAndReturnError(
  uri: string,
  options: { withAuthorizationHeader?: string } = {},
): Promise<AxiosResponse> {
  const headers = options.withAuthorizationHeader ? { authorization: options.withAuthorizationHeader } : {};

  return axios.get(uri, { headers }).catch((error) => Promise.resolve(error.response));
}
