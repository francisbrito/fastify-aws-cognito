import * as http from "http";

import { FastifyInstance } from "fastify";

import { FastifyAwsCognitoDecoration } from "./index";

declare module "fastify" {
  interface FastifyInstance<
    HttpServer = http.Server,
    HttpRequest = http.IncomingMessage,
    HttpResponse = http.ServerResponse
  > {
    cognito: FastifyAwsCognitoDecoration;
  }

  interface FastifyRequest {
    token: any;
  }
}
