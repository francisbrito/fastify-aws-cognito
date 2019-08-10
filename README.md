
# fastify-aws-cognito  
  
[![Build Status](https://img.shields.io/travis/francisbrito/fastify-aws-cognito/master.svg?style=flat-square)](https://travis-ci.org/francisbrito/fastify-aws-cognito) [![Coverage Status](https://img.shields.io/coveralls/github/francisbrito/fastify-aws-cognito/master.svg?style=flat-square)](https://coveralls.io/github/francisbrito/fastify-aws-cognito?branch=master) [![Known vulnerabilities](https://img.shields.io/snyk/vulnerabilities/github/francisbrito/fastify-aws-cognito.svg?style=flat-square)](https://snyk.io//test/github/francisbrito/fastify-aws-cognito?targetFile=package.json) [![npm version](https://img.shields.io/npm/v/fastify-aws-cognito?style=flat-square)](https://www.npmjs.com/package/fastify-aws-cognito) [![npm downloads](https://img.shields.io/npm/dm/fastify-aws-cognito?style=flat-square)](https://www.npmjs.com/package/fastify-aws-cognito)  
  
AWS Cognito JWT verification for Fastify.  
  
## Install  
  
```sh  
npm install fastify-aws-cognito  
```  
  
Or, using `yarn`:  
  
```sh  
yarn add fastify-aws-cognito  
```  
  
## Usage  
  
```javascript  
const fastify = require("fastify")();  
  
fastify  
  .register(require("fastify-aws-cognito"), {  
    region: "<region>",  
    userPoolId: "<user pool id>"  
  })  
  .after(error => {  
    if (error) throw error;  
  
    fastify.get("/", { preValidation: [fastify.cognito.verify] }, async request => request.token);  
  })  
  .listen(3000);  
```  
  
## API  
  
### `plugin(instance, options)`  
#### `instance`  
Type: `fastify.FastifyInstance`  
A `fastify` instance to be decorated. This value will be provided by the framework when calling `fastify.register`.  
  
#### `options`  
Type: `object`  
  
##### `region`  
Type: `string`  
**Required**.  
  
Region where user pool was created. e.g: `us-east-1`.  
  
##### `userPoolId`  
Type: `string`  
**Required**.  
  
Id of the AWS Cognito user pool from which the token was generated. e.g: `us-east-1_1234abcd`  
  
##### `allowedAudiences`  
Type: `string[]`  
_Optional_.

A list of [JWT Audiences](https://tools.ietf.org/html/rfc7519#section-4.1.3) to validate the token. Useful if you'd like to restrict which [app clients](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html) can access your server.

##### `verifyJtiWith`
Type: `function`
_Optional_.

A function with the signature `(jti: string) => Promise<boolean>` to be used to check if a given JWT id is valid or not. If not provided, all `jti` claims will be assumed as valid.

### `instance.cognito.verify(request)`
A `fastify` handler that will reject any request with an invalid or missing JWT.

_Note_: This handler returns a `Promise` and (currently) does not receive a callback.

#### `request`
Type: `fastify.FastifyRequest`
**Required**.

`fastify` request to be verified.

### `FastifyRequest.verifyCognito()`
Verifies the calling request.
