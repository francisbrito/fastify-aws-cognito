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

Todo
