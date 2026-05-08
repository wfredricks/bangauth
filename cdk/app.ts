#!/usr/bin/env npx ts-node
/**
 * UDT Identity Provider — CDK App Entry Point
 *
 * // Why: Single-stack deployment for all IdP infrastructure. Everything from
 * // Lambda functions to DNS records in one `cdk deploy`. Self-contained and
 * // reproducible — no manual console clicking required.
 *
 * @module cdk/app
 */

import * as cdk from 'aws-cdk-lib';
import { UdtIdpStack } from './idp-stack';

const app = new cdk.App();

new UdtIdpStack(app, 'UdtIdpStack', {
  env: {
    account: '230152865130',
    region: 'us-east-1',
  },
  tags: {
    project: 'udt-idp',
    environment: 'production',
  },
  description: 'UDT Identity Provider — Serverless IdP for constellation access',
});
