/**
 * UDT Identity Provider — CDK Stack
 *
 * // Why: Codifies the entire IdP infrastructure as a single deployable stack.
 * // Originally vibe-built in the console (2026-05-02), now captured as IaC
 * // so we can tear down and recreate reliably.
 *
 * // Architecture: Serverless IdP using API Gateway → Lambda → SSM/Secrets Manager.
 * // SPA served via CloudFront → S3. SES for inbound/outbound email. EventBridge
 * // for monthly key rotation.
 *
 * @module cdk/idp-stack
 */

import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import * as events from 'aws-cdk-lib/aws-events';
import * as eventsTargets from 'aws-cdk-lib/aws-events-targets';
import * as ses from 'aws-cdk-lib/aws-ses';
import * as sesActions from 'aws-cdk-lib/aws-ses-actions';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { Construct } from 'constructs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DOMAIN_NAME = 'udt-credence.ai';
const HOSTED_ZONE_ID = 'Z0687828C5KQVAA23I1F';

/** Path to handler source files relative to this CDK file */
const HANDLERS_DIR = path.join(__dirname, '..', 'src', 'handlers');

/** Default Lambda settings shared by all functions */
const LAMBDA_DEFAULTS = {
  runtime: lambda.Runtime.NODEJS_20_X,
  architecture: lambda.Architecture.ARM_64,
  handler: 'index.handler',
  memorySize: 256,
  timeout: cdk.Duration.seconds(30),
} as const;

/**
 * Lambda function definition — name, source handler file, and optional
 * overrides for memory/timeout.
 */
interface LambdaDef {
  /** Lambda function name (e.g. 'udt-idp-verify') */
  name: string;
  /** Handler source filename without extension (e.g. 'verify') */
  entry: string;
  /** Memory in MB (default 256) */
  memorySize?: number;
  /** Timeout in seconds (default 30) */
  timeoutSeconds?: number;
}

const LAMBDA_DEFS: LambdaDef[] = [
  { name: 'udt-idp-verify',        entry: 'verify' },
  { name: 'udt-idp-keys',          entry: 'keys' },
  { name: 'udt-idp-request-token', entry: 'request-token' },
  { name: 'udt-idp-login',         entry: 'login',         timeoutSeconds: 90 },
  { name: 'udt-idp-provision',     entry: 'provision' },
  { name: 'udt-idp-twin-status',   entry: 'twin-status' },
  { name: 'udt-idp-mfa-enroll',    entry: 'mfa-enroll' },
  { name: 'udt-idp-mfa-verify',    entry: 'mfa-verify' },
  { name: 'udt-idp-mfa-reset',     entry: 'mfa-reset' },
  { name: 'udt-idp-rotate',        entry: 'rotate',        memorySize: 512, timeoutSeconds: 300 },
  { name: 'udt-idp-inbound-email', entry: 'inbound-email' },
];

/**
 * API route definition — HTTP method, path, and which Lambda handles it.
 */
interface RouteDef {
  method: apigwv2.HttpMethod;
  path: string;
  /** Key into the lambdas map (Lambda function name) */
  handler: string;
}

const ROUTES: RouteDef[] = [
  { method: apigwv2.HttpMethod.GET,  path: '/idp/keys',              handler: 'udt-idp-keys' },
  { method: apigwv2.HttpMethod.POST, path: '/idp/verify',            handler: 'udt-idp-verify' },
  { method: apigwv2.HttpMethod.POST, path: '/idp/request-token',     handler: 'udt-idp-request-token' },
  { method: apigwv2.HttpMethod.POST, path: '/idp/login',             handler: 'udt-idp-login' },
  { method: apigwv2.HttpMethod.POST, path: '/idp/provision',         handler: 'udt-idp-provision' },
  { method: apigwv2.HttpMethod.POST, path: '/idp/twin-status',       handler: 'udt-idp-twin-status' },
  { method: apigwv2.HttpMethod.POST, path: '/idp/mfa/enroll',        handler: 'udt-idp-mfa-enroll' },
  { method: apigwv2.HttpMethod.POST, path: '/idp/mfa/verify',        handler: 'udt-idp-mfa-verify' },
  { method: apigwv2.HttpMethod.POST, path: '/idp/mfa/reset-request', handler: 'udt-idp-mfa-reset' },
  { method: apigwv2.HttpMethod.POST, path: '/idp/mfa/reset-confirm', handler: 'udt-idp-mfa-reset' },
  { method: apigwv2.HttpMethod.POST, path: '/admin/reset-mfa',       handler: 'udt-idp-mfa-reset' },
];

// ---------------------------------------------------------------------------
// Stack
// ---------------------------------------------------------------------------

export class UdtIdpStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // -----------------------------------------------------------------------
    // Stack-level CfnParameter for Animator URL (changes on ECS redeploy)
    // -----------------------------------------------------------------------
    const animatorUrl = new cdk.CfnParameter(this, 'AnimatorUrl', {
      type: 'String',
      default: 'http://ANIMATOR_IP:3200',
      description: 'Public URL of the Animator service (changes on ECS redeploy)',
    });

    // -----------------------------------------------------------------------
    // 1. IAM Role — shared by all Lambda functions
    // -----------------------------------------------------------------------
    const lambdaRole = new iam.Role(this, 'LambdaRole', {
      roleName: 'udt-idp-lambda-role',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Execution role for all UDT IdP Lambda functions',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
      inlinePolicies: {
        'idp-ssm': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: ['ssm:GetParameter', 'ssm:PutParameter'],
              resources: [`arn:aws:ssm:us-east-1:${this.account}:parameter/udt/idp/*`],
            }),
          ],
        }),
        'idp-secrets': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: [
                'secretsmanager:GetSecretValue',
                'secretsmanager:CreateSecret',
                'secretsmanager:PutSecretValue',
                'secretsmanager:ListSecrets',
                'secretsmanager:DeleteSecret',
              ],
              resources: [`arn:aws:secretsmanager:us-east-1:${this.account}:secret:/udt/idp/*`],
            }),
            // ListSecrets requires Resource: * (AWS limitation)
            new iam.PolicyStatement({
              actions: ['secretsmanager:ListSecrets'],
              resources: ['*'],
            }),
          ],
        }),
        'idp-ses': new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              actions: ['ses:SendEmail', 'ses:SendRawEmail'],
              resources: ['*'],
            }),
          ],
        }),
      },
    });

    // -----------------------------------------------------------------------
    // 2. Lambda Functions — NodejsFunction with esbuild bundling
    // -----------------------------------------------------------------------

    /** Map of function name → Lambda construct for route wiring */
    const lambdas: Record<string, NodejsFunction> = {};

    for (const def of LAMBDA_DEFS) {
      const fn = new NodejsFunction(this, sanitizeId(def.name), {
        functionName: def.name,
        entry: path.join(HANDLERS_DIR, `${def.entry}.ts`),
        handler: 'handler',
        runtime: LAMBDA_DEFAULTS.runtime,
        architecture: LAMBDA_DEFAULTS.architecture,
        memorySize: def.memorySize ?? LAMBDA_DEFAULTS.memorySize,
        timeout: cdk.Duration.seconds(def.timeoutSeconds ?? LAMBDA_DEFAULTS.timeout.toSeconds()),
        role: lambdaRole,
        bundling: {
          // AWS SDK v3 is included in the Node 20 runtime — no need to bundle it
          externalModules: ['@aws-sdk/*'],
          minify: true,
          sourceMap: false,
          target: 'node20',
        },
      });

      cdk.Tags.of(fn).add('project', 'udt-idp');
      cdk.Tags.of(fn).add('environment', 'production');

      lambdas[def.name] = fn;
    }

    // -----------------------------------------------------------------------
    // 3. API Gateway HTTP API
    // -----------------------------------------------------------------------
    const httpApi = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: 'udt-idp',
      description: 'UDT Identity Provider API',
      corsPreflight: {
        allowOrigins: [`https://${DOMAIN_NAME}`],
        allowMethods: [
          apigwv2.CorsHttpMethod.GET,
          apigwv2.CorsHttpMethod.POST,
          apigwv2.CorsHttpMethod.OPTIONS,
        ],
        allowHeaders: ['Content-Type', 'Authorization'],
        maxAge: cdk.Duration.hours(1),
      },
    });

    // Wire up routes
    for (const route of ROUTES) {
      const fn = lambdas[route.handler];
      httpApi.addRoutes({
        path: route.path,
        methods: [route.method],
        integration: new integrations.HttpLambdaIntegration(
          `${sanitizeId(route.handler)}-${route.method}-${sanitizeId(route.path)}`,
          fn,
        ),
      });
    }

    // -----------------------------------------------------------------------
    // 4. SSM Parameters
    // -----------------------------------------------------------------------

    const ssmParams: Record<string, string> = {
      '/udt/idp/allowedDomains':   '*.mil,*credence*,gmail.com',
      '/udt/idp/constellationId':  'dla-piee',
      '/udt/idp/ses/fromAddress':  'twin@twinsmith.ai',
      '/udt/idp/ses/fromName':     'UDT Digital Twin',
      '/udt/idp/mfaPolicy':        'required',
      '/udt/idp/mfaIssuer':        'DLA PIEE',
    };

    for (const [paramName, value] of Object.entries(ssmParams)) {
      new ssm.StringParameter(this, `Param${sanitizeId(paramName)}`, {
        parameterName: paramName,
        stringValue: value,
        description: `UDT IdP config: ${paramName}`,
        tier: ssm.ParameterTier.STANDARD,
      });
    }

    // animatorUrl — uses CfnParameter so it can be overridden at deploy time
    new ssm.StringParameter(this, 'ParamAnimatorUrl', {
      parameterName: '/udt/idp/animatorUrl',
      stringValue: animatorUrl.valueAsString,
      description: 'UDT IdP config: Animator service URL (parameterized)',
      tier: ssm.ParameterTier.STANDARD,
    });

    // loginUrl and currentKid are set post-deploy (by rotate Lambda / deploy script)
    // Create them with placeholder values so the Lambdas don't fail on first read.
    new ssm.StringParameter(this, 'ParamLoginUrl', {
      parameterName: '/udt/idp/loginUrl',
      stringValue: `https://${DOMAIN_NAME}/login`,
      description: 'UDT IdP config: Login page URL (set to CloudFront domain)',
      tier: ssm.ParameterTier.STANDARD,
    });

    new ssm.StringParameter(this, 'ParamCurrentKid', {
      parameterName: '/udt/idp/currentKid',
      stringValue: 'PENDING_INITIAL_ROTATION',
      description: 'UDT IdP config: Current signing key ID (set by rotate Lambda)',
      tier: ssm.ParameterTier.STANDARD,
    });

    // -----------------------------------------------------------------------
    // 5. S3 Bucket — SPA hosting
    // -----------------------------------------------------------------------
    const spaBucket = new s3.Bucket(this, 'SpaBucket', {
      bucketName: `udt-idp-spa-${this.account}`,
      websiteIndexDocument: 'index.html',
      websiteErrorDocument: 'index.html', // SPA fallback
      publicReadAccess: true,
      blockPublicAccess: new s3.BlockPublicAccess({
        blockPublicAcls: false,
        ignorePublicAcls: false,
        blockPublicPolicy: false,
        restrictPublicBuckets: false,
      }),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // -----------------------------------------------------------------------
    // 6. CloudFront Distribution
    // -----------------------------------------------------------------------

    // Import existing hosted zone
    const hostedZone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
      hostedZoneId: HOSTED_ZONE_ID,
      zoneName: DOMAIN_NAME,
    });

    // ACM certificate (must be in us-east-1 for CloudFront — we're already there)
    const certificate = new acm.Certificate(this, 'Certificate', {
      domainName: DOMAIN_NAME,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    const distribution = new cloudfront.Distribution(this, 'Distribution', {
      defaultBehavior: {
        origin: new origins.S3StaticWebsiteOrigin(spaBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
      },
      domainNames: [DOMAIN_NAME],
      certificate,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      errorResponses: [
        {
          httpStatus: 404,
          responseHttpStatus: 200,
          responsePagePath: '/index.html',
          ttl: cdk.Duration.seconds(0),
        },
      ],
      comment: 'UDT IdP SPA — udt-credence.ai',
    });

    // -----------------------------------------------------------------------
    // 7. Route 53 Records
    // -----------------------------------------------------------------------

    // A record → CloudFront
    new route53.ARecord(this, 'AliasRecord', {
      zone: hostedZone,
      recordName: DOMAIN_NAME,
      target: route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(distribution)),
    });

    // MX record for SES inbound email
    new route53.MxRecord(this, 'MxRecord', {
      zone: hostedZone,
      values: [
        {
          priority: 10,
          hostName: 'inbound-smtp.us-east-1.amazonaws.com',
        },
      ],
    });

    // -----------------------------------------------------------------------
    // 8. EventBridge Rule — monthly key rotation
    // -----------------------------------------------------------------------
    const rotateFn = lambdas['udt-idp-rotate'];

    new events.Rule(this, 'MonthlyRotation', {
      ruleName: 'udt-idp-monthly-rotation',
      description: 'Rotate IdP signing keys on the 1st of each month at midnight UTC',
      schedule: events.Schedule.expression('cron(0 0 1 * ? *)'),
      targets: [new eventsTargets.LambdaFunction(rotateFn)],
    });

    // -----------------------------------------------------------------------
    // 9. SES Receipt Rule — inbound email → Lambda
    // -----------------------------------------------------------------------
    const inboundEmailFn = lambdas['udt-idp-inbound-email'];

    // Grant SES permission to invoke the Lambda
    inboundEmailFn.addPermission('SesInvoke', {
      principal: new iam.ServicePrincipal('ses.amazonaws.com'),
      sourceAccount: this.account,
    });

    const receiptRuleSet = new ses.ReceiptRuleSet(this, 'ReceiptRuleSet', {
      receiptRuleSetName: 'udt-idp-inbound',
    });

    receiptRuleSet.addRule('InboundEmailRule', {
      recipients: [
        `twin@twinsmith.ai`,
        `token@twinsmith.ai`,
        `access@twinsmith.ai`,
        `twin@${DOMAIN_NAME}`,
        `token@${DOMAIN_NAME}`,
        `access@${DOMAIN_NAME}`,
      ],
      actions: [
        new sesActions.Lambda({
          function: inboundEmailFn,
          invocationType: sesActions.LambdaInvocationType.EVENT,
        }),
      ],
      scanEnabled: true,
    });

    // -----------------------------------------------------------------------
    // 10. Outputs
    // -----------------------------------------------------------------------
    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: httpApi.apiEndpoint,
      description: 'API Gateway endpoint URL',
    });

    new cdk.CfnOutput(this, 'DistributionDomain', {
      value: distribution.distributionDomainName,
      description: 'CloudFront distribution domain name',
    });

    new cdk.CfnOutput(this, 'SpaBucketName', {
      value: spaBucket.bucketName,
      description: 'S3 bucket for SPA deployment',
    });

    new cdk.CfnOutput(this, 'DistributionId', {
      value: distribution.distributionId,
      description: 'CloudFront distribution ID (for cache invalidation)',
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert a string like 'udt-idp-verify' or '/idp/keys' into a valid
 * CDK construct ID like 'UdtIdpVerify' or 'IdpKeys'.
 */
function sanitizeId(name: string): string {
  return name
    .replace(/^\//, '')
    .split(/[-\/]/)
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join('');
}
