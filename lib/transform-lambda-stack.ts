import {
  aws_iam as iam,
  aws_lambda as lambda,
  aws_logs as logs,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
  Tags } from 'aws-cdk-lib';
import { Construct } from 'constructs';

import { ContextParameter } from './context-parameter';

export class TransformLambdaStack extends Stack {

  public readonly function: lambda.IFunction;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const contextParam: ContextParameter = this.node.tryGetContext('kinesis-lambda-opensearch-stack') as ContextParameter;
    const projectName = contextParam.projectName;

    const functionName = `${projectName}-transform`;

    const accountId = Stack.of(this).account;
    const region = Stack.of(this).region;

    Tags.of(this).add('project', projectName);

    // -----------------------------
    // IAM Policy & Role
    // -----------------------------
    const lambdaPolicyDocument = new iam.PolicyDocument({
      statements:[
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'logs:CreateLogGroup'
          ],
          resources: [
            `arn:aws:logs:${region}:${accountId}:log-group:/aws/lambda/${functionName}`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'logs:CreateLogStream',
            'logs:PutLogEvents'
          ],
          resources: [
            `arn:aws:logs:${region}:${accountId}:log-group:/aws/lambda/${functionName}:*`
          ]
        })
      ]
    });
    const lambdaRole = new iam.Role(this, 'transform-lambda-role', {
      roleName: `${projectName}-transform-lambda-Role`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: `Transform lambda role for ${projectName}`,
      inlinePolicies: {
        'policy': lambdaPolicyDocument
      }
    });

    // ----------
    // Cloud Watch Logs
    // ----------
    const lambdaLogGroup = new logs.LogGroup(this, 'transform-lambda-logs', {
      logGroupName: `/aws/lambda/${functionName}`,
      removalPolicy: RemovalPolicy.DESTROY,
      retention: logs.RetentionDays.INFINITE
    });

    // -----------------------------
    // Lambda
    // -----------------------------
    const lambdaFunction = new lambda.Function(this, 'transform-lambda', {
      runtime: lambda.Runtime.PYTHON_3_9,
      code: lambda.AssetCode.fromAsset('lambda/transform'),
      handler: 'app.lambda_handler',
      architecture: lambda.Architecture.X86_64,
      functionName: `${functionName}`,
      memorySize: 128,
      role: lambdaRole,
      timeout: Duration.seconds(300),
      environment: {
        //KEY: "VALUE"
        LOG_LEVEL: "DEBUG"
      }
    });

    // -----------------------------
    // Output
    // -----------------------------
    new CfnOutput(this, 'transform-lambda-arn', {
      value: lambdaFunction.functionArn
    });

    this.function = lambdaFunction;
  }
}
