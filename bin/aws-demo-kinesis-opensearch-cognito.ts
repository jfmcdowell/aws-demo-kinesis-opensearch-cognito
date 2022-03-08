#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { StackProps } from 'aws-cdk-lib';
import { KinesisOpenSearchStack } from '../lib/kinesis-opensearch-stack';
import { TransformLambdaStack } from '../lib/transform-lambda-stack';

const app = new cdk.App();

const stackProps: StackProps = {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION
  },
  description: "For streaming data analytics and visualize demonstration."
}

const transformLambdaStack = new TransformLambdaStack(app, 'KinesisOpenSearchCognito-TransformLambdaStack', {
  ...stackProps,
  description: "Lambda function for transformation records on Firehose",
});

const kinesisOpenSearchStack = new KinesisOpenSearchStack(app, 'KinesisOpenSearchCognitoStack', {
  ...stackProps,
  transformLambda: transformLambdaStack.function
});
