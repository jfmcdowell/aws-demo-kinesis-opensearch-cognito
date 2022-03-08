import {
    App,
    AppProps,
    StackProps
} from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { KinesisOpenSearchStack } from '../lib/kinesis-opensearch-stack';
import { TransformLambdaStack } from '../lib/transform-lambda-stack';

const contextParam = {
    context: {
        "kinesis-lambda-opensearch-stack": {
            "projectName": "test",
            "vpcId": "vpc-0123456789",
            "openSearchDomainName": "test",
            "openSearchIndexName": "test",
            "securityGroupIdsForOpenSearch": [
                "sg-123456789abcdef01"
            ],
            "subnets": [
                {"subnetId": "subnet-0123456789abcdef0", "availabilityZone": "us-east-1a"}
            ],
            "bucketNameForFirehose": "test",
            "securityGroupIdsForFirehose": [
                "sg-123456789abcdef01"
            ]
        }
    }
} as AppProps;

const stackProps: StackProps = {
    env: {
        account: "123456789012",
        region: "us-east-1"
    }
};

test("snapshot test", () => {

    const app = new App(contextParam);
    const transformLambdaStack = new TransformLambdaStack(app, "snapshotTest-transform-lambda-stack", stackProps);
    const kinesisOpenSearchStack = new KinesisOpenSearchStack(app, "snapshotTest-kinesis-opensearch-stack", {
        ...stackProps,
        transformLambda: transformLambdaStack.function
    });

    const transformLambdaTemplate = Template.fromStack(transformLambdaStack).toJSON();
    const kinesisOpenSearchTemplate = Template.fromStack(kinesisOpenSearchStack).toJSON();

    transformLambdaTemplate.Parameters = {};
    Object.values(transformLambdaTemplate.Resources).forEach((resource: any) => {
        if (resource?.Properties?.Code) {
            resource.Properties.Code = {};
        }
    });
    expect(transformLambdaTemplate).toMatchSnapshot();

    kinesisOpenSearchTemplate.Parameters = {};
    Object.values(kinesisOpenSearchTemplate.Resources).forEach((resource: any) => {
        if (resource?.Properties?.Code) {
            resource.Properties.Code = {};
        }
    });
    expect(kinesisOpenSearchTemplate).toMatchSnapshot();
});

test("fine grained assertions test", () => {

    const app = new App(contextParam);
    const transformLambdaStack = new TransformLambdaStack(app, "snapshotTest-transform-lambda-stack", stackProps);
    const kinesisOpenSearchStack = new KinesisOpenSearchStack(app, "snapshotTest-kinesis-opensearch-stack", {
        ...stackProps,
        transformLambda: transformLambdaStack.function
    });

    const transformLambdaTemplate = Template.fromStack(transformLambdaStack);
    const kinesisOpenSearchTemplate = Template.fromStack(kinesisOpenSearchStack);

    transformLambdaTemplate.resourceCountIs("AWS::Logs::LogGroup", 1);
    transformLambdaTemplate.resourceCountIs("AWS::IAM::Role", 1);
    transformLambdaTemplate.resourceCountIs("AWS::Lambda::Function", 1);

    kinesisOpenSearchTemplate.resourceCountIs("AWS::Cognito::UserPool", 1);
    kinesisOpenSearchTemplate.resourceCountIs("AWS::Cognito::UserPoolDomain", 1);
    kinesisOpenSearchTemplate.resourceCountIs("AWS::Cognito::IdentityPool", 1);
    kinesisOpenSearchTemplate.resourceCountIs("AWS::IAM::Role", 8);
    kinesisOpenSearchTemplate.resourceCountIs("AWS::Cognito::IdentityPoolRoleAttachment", 1);
    kinesisOpenSearchTemplate.resourceCountIs("AWS::OpenSearchService::Domain", 1);
    kinesisOpenSearchTemplate.resourceCountIs("AWS::Kinesis::Stream", 1);
    kinesisOpenSearchTemplate.resourceCountIs("AWS::KinesisFirehose::DeliveryStream", 1);
    kinesisOpenSearchTemplate.resourceCountIs("AWS::Lambda::Function", 3);
});

test("Cognito Identity Pool require AllowUnauthenticatedIdentities is 'true'", () => {
    const app = new App(contextParam);
    const transformLambdaStack = new TransformLambdaStack(app, "snapshotTest-transform-lambda-stack", stackProps);
    const kinesisOpenSearchStack = new KinesisOpenSearchStack(app, "snapshotTest-kinesis-opensearch-stack", {
        ...stackProps,
        transformLambda: transformLambdaStack.function
    });

    const transformLambdaTemplate = Template.fromStack(transformLambdaStack);
    const kinesisOpenSearchTemplate = Template.fromStack(kinesisOpenSearchStack);

    kinesisOpenSearchTemplate.hasResourceProperties("AWS::Cognito::IdentityPool", {
        AllowUnauthenticatedIdentities: true
    })
});
