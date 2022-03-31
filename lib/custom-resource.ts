import {
  aws_ec2 as ec2,
  aws_iam as iam,
  aws_lambda as lambda,
  aws_logs as logs,
  AssetHashType,
  Duration,
  RemovalPolicy,
  Tags,
  CustomResource
} from 'aws-cdk-lib';
import { Provider } from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';

export type UpdateCognitoAndOpenSearchCustomResourceConstructProps = {
  projectName: string,
  vpc: ec2.IVpc,
  subnets: ec2.ISubnet[],
  securityGroups: ec2.ISecurityGroup[],
  lambdaRole: iam.IRole,
  cognitoIdentityPoolId: string,
  cognitoIdentityPoolAuthRole: iam.IRole,
  cognitoIdentityPoolUnauthRole: iam.IRole,
  openSearchDomainEndpoint: string,
  openSearchIndexName: string,
  openSearchMasterUserRole: iam.IRole,
  firehoseRole: iam.IRole
};

export class UpdateCognitoAndOpenSearchCustomResource extends Construct {
  constructor(scope: Construct, id: string, props: UpdateCognitoAndOpenSearchCustomResourceConstructProps) {
    super(scope, id);

    const projectName = props.projectName;
    const vpcId = props.vpc.vpcId;

    const functionName = `${projectName}-custom-resource`;
    const functionLogGroupName = `/aws/lambda/${functionName}`;

    Tags.of(this).add('project', projectName);

    const vpc = ec2.Vpc.fromLookup(this, 'vpc', {
      vpcId: vpcId
    });

    // ----------
    // Cloud Watch Logs
    // ----------
    const lambdaLogGroup = new logs.LogGroup(this, 'cfn-custom-resource-lambda-logs', {
      logGroupName: functionLogGroupName,
      removalPolicy: RemovalPolicy.DESTROY,
      retention: logs.RetentionDays.INFINITE
    });

    // -----------------------------
    // Lambda
    // -----------------------------
    const runtime = lambda.Runtime.PYTHON_3_9;
    const onEventHandler = new lambda.SingletonFunction(this, 'cfn-custom-resource-lambda-function', {
      uuid: 'me.msysh.development.aws.cdk.kinesislambdaopensearch',
      code: lambda.AssetCode.fromAsset('lambda/cfn-custom-resource', {
        assetHashType: AssetHashType.OUTPUT,
        bundling: {
          image: runtime.bundlingImage,
          command: [
            'bash',
            '-c',
            [
              'cp -r ./* /asset-output',
              'pip install -t /asset-output --requirement requirements.txt',
            ].join(' && ')
          ],
          user: 'root'
        }
      }),
      handler: 'app.lambda_handler',
      runtime: runtime,
      architecture: lambda.Architecture.X86_64,
      functionName: `${functionName}`,
      memorySize: 128,
      role: props.lambdaRole,
      timeout: Duration.seconds(300),
      environment: {
        LOG_LEVEL: "DEBUG"
      },
      vpc: props.vpc,
      vpcSubnets: { subnets: props.subnets },
      securityGroups: props.securityGroups
    });

    const provider = new Provider(this, 'custom-resource-provider', { onEventHandler });

    const customResource = new CustomResource(this, 'custom-resource', {
      serviceToken: provider.serviceToken,
      properties: {
        'cognitoIdentityPoolId': props.cognitoIdentityPoolId,
        'cognitoIdentityPoolAuthRole': props.cognitoIdentityPoolAuthRole.roleArn,
        'cognitoIdentityPoolUnauthRole': props.cognitoIdentityPoolUnauthRole.roleArn,
        'openSearchDomainEndpoint': props.openSearchDomainEndpoint,
        'openSearchIndexName': props.openSearchIndexName,
        'openSearchMasterUserRoleArn': props.openSearchMasterUserRole.roleArn,
        'firehoseRoleArn': props.firehoseRole.roleArn
      },
      removalPolicy: RemovalPolicy.DESTROY
    });
  }
}