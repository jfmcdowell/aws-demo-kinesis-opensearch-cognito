import {
  aws_cognito as cognito,
  aws_ec2 as ec2,
  aws_iam as iam,
  aws_kinesis as kinesis,
  aws_kinesisfirehose as firehose,
  aws_lambda as lambda,
  aws_logs as logs,
  aws_opensearchservice as opensearch,
  aws_s3 as s3,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
  Tags } from 'aws-cdk-lib';
import { Construct } from 'constructs';

import { ContextParameter, Subnet } from './context-parameter';
import { CognitoAuth } from './cognito-auth';
import { UpdateCognitoAndOpenSearchCustomResource } from './custom-resource';

export type KinesisOpenSearchStackProps = StackProps & {
  transformLambda: lambda.IFunction
};

export class KinesisOpenSearchStack extends Stack {

  constructor(scope: Construct, id: string, props: KinesisOpenSearchStackProps) {
    super(scope, id, props);

    const accountId = Stack.of(this).account;
    const region = Stack.of(this).region;

    const contextParam: ContextParameter = this.node.tryGetContext('kinesis-lambda-opensearch-stack') as ContextParameter;

    const projectName = contextParam.projectName;
    const vpcId = contextParam.vpcId;
    const openSearchDomainName = contextParam.openSearchDomainName;
    const openSearchIndexName = contextParam.openSearchIndexName;
    const securityGroupIdsForOpenSearch: string[] = contextParam.securityGroupIdsForOpenSearch;
    const subnetInfos: Subnet[] = contextParam.subnets;
    const bucketNameForFirehose = contextParam.bucketNameForFirehose;
    const securityGroupIdsForFirehose: string[] = contextParam.securityGroupIdsForFirehose;

    Tags.of(this).add('project', projectName);

    const vpc = ec2.Vpc.fromLookup(this, 'vpc', {
      vpcId: vpcId
    });

    const securityGroupsForOpenSearch: ec2.ISecurityGroup[] = getSecurityGroups(this, 'opensearch-security-group', securityGroupIdsForOpenSearch);
    const securityGroupsForFirehose: ec2.ISecurityGroup[] = getSecurityGroups(this, 'firehose-security-group', securityGroupIdsForFirehose);
    const subnets: ec2.ISubnet[] = getSubnets(this, subnetInfos);

    // -----------------------------
    // Cognito
    // -----------------------------
    const cognitoAuth = new CognitoAuth(this, 'cognito-auth', {
      projectName: projectName
    });

    // -----------------------------
    // IAM Policy & Role (for Custom Resource Lambda)
    // -----------------------------
    const customResourcefunctionName = `${projectName}-custom-resource`;
    const customResourceLambdaLogGroupName = `/aws/lambda/${customResourcefunctionName}`;
    const customResourceLambdaPolicyDocument = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'logs:CreateLogGroup'
          ],
          resources: [
            `arn:aws:logs:${region}:${accountId}:log-group:${customResourceLambdaLogGroupName}`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'logs:CreateLogStream',
            'logs:PutLogEvents'
          ],
          resources: [
            `arn:aws:logs:${region}:${accountId}:log-group:${customResourceLambdaLogGroupName}:*`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'ec2:CreateNetworkInterface',
            'ec2:DescribeNetworkInterfaces',
            'ec2:DeleteNetworkInterface'
          ],
          resources: [
            '*'
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'cognito-identity:DescribeIdentityPool'
          ],
          resources: [
            `arn:aws:cognito-identity:${region}:${accountId}:identitypool/${cognitoAuth.props.identityPoolId}`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'cognito-identity:SetIdentityPoolRoles'
          ],
          resources: [
            '*'
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'es:ESHttpPut'
          ],
          resources: [
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomainName}/_plugins/_security/api/roles/firehose`,
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomainName}/_plugins/_security/api/rolesmapping/firehose`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'es:DescribeDomain'
          ],
          resources: [
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomainName}`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'sts:AssumeRole'
          ],
          resources: [
            `arn:aws:iam::${accountId}:role/${projectName}-opensearch-master-user-role`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iam:PassRole'
          ],
          resources: [
            cognitoAuth.props.identityPoolAuthRole.roleArn,
            cognitoAuth.props.identityPoolUnauthRole.roleArn
          ],
          // conditions: {
          //   "StringEquals": {
          //     "iam:PassedToService": "cognito-identity.amazonaws.com"
          //   }
          // }
        })
      ]
    });
    const customResourceLambdaRole = new iam.Role(this, 'cfn-custom-resource-lambda-role', {
      roleName: `${projectName}-cfn-custom-resource-lambda-role`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: `Post set up CfnCustomResource Lambda role for ${projectName}`,
      inlinePolicies: {
        'policy': customResourceLambdaPolicyDocument
      }
    });

    // -----------------------------
    // OpenSearch
    // -----------------------------

    // Cognito Auth Role
    const roleOpenSearchCognitoAuth = new iam.Role(this, 'opensearch-cognito-auth-role', {
      roleName: `${projectName}-cognito-auth-role`,
      assumedBy: new iam.ServicePrincipal('es.amazonaws.com'),
      description: `Cognito auth role for ${projectName}`,
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonOpenSearchServiceCognitoAccess'),
      ]
    });
    roleOpenSearchCognitoAuth.attachInlinePolicy(new iam.Policy(this, 'opensearch-cognito-auth-policy', {
      policyName: 'policy',
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'ec2:DescribeVpcs',
            'cognito-identity:ListIdentityPools',
            'cognito-idp:ListUserPools'
          ],
          resources: [
            '*'
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iam:GetRole',
            'iam:PassRole'
          ],
          resources: [
            roleOpenSearchCognitoAuth.roleArn
          ]
        })
      ]
    }));

    // OpenSearch Master Uesr Role
    const masterUserPolicy = new iam.PolicyDocument({
      statements:[
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'es:*'
          ],
          resources: [
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomainName}/*`
          ]
        })
      ]
    });
    const masterUserRole = new iam.Role(this, 'opensearch-master-user-role', {
      roleName: `${projectName}-opensearch-master-user-role`,
      assumedBy: new iam.CompositePrincipal(
        new iam.FederatedPrincipal(
          'cognito-identity.amazonaws.com',
          {
            "StringEquals": {
              "cognito-identity.amazonaws.com:aud": cognitoAuth.props.identityPoolId
            },
            "ForAnyValue:StringLike": {
              "cognito-identity.amazonaws.com:amr": "authenticated"
            }
          },
          'sts:AssumeRoleWithWebIdentity'
        ),
        new iam.ArnPrincipal(customResourceLambdaRole.roleArn)
      ),
      description: `OpenSearch master user role for ${projectName} - Domain Name: ${openSearchDomainName}`,
      inlinePolicies: {
        'policy': masterUserPolicy
      }
    });

    // CloudWatch Logs
    const openSearchLogs = new logs.LogGroup(this, 'opensearch-logs', {
      logGroupName: `/aws/opensearch/${openSearchDomainName}`,
      removalPolicy: RemovalPolicy.DESTROY,
      retention: logs.RetentionDays.SIX_MONTHS
    });

    // OpenSearch Domain
    const openSearchDomain = new opensearch.Domain(this, 'opensearch', {
      version: opensearch.EngineVersion.OPENSEARCH_1_1,
      accessPolicies: [
        new iam.PolicyStatement({
          principals: [
            new iam.AccountPrincipal(accountId)
          ],
          effect: iam.Effect.ALLOW,
          actions: [
            'es:*'
          ],
          resources: [
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomainName}/*`
          ]
        })
      ],
      capacity: {
        dataNodeInstanceType: 'm5.large.search',
        dataNodes: 1,
        // masterNodeInstanceType: '',
        masterNodes: 0,
        // warmInstanceType: '',
        warmNodes: 0
      },
      cognitoDashboardsAuth: {
        identityPoolId: cognitoAuth.props.identityPoolId,
        userPoolId: cognitoAuth.props.userPoolId,
        role: roleOpenSearchCognitoAuth
      },
      // customEndpoint: {
      //   domainName: '',
      //   certificate: acm.Certificate.fromCertificateArn(this, 'custom-domain-certificate', ''),
      //   hostedZone: route53.HostedZone.fromHostedZoneId(this, 'custom-domain-hostedzon', '')
      // },
      domainName: openSearchDomainName,
      ebs: {
        enabled: true,
        volumeSize: 20,
        volumeType: ec2.EbsDeviceVolumeType.GP2
      },
      enableVersionUpgrade: true,
      encryptionAtRest: {
        enabled: true,
      },
      enforceHttps: true,
      fineGrainedAccessControl: {
        masterUserArn: masterUserRole.roleArn
      },
      logging: {
        appLogEnabled: true,
        appLogGroup: openSearchLogs,
        auditLogEnabled: true,
        auditLogGroup: openSearchLogs,
        slowIndexLogEnabled: true,
        slowIndexLogGroup: openSearchLogs,
        slowSearchLogEnabled: true,
        slowSearchLogGroup: openSearchLogs
      },
      nodeToNodeEncryption: true,
      removalPolicy: RemovalPolicy.DESTROY,
      securityGroups: securityGroupsForOpenSearch,
      tlsSecurityPolicy: opensearch.TLSSecurityPolicy.TLS_1_2,
      useUnsignedBasicAuth: false,
      vpc: vpc,
      vpcSubnets: [
        {
          subnets: subnets
        }
      ],
      // zoneAwareness: {
      //   availabilityZoneCount: 1,
      //   enabled: true
      // }
    });

    // Master user group
    const cfnUserPoolGroup = new cognito.CfnUserPoolGroup(this, 'cognito-master-users-group', {
      userPoolId: cognitoAuth.props.userPoolId,
      description: 'OpenSearch master users group',
      groupName: 'master',
      precedence: 1,
      roleArn: masterUserRole.roleArn
    });

    // -----------------------------
    // Kinesis Data Stream
    // -----------------------------
    const stream = new kinesis.Stream(this, 'kinesis-stream', {
      retentionPeriod: Duration.days(1),
      // shardCount: 1,
      streamMode: kinesis.StreamMode.ON_DEMAND,
      streamName: projectName
    });

    // -----------------------------
    // Role for Firehose
    // -----------------------------
    const logGroupName = `/aws/kinesisfirehose/${projectName}`;
    const firehoseBucket = s3.Bucket.fromBucketName(this, 'firehose-s3-bucket', bucketNameForFirehose);
    const deliveryStreamPolicy = new iam.PolicyDocument({
      statements:[
        // For EC2 (VPC)
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'ec2:DescribeVpcs',
            'ec2:DescribeVpcAttribute',
            'ec2:DescribeSubnets',
            'ec2:DescribeSecurityGroups',
            'ec2:DescribeNetworkInterfaces',
            'ec2:CreateNetworkInterface',
            'ec2:CreateNetworkInterfacePermission',
            'ec2:DeleteNetworkInterface'
          ],
          resources: [
            '*'
          ]
        }),
        // For S3
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            's3:AbortMultipartUpload',
            's3:GetBucketLocation',
            's3:GetObject',
            's3:ListBucket',
            's3:ListBucketMultipartUploads',
            's3:PutObject'
          ],
          resources: [
            firehoseBucket.bucketArn,
            `${firehoseBucket.bucketArn}/*`
          ]
        }),
        // For Lambda
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'lambda:InvokeFunction',
            'lambda:GetFunctionConfiguration'
          ],
          resources: [
            props.transformLambda.functionArn,
          ]
        }),
        // For OpenSearch
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'es:DescribeElasticsearchDomain',
            'es:DescribeElasticsearchDomains',
            'es:DescribeElasticsearchDomainConfig',
            'es:ESHttpPost',
            'es:ESHttpPut'
          ],
          resources: [
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}`,
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}/*`
          ]
        }),
        // For OpenSearch (Specified GET)
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'es:ESHttpGet'
          ],
          resources: [
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}/_all/_settings`,
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}/_cluster/stats`,
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}/cloudwatch-event*/_mapping/`,
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}/_nodes`,
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}/_nodes/stats`,
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}/_nodes/*/stats`,
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}/_stats`,
            `arn:aws:es:${region}:${accountId}:domain/${openSearchDomain.domainName}/cloudwatch-event*/_stats`
          ]
        }),
        // For CloudWatch Logs
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'logs:PutLogEvents'
          ],
          resources: [
            `arn:aws:logs:${region}:${accountId}:log-group:${logGroupName}:log-stream:*`
          ]
        }),
        // For Kinesis Data Stream
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'kinesis:DescribeStream',
            'kinesis:GetShardIterator',
            'kinesis:GetRecords',
            'kinesis:ListShards'
          ],
          resources: [
            `arn:aws:kinesis:${region}:${accountId}:stream/${stream.streamName}`
          ]
        }),
      ]
    });
    const deliveryStreamRole = new iam.Role(this, 'firehose-role', {
      roleName: `${projectName}-firehose-role`,
      assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com'),
      description: `Firehose delivery stream role for ${projectName}`,
      inlinePolicies: {
        'policy': deliveryStreamPolicy
      }
    });

    // -----------------------------
    // Kinesis Firehose
    // -----------------------------
    const cfnDeliveryStream = new firehose.CfnDeliveryStream(this, 'kinesis-data-firehose', {
      amazonopensearchserviceDestinationConfiguration: {
        indexName: openSearchIndexName,
        roleArn: deliveryStreamRole.roleArn,
        s3BackupMode: 'AllDocuments',
        s3Configuration: {
          bucketArn: s3.Bucket.fromBucketName(this, 'bucket-for-firehose', bucketNameForFirehose).bucketArn,
          roleArn: deliveryStreamRole.roleArn,
          bufferingHints: {
            intervalInSeconds: 60,
            sizeInMBs: 1
          },
          cloudWatchLoggingOptions: {
            enabled: false,
            logGroupName: logGroupName,
            logStreamName: 's3'
          },
          compressionFormat: 'ZIP',
          errorOutputPrefix: `firehose/${projectName}/error/`,
          prefix: `firehose/${projectName}/`
        },
        bufferingHints: {
          intervalInSeconds: 60,
          sizeInMBs: 1
        },
        cloudWatchLoggingOptions: {
          enabled: false,
          logGroupName: logGroupName,
          logStreamName: 'log'
        },
        domainArn: openSearchDomain.domainArn,
        indexRotationPeriod: 'OneDay',
        processingConfiguration: {
          enabled: true,
          processors: [
            {
              type: 'Lambda',
              parameters: [
                {
                  parameterName: 'LambdaArn',
                  parameterValue: props.transformLambda.functionArn,
                }
              ],
            }
          ]
        },
        retryOptions: {
          durationInSeconds: 120
        },
        vpcConfiguration : {
          roleArn: deliveryStreamRole.roleArn,
          securityGroupIds: securityGroupIdsForFirehose,
          subnetIds: getSubnetIds(subnetInfos)
        }
      },
      deliveryStreamName: `${projectName}`,
      deliveryStreamType: 'KinesisStreamAsSource',
      kinesisStreamSourceConfiguration: {
        kinesisStreamArn: stream.streamArn,
        roleArn: deliveryStreamRole.roleArn
      }
    });

    // -----------------------------
    // Custom Resource
    // -----------------------------
    new UpdateCognitoAndOpenSearchCustomResource(this, 'update-cognito-and-opensearch-custom-resource', {
      projectName: projectName,
      vpc: vpc,
      subnets: subnets,
      securityGroups: securityGroupsForFirehose,
      lambdaRole: customResourceLambdaRole,
      cognitoIdentityPoolId: cognitoAuth.props.identityPoolId,
      cognitoIdentityPoolAuthRole: cognitoAuth.props.identityPoolAuthRole,
      cognitoIdentityPoolUnauthRole: cognitoAuth.props.identityPoolUnauthRole,
      openSearchDomainEndpoint: openSearchDomain.domainEndpoint,
      openSearchIndexName: openSearchIndexName,
      openSearchMasterUserRole: masterUserRole,
      firehoseRole: deliveryStreamRole
    });

    // -----------------------------
    // Output
    // -----------------------------
    new CfnOutput(this, 'OpeSearch-Endpoint', {
        value: `https://${openSearchDomain.domainEndpoint}/_dashboards/app/home`
    });
  }
}

function getSecurityGroups(scope: Construct, id: string, securityGroupIds: string[]): ec2.ISecurityGroup[] {
  let securityGroups: ec2.ISecurityGroup[] = [];
  securityGroupIds.map((sgid, index) => {
    securityGroups.push(ec2.SecurityGroup.fromSecurityGroupId(scope, `${id}-${sgid}-${index}`, sgid));
  });
  return securityGroups;
}

function getSubnetIds(subnetInfos: Subnet[]): string[]{
  let subnetIds: string[] = [];

  for (let i = 0; i < subnetInfos.length; i ++){
    subnetIds.push(subnetInfos[i].subnetId);
  }
  return subnetIds;
}

function getSubnets(scope: Construct, subnetInfos: Subnet[]): ec2.ISubnet[] {
  let subnets: ec2.ISubnet[] = [];

  for (let i = 0; i < subnetInfos.length; i ++){
    subnets.push(ec2.Subnet.fromSubnetAttributes(scope, `opensearch-subnet-${i}`, {
      subnetId: subnetInfos[i].subnetId,
      availabilityZone: subnetInfos[i].availabilityZone
    }));
  }
  return subnets;
}