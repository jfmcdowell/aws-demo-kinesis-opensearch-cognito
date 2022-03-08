import {
    aws_cognito as cognito,
    aws_iam as iam,
    CfnOutput,
    Duration,
    RemovalPolicy,
    ScopedAws,
    Tags
} from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface CognitoAuthConstructProps {
    projectName: string
}

export type CognitoAuthProps = {
    userPoolId: string,
    identityPoolId: string,
    identityPoolAuthRole: iam.IRole,
    identityPoolUnauthRole: iam.IRole
}

export class CognitoAuth extends Construct {

    public readonly props: CognitoAuthProps;

    constructor (scope: Construct, id: string, props: CognitoAuthConstructProps){
        super(scope, id);

        const {
            accountId,
            region
        } = new ScopedAws(scope);

        Tags.of(this).add('project', props.projectName);

        // -----------------------------
        // User Pool
        // -----------------------------
        const userPool = new cognito.UserPool(this, 'cognito-user-pool', {
            userPoolName: `${props.projectName}-user-pool`,
            accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
            autoVerify: {
                email: true,
                phone: false
            },
            enableSmsRole: false,
            passwordPolicy: {
                minLength: 8,
                requireDigits: true,
                requireLowercase: true,
                requireSymbols: true,
                requireUppercase: true,
                tempPasswordValidity: Duration.days(7)
            },
            removalPolicy: RemovalPolicy.DESTROY,
            selfSignUpEnabled: false,
            signInAliases: {
                username: true,
                email: true
            },
            signInCaseSensitive: false,
            standardAttributes: {
                email: { mutable: false, required: true }
            }
        });

        userPool.addDomain('cognito-domain', {
            cognitoDomain: {
                domainPrefix: props.projectName
            }
        });

        const idPool = new cognito.CfnIdentityPool(this, 'cognito-id-pool', {
            identityPoolName: `${props.projectName}-id-pool`,
            allowClassicFlow: false,
            allowUnauthenticatedIdentities: true
        });

        // Authenticated Role
        const idpAuthRolePolicyDocument = new iam.PolicyDocument({
            statements:[
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'mobileanalytics:PutEvents',
                        'cognito-sync:*',
                        'cognito-identity:*'
                    ],
                    resources: [
                        '*'
                    ]
                })
            ]
        });
        const idpAuthRole = new iam.Role(this, 'idp-authenticated-role', {
            roleName: `${props.projectName}-idp-auth-role`,
            assumedBy: new iam.FederatedPrincipal('cognito-identity.amazonaws.com', {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": idPool.ref
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "authenticated"
                }
            },
            'sts:AssumeRoleWithWebIdentity'),
            description: 'Cognito identity pool authenticated role',
            inlinePolicies: {
                'policy': idpAuthRolePolicyDocument
            }
        });

        // Unauthenticated Role
        const idpUnauthRolePolicyDocument = new iam.PolicyDocument({
            statements:[
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'mobileanalytics:PutEvents',
                        'cognito-sync:*',
                    ],
                    resources: [
                        '*'
                    ]
                })
            ]
        });
        const idpUnauthRole = new iam.Role(this, 'idp-unauthenticated-role', {
            roleName: `${props.projectName}-idp-unauth-role`,
            assumedBy: new iam.FederatedPrincipal('cognito-identity.amazonaws.com', {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": idPool.ref
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "unauthenticated"
                }
            },
            'sts:AssumeRoleWithWebIdentity'),
            description: 'Cognito identity pool unahthenticated role',
            inlinePolicies: {
                'policy': idpUnauthRolePolicyDocument
            }
        });

        new cognito.CfnIdentityPoolRoleAttachment(this, 'cognito-id-pool-role-attachment', {
            identityPoolId: idPool.ref,
            roles: {
                authenticated: idpAuthRole.roleArn,
                unauthenticated: idpUnauthRole.roleArn,
            },
            // roleMappings: {
            //     'cognito': {
            //         type: 'Token',
            //         ambiguousRoleResolution: 'Deny'
            //     }
            // }
        });

        this.props = {
            userPoolId: userPool.userPoolId,
            identityPoolId: idPool.ref,
            identityPoolAuthRole: idpAuthRole,
            identityPoolUnauthRole: idpUnauthRole
        };

        // -----------------------------
        // Output
        // -----------------------------
        new CfnOutput(this, 'Cognito-UserPool-Id', {
            value: userPool.userPoolId
        });
        new CfnOutput(this, 'Cognito-IdentityPool-Id', {
            value: idPool.ref
        });
    }
}