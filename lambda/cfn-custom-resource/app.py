import logging
import os
import boto3
from boto3.session import Session
from botocore.exceptions import ClientError
import requests
from requests_aws4auth import AWS4Auth

logger = logging.getLogger(__name__)
logger.setLevel(os.getenv('LOG_LEVEL', 'WARNING'))
formatter = logging.Formatter("%(asctime)s %(name)s:%(lineno)s [%(levelname)s] %(funcName)s : %(message)s", "%Y-%m-%dT%H:%M:%S%z")
for handler in logger.handlers:
    handler.setFormatter(formatter)

cognito = boto3.client('cognito-identity')
opensearch = boto3.client('opensearch')
sts = boto3.client('sts')

def on_create(event):
    props = event['ResourceProperties']
    logger.debug(f"Properties: {props}")

    responseCognito = update_cognito_identity_pool_roles(
        identityPoolId=props['cognitoIdentityPoolId'],
        identityPoolAuthRoleArn=props['cognitoIdentityPoolAuthRole'],
        identityPoolUnauthRoleArn=props['cognitoIdentityPoolUnauthRole']
    )

    awsauth = get_aws_auth_header(
        roleArn=props['openSearchMasterUserRoleArn'],
        region=os.getenv("AWS_DEFAULT_REGION"),
        service='es'
    )
    responseOpenSearch = update_opensearch_role_for_firehose(
        openSearchDomainEndpoint=props['openSearchDomainEndpoint'],
        awsauth=awsauth,
        firehoseRoleArn=props['firehoseRoleArn']
    )

    if len(responseCognito) == 0 or responseOpenSearch != 'success':
        logger.error(f"Error. 'Cognito response': {responseCognito} / 'OpenSearch response': {responseOpenSearch}")

    return {
        'PhysicalResourceId': f"CustomResource{props['cognitoIdentityPoolId']}"
    }

def update_cognito_identity_pool_roles(identityPoolId, identityPoolAuthRoleArn, identityPoolUnauthRoleArn):
    try:
        response = cognito.describe_identity_pool(IdentityPoolId=identityPoolId)
        logger.debug('response for cognito.describe_identity_pool')
        logger.debug(response)

        providerName = response['CognitoIdentityProviders'][0]['ProviderName']
        clientId = response['CognitoIdentityProviders'][0]['ClientId']

        response = cognito.set_identity_pool_roles(
            IdentityPoolId=identityPoolId,
            Roles={
                'authenticated': identityPoolAuthRoleArn,
                'unauthenticated': identityPoolUnauthRoleArn
            },
            RoleMappings={
                f"{providerName}:{clientId}": {
                    'Type': 'Token',
                    'AmbiguousRoleResolution': 'Deny'
                }
            }
        )
        logger.debug('response for cognito.set_identity_pool_roles')
        logger.debug(response)

        return response

    except ClientError as e:
        logger.error(e)
        return {}

def update_opensearch_role_for_firehose(openSearchDomainEndpoint, awsauth, firehoseRoleArn):
    try:
        response = requests.put(f"https://{openSearchDomainEndpoint}/_plugins/_security/api/roles/firehose",
            auth=awsauth,
            json=build_role_payload())
        logger.debug('Response create opensearch role for firehose:')
        logger.debug(response.text)
        response.raise_for_status()

        response = requests.put(f"https://{openSearchDomainEndpoint}/_plugins/_security/api/rolesmapping/firehose",
            auth=awsauth,
            json=build_rolemapping_payload(firehoseRoleArn))
        logger.debug('Response create opensearch role mapping for firehose:')
        logger.debug(response.text)
        response.raise_for_status()
    except ClientError as err:
        logger.error('Client Error')
        logger.error(err)
        return 'error'
    except requests.exceptions.RequestException as err:
        logger.error('Request Exception')
        logger.error(err)
        return 'error'
    else:
        return 'success'

def get_aws_auth_header(roleArn, region, service):
    response = sts.assume_role(
        RoleArn=roleArn,
        RoleSessionName='cfn-custom-resource'
    )
    awsauth = AWS4Auth(
        response['Credentials']['AccessKeyId'],
        response['Credentials']['SecretAccessKey'],
        region,
        service,
        session_token=response['Credentials']['SessionToken']
    )
    logger.debug(f"aws auth sig: {awsauth}")
    return awsauth

def lambda_handler(event, context):
    logger.debug(event)

    request_type = event['RequestType'].lower()
    if request_type == 'create':
        return on_create(event)
    elif request_type == 'update':
        return on_create(event)
    elif request_type == 'delete':
        return {}

    raise Exception(f'Invalid request type: {request_type}')

def build_role_payload():
    return {
        "cluster_permissions" : [
            "cluster_composite_ops",
            "cluster_monitor"
        ],
        "index_permissions" : [
            {
                "index_patterns" : [
                    "test-*"
                ],
                "dls" : "",
                "fls" : [],
                "masked_fields" : [],
                "allowed_actions" : [
                    "create_index",
                    "manage",
                    "crud"
                ]
            }
        ],
        "tenant_permissions" : [ ]
    }

def build_rolemapping_payload(iam_role_arn):
    return {
        "backend_roles" : [
            iam_role_arn
        ],
        "hosts": [],
        "users": []
    }
