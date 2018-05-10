#!/usr/bin/env python3

# See also
# https://stackoverflow.com/questions/39272744/when-to-use-a-boto3-client-and-when-to-use-a-boto3-resource
# https://stackoverflow.com/questions/1661275/disable-boto-logging-without-modifying-the-boto-files
# 

from pprint import pprint as pp

import sys
import logging

logger = logging.getLogger()
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)
logging.getLogger('botocore').setLevel(logging.WARN)
logging.getLogger('boto3').setLevel(logging.WARN)

import boto3
import boto3.session

import botocore.config

#AWS_PROFILE="dev"
#boto3.setup_default_session(profile_name=AWS_PROFILE)

config = {
    "cloudformation":           True,
    "apigateway":               True,
    "iot":                      True,
    "elasticbeanstalk":         True,
    "lambda":                   True,
    "ec2":                      True,
        "ec2-elb":              True,
        "ec2-autoscaling":      True,
        "ec2-instance":         True,
        "ec2-volumes":          True,
        "ec2-security-group":   True,
        "ec2-eip":              True,
        "ec2-images":           True,
        "ec2-keypairs":         True,
        "ec2-snapshots":        True,
    "s3":                       True,
    "dynamodb":                 True,
    "rds":                      True,
    "iam":                      True,
        "iam-group":            True,
        "iam-user":             True,
        "iam-role":             True,
        "iam-policy":           True,
}

ASKED_FOR_DELETION = True
# https://stackoverflow.com/questions/33332050/getting-the-current-user-account-id-in-boto3
account_id = boto3.client('sts').get_caller_identity().get('Account')

def ask_for_delete():

    if not ASKED_FOR_DELETION:
        return True

    logger.info("      Please confirm with 'yes'")
    choice = input().lower()

    if choice == "yes":
        logger.info("        ... Done")
        return True

    return False

# Get regions for service
def get_region(service_name):
    """
    https://stackoverflow.com/questions/38451032/how-to-list-available-regions-with-boto3-python
    """
    return boto3.session.Session().get_available_regions(service_name)

##
# CloudFormation

if config["cloudformation"]:

    for region in get_region("cloudformation"):

        logger.info("# CloudFormation\tregion: {}".format(region))
        client = boto3.client("cloudformation", region_name=region)  
        
        for stack in client.list_stacks(
                StackStatusFilter=[
                    'CREATE_IN_PROGRESS',
                    'CREATE_FAILED',
                    'CREATE_COMPLETE',
                    'ROLLBACK_IN_PROGRESS',
                    'ROLLBACK_FAILED',
                    'ROLLBACK_COMPLETE',
                    'DELETE_FAILED',
                    'UPDATE_IN_PROGRESS',
                    'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
                    'UPDATE_COMPLETE',
                    'UPDATE_ROLLBACK_IN_PROGRESS',
                    'UPDATE_ROLLBACK_FAILED',
                    'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
                    'UPDATE_ROLLBACK_COMPLETE',
                    'REVIEW_IN_PROGRESS',
                ]
            )["StackSummaries"]:

            stack_name = stack["StackName"]
            logger.info(" + Delete: {}".format(stack_name))

            if ask_for_delete():
                client.delete_stack(StackName=stack_name)

##
# API Gateway

if config["apigateway"]:

    for region in get_region("apigateway"):

        logger.info("# API Gateway\tregion: {}".format(region))
        client = boto3.client("apigateway", region_name=region)  
        
        is_first_api = True

        for api in client.get_rest_apis()["items"]:

            logger.info(" + Delete: {}".format(api["name"]))

            if ask_for_delete():

                if is_first_api:
                    is_first_api = False
                else:
                    time.sleep(50)

                client.delete_rest_api(
                    restApiId=api["id"]
                )

##
# IoT

if config["iot"]:

    for region in get_region("iot"):

        logger.info("# IoT - Things\tregion: {}".format(region))
        client = boto3.client("iot", region_name=region)

        for thing in client.list_things()["things"]:

            thing_name = thing["thingName"]
            logger.info(" + Delete: {}".format(thing_name))

            if ask_for_delete():
                client.delete_thing(thingName=thing_name)

##
# ElasticBeanstalk

if config["elasticbeanstalk"]:

    for region in get_region("elasticbeanstalk"):

        logger.info("# ElasticBeanstalk\tregion: {}".format(region))
        client = boto3.client("elasticbeanstalk", region_name=region)

        for app in client.describe_applications()["Applications"]:

            app_name = app["ApplicationName"]
            logger.info(" + Delete: {}".format(app_name))

            if ask_for_delete():

                client.delete_application(
                    ApplicationName=app_name,
                    TerminateEnvByForce=True
                )

##
# Lambda

if config["lambda"]:

    for region in get_region("lambda"):

        logger.info("# Lambda\tregion: {}".format(region))
        client = boto3.client("lambda", region_name=region)  
        
        for function in client.list_functions()["Functions"]:

            function_name = function["FunctionName"]
            logger.info(" + Delete: {}".format(function_name))

            if ask_for_delete():
                client.delete_function(
                    FunctionName=function_name
                )

##
# EC2

if config["ec2"]:

    if config["ec2-elb"]:

        for region in get_region("elb"):

            logger.info("# EC2 - ElasticLoadBalancing\tregion: {}".format(region))
            client = boto3.client("elbv2", region_name=region)  

            for lb in client.describe_load_balancers()["LoadBalancers"]:

                lb_name = lb["LoadBalancerName"]
                logger.info(" + Delete: {}".format(lb_name))

                if ask_for_delete():
                    client.delete_load_balancer(
                        LoadBalancerArn=lb["LoadBalancerArn"]
                    )

    if config["ec2-autoscaling"]:

        for region in get_region("autoscaling"):

            logger.info("# EC2 - AutoScaling \tregion: {}".format(region))
            client = boto3.client("autoscaling", region_name=region)  

            for group in client.describe_auto_scaling_groups()["AutoScalingGroups"]:

                group_name = group["AutoScalingGroupName"]
                logger.info(" + Delete (group): {}".format(group_name))

                if ask_for_delete():
                    client.delete_auto_scaling_group(
                        AutoScalingGroupName=group_name,
                        ForceDelete=True
                    )

            for config in client.describe_launch_configurations()["LaunchConfigurations"]:

                config_name = config["LaunchConfigurationName"]
                logger.info(" + Delete (launch conf): {}".format(config_name))

                if ask_for_delete():
                    client.delete_launch_configuration(
                        LaunchConfigurationName=config_name
                    )

    if config["ec2-instance"]:
        
        for region in get_region("ec2"):

            logger.info("# EC2 - Instance\tregion: {}".format(region))
            client = boto3.resource("ec2", region_name=region)
            instances = client.instances.filter(
                Filters=[
                    {
                        'Name': 'instance-state-name',
                        'Values': [
                                'pending',
                                'running',
                                'shutting-down',
                                'stopping',
                                'stopped',
                            ]
                    }
                ]
            )

            for instance in instances:
                logger.info(" + Delete: {}".format(instance.id))

                if ask_for_delete():
                    instance.terminate()

    if config["ec2-volumes"]:

        for region in get_region("ec2"):

            logger.info("# EC2 - Volumes\tregion: {}".format(region))
            client = boto3.resource("ec2", region_name=region)
            
            # http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.ServiceResource.volumes
            for volume in client.volumes.filter(Filters=[{'Name': 'status', 'Values': [
                'creating',
                'available',
                #'in-use'
                'error',
            ]}]):

                logger.info(" + Delete: {}".format(volume.id))

                if ask_for_delete():
                    volume.delete()

    if config["ec2-security-group"]:

        for region in get_region("ec2"):

            logger.info("# EC2 - Security Group\tregion: {}".format(region))
            client = boto3.resource("ec2", region_name=region)

            for security_groups in client.security_groups.all():

                logger.info(" + Delete: {} | {}".format(security_groups.group_name, security_groups.id))

                if ask_for_delete():
                    security_groups.delete()

    if config["ec2-eip"]:

        for region in get_region("ec2"):

            logger.info("# EC2 - Elastic IPs\tregion: {}".format(region))
            client = boto3.client("ec2", region_name=region)

            for ip in client.describe_addresses()["Addresses"]:

                logger.info(" + Delete: {} [{}]".format(
                    ip["PublicIp"],
                    ip["AllocationId"],
                ))

                if ask_for_delete():
                    client.release_address(
                        AllocationId=ip["AllocationId"],
                        PublicIp=ip["PublicIp"],
                        DryRun=False
                    )

    if config["ec2-images"]:

        for region in get_region("ec2"):

            logger.info("# EC2 - Images\tregion: {}".format(region))
            client = boto3.resource("ec2", region_name=region)
            
            for image in client.images.filter(Owners=['self']): # .all():

                logger.info(" + Delete: {}\t\tHint: Has delay!".format(image.id))

                if ask_for_delete():
                    # http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Image.deregister
                    image.deregister(DryRun=False)

    if config["ec2-keypairs"]:

        for region in get_region("ec2"):

            logger.info("# EC2 - Keypairs\tregion: {}".format(region))
            client = boto3.client("ec2", region_name=region)  
            
            for keypair in client.describe_key_pairs()["KeyPairs"]:

                keypair_name = keypair["KeyName"]
                logger.info(" + Delete: {}".format(keypair_name))

                if ask_for_delete():
                    client.delete_key_pair(KeyName=keypair_name)

    if config["ec2-snapshots"]:

        for region in get_region("ec2"):

            logger.info("# EC2 - Snapshots\tregion: {}".format(region))
            client = boto3.resource("ec2", region_name=region)

            for snapshot in client.snapshots.filter(OwnerIds=[account_id]):

                logger.info(" + Delete: {}".format(snapshot.id))

                if ask_for_delete():
                    snapshot.delete()

##
# S3

if config["s3"]:

    logger.info("# S3")
    s3 = boto3.resource('s3')

    for bucket in s3.buckets.all():

        logger.info(" + Delete: {}".format(bucket.name))

        if ask_for_delete():
            for key in bucket.objects.all():
                key.delete()

            bucket.delete()

##
# DynamoDB

if config["dynamodb"]:

    # http://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html
    for region in get_region("dynamodb"):

        logger.info("# DynamoDB \tregion: {}".format(region))
        client = boto3.client("dynamodb", region_name=region)

        for table in client.list_tables()["TableNames"]:

            logger.info(" + Delete (table): {}".format(table))

            if ask_for_delete():
                client.delete_table(
                    TableName=table
                )
        
        # BUG: https://github.com/boto/boto3/issues/1542
        if region == "eu-west-3":
            continue 

        for backup in client.list_backups()["BackupSummaries"]:

            logger.info(" + Delete (backup): {} [{}]".format(
                backup["TableName"],
                backup["BackupCreationDateTime"],
            ))

            if ask_for_delete():
                client.delete_backup(
                    BackupArn=backup["BackupArn"]
                )

##
# RDS

if config["rds"]:

    # http://boto3.readthedocs.io/en/latest/reference/services/rds.html
    for region in get_region("rds"):

        logger.info("# RDS \tregion: {}".format(region))
        client = boto3.client("rds", region_name=region)

        for instance in client.describe_db_instances()["DBInstances"]:

            logger.info(" + Delete (instance): {} [{}]".format(
                instance["DBInstanceIdentifier"],
                instance["Engine"],
            ))

            if ask_for_delete():
                client.delete_db_instance(
                    DBInstanceIdentifier=instance["DBInstanceIdentifier"],
                    SkipFinalSnapshot=True,
                )

        for snap in client.describe_db_snapshots()["DBSnapshots"]:

            # Can not delete automated snapshots
            if snap["SnapshotType"] == "automated":
                continue

            logger.info(" + Delete (instance - snapshots): {} [{} | {} | {}]".format(
                snap["DBSnapshotIdentifier"],
                snap["SnapshotCreateTime"],
                snap["Engine"],
                snap["SnapshotType"],
            ))

            if ask_for_delete():
                client.delete_db_snapshot(
                    DBSnapshotIdentifier=snap["DBSnapshotIdentifier"],
                )

        for cluster in client.describe_db_clusters()["DBClusters"]:

            logger.info(" + Delete (cluster): {}".format(
                cluster["DBClusterIdentifier"]
            ))

            if ask_for_delete():
                client.delete_db_cluster(
                    DBClusterIdentifier=cluster["DBClusterIdentifier"],
                    SkipFinalSnapshot=True,
                )

        for snap in client.describe_db_cluster_snapshots()["DBClusterSnapshots"]:

            logger.info(" + Delete (cluster - snapshots): {} [{}]".format(
                snap["DBClusterSnapshotIdentifier"],
                snap["SnapshotCreateTime"],
            ))

            if ask_for_delete():
                client.delete_db_cluster_snapshot(
                    DBClusterSnapshotIdentifier=snap["DBClusterSnapshotIdentifier"],
                )


##
# IAM

if config["iam"]:

    if config["iam-group"]:
    
        logger.info("# IAM - Group")
        resource = boto3.resource('iam')
        client = boto3.client('iam')

        for group in resource.groups.all():

            logger.info(" + Delete: {}".format(group.name))

            if ask_for_delete():

                for user in client.get_group(GroupName=group.name)["Users"]:

                    client.remove_user_from_group(
                        GroupName=group.name,
                        UserName=user["UserName"]
                    )

                for policy in client.list_attached_group_policies(GroupName=group.name)["AttachedPolicies"]:
            
                    client.detach_group_policy(
                        GroupName=group.name,
                        PolicyArn=policy["PolicyArn"]
                    )

                group.delete()

    if config["iam-user"]:

        # https://gist.github.com/xxxVxxx/9648264fd6f41bbb1f65

        logger.info("# IAM - User")
        resource = boto3.resource('iam')

        for user in resource.users.all():

            logger.info(" + Delete: {}".format(user.user_name))

            if ask_for_delete():

                for key in user.access_keys.all():
                    key.delete()

                user.delete()

    if config["iam-role"]:

        logger.info("# IAM - Role")
        resource = boto3.resource('iam')
        client = boto3.client('iam')

        for role in resource.roles.all():

            logger.info(" + Delete: {}".format(role.name))

            if ask_for_delete():

                for policy in client.list_attached_role_policies(RoleName=role.name)["AttachedPolicies"]:

                    client.detach_role_policy(
                        RoleName=role.name,
                        PolicyArn=policy["PolicyArn"]
                    )

                role.delete()

    if config["iam-policy"]:

        logger.info("# IAM - Policy")
        resource = boto3.resource('iam')
        client = boto3.client('iam')

        for policy in resource.policies.filter(Scope="Local"):

            logger.info(" + Delete: {}".format(policy.policy_name))

            if ask_for_delete():

                for version in client.list_policy_versions(PolicyArn=policy.arn)["Versions"]:
                    
                    if not version["IsDefaultVersion"] == True:
  
                        client.delete_policy_version(
                            PolicyArn=policy.arn,
                            VersionId=version["VersionId"]
                        )

                policy.delete()
