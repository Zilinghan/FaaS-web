import boto3
ecs_client = boto3.client(
    'ecs',
    aws_access_key_id='YOUR_ACCESS_KEY',
    aws_secret_access_key='YOUR_SECRETE_ACCESS_KEY',
    region_name='YOUR_ECS_REGION'
)

def run_task(params):
    response = ecs_client.run_task(
        cluster='CLUSTER_NAME',
        taskDefinition='TASK_DEF',
        count=1,
        launchType='FARGATE',
        networkConfiguration={
            'awsvpcConfiguration': {
                'subnets': ['YOUR_SUBNETS_ID1','YOUR_SUBNETS_ID2','YOUR_SUBNETS_ID3'],
                'assignPublicIp': 'ENABLED'
            }
        },
        overrides = {
            'containerOverrides': [{
                'name': 'CONTAINER_NAME',
                'command': params,
            }]
        }
    )
    return response['tasks'][0]['taskArn']

print(run_task(['id1,id2', 'id3', 'id4', 'id5']))