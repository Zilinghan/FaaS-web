# Instructions on running one-time/batch task on AWS ECS 
This readme file contains the instructions on how to run one-time/batch task using the AWS Elastic Container Services + Fargate. Running the APPFL server is the example of one-time/batch task.

1. Create an AWS ECS Cluster: choose default VPC and some subnets, and select AWS Fargate as the Infrastructure.

2. Create an ECS task definition: choose the container image for running the desired task from Docker hub, and configure Memory and CPU. (Note: The value of memory and CPU can be overridden when launching task instances on demand.)

3. **Note**: Since we only need to run one-time/batch jobs that do not need to run all the time, there is **no need** to create ECS service.

4. Create an IAM role for accessing ECS: use AmazonECS_FullAccess policy when creating the user. Then generate access key for the user, and note the access key information down.

5. You can now require AWS ECS to launch a container to run a batch job for you using the template in [ecs-test.py](ecs-test.py). Specifically, replace `YOUR_ACCESS_KEY` and `YOUR_SECRETE_ACCESS_KEY` with the information you get after creating the IAM user, `CLUSTER_NAME` with the name of your cluster created in step 1, `TASK_DEF` with the name of the task definition you create in step 2, `YOUR_SUBNETS_IDx` with the subnet IDs you use when creating the cluster in step 1, `CONTAINER_NAME` with you give to your container image. Finally, pass parameters to the container as a list using the `params` variable.

6. You can use AWS CloudWatch service to see the log of the running task.