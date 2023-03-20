"""
For NCSA Delta Cluster: CPU
"""
import socket
from parsl.launchers import SrunLauncher
from parsl.providers import SlurmProvider

from funcx_endpoint.endpoint.utils.config import Config
from funcx_endpoint.executors import HighThroughputExecutor

# fmt: off
hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)

# PLEASE UPDATE user_opts BEFORE USE
user_opts = {
    'delta': {
        'worker_init': 'module load anaconda3_cpu; conda init bash; source ~/.bashrc; conda activate funcx',
        'scheduler_options': '#SBATCH --mail-user=xxx@illinois.edu\n#SBATCH --mail-type=ALL\n#SBATCH --constraint=projects',
    }
}

config = Config(
    executors=[
        HighThroughputExecutor(
            max_workers_per_node=2,
            worker_debug=True,
            address=ip_address,
            provider=SlurmProvider(
                account='bbke-delta-cpu',
                partition='cpu',
                launcher=SrunLauncher(),
                # string to prepend to #SBATCH blocks in the submit
                # script to the scheduler eg: '#SBATCH --constraint=knl,quad,cache'
                scheduler_options=user_opts['delta']['scheduler_options'],

                # Command to be run before starting a worker, such as:
                # 'module load Anaconda; source activate parsl_env'.
                worker_init=user_opts['delta']['worker_init'],

                # Scale between 0-1 blocks with 2 nodes per block
                nodes_per_block=2,
                init_blocks=1,
                min_blocks=1,
                max_blocks=1,

                # Hold blocks for 30 minutes
                walltime='00:30:00'
            ),
        )
    ],
)

# For now, visible_to must be a list of URNs for globus auth users or groups, e.g.:
# urn:globus:auth:identity:{user_uuid}
# urn:globus:groups:id:{group_uuid}
meta = {
    "name": '<ENDPOINT_NAME>',
    "description": "",
    "organization": "",
    "department": "",
    "public": False,
    "visible_to": [],
}