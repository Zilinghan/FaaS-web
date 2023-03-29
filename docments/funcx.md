# How to setup funcx endpoint on Delta Cluster @ NCSA

## Installation
0.  ssh to the login node of your cluster and load the anaconda module. For Delta, you can use the following command if you want to use GPU

    ```
    module load anaconda3_gpu
    ```
    or this fow CPU
    ```
    module load anaconda3_cpu
    ```
1. Create a virtual environment using `conda`

    ```
    conda create -n funcx python=3.8
    conda activate funcx
    ```
2. Clone this repository, and install dependencies.

    ```
    git clone https://github.com/Zilinghan/FL-as-a-Service.git FaaS
    cd FaaS
    git checkout funcx
    pip install -r requirements.txt
    pip install -e .
    ```


## FuncX Endpoint Config
3. Setup funcX endpoint. Please add your own `<ENDPOINT_NAME>` such as `delta-cpu-01`. 

    You might be required to login with [Globus](https://app.globus.org), following the prompt instructions and finish the authentication steps.

    ```
    funcx-endpoint configure <ENDPOINT_NAME>
    ```

4. Confiugre the endpoint by editting the file `~/.funcx/<ENDPOINT_NAME>/config.py`. You can refer to these two sample configurations: [[CPU](config-cpu.py)] [[GPU](config-gpu.py)]. Please pay attention to the following points. More information of the configuration for endpoint can be found [here](https://funcx.readthedocs.io/en/latest/endpoints.html).

    (1) Put whatever cmds you want to run before starting a worker into `'worker_init'` part.

    (2) Put whatever cmds you want to run with `#SBATCH` into the `'scheduler_options'` part, e.g., change the `--mail-user` to your email address.
    
    (3) Replace the `<ENDPOINT_NAME>` to your created name.

5. Start the funcX endpoint. The follwoing command will allocate resources you required from the `config.py` file above. [**Note**: Whenever you modify the `config.py`, you need to first run `funcx-endpoint stop <ENDPOINT_NAME>` and then re-start it to have the changes make effect.]

    ```
    funcx-endpoint start <ENDPOINT_NAME>
    ```

6. Get you endpoint id.
    ```
    funcx-endpoint list
    ```

7. Use a simple test to see if your endpoint is running. Run [`funcx-test.py`](funcx-test.py) by first **replacing the endpoint-id with yours**, then see if you can see the results returned from the endpoint.
    ```
    python funcx-test.py
    ```