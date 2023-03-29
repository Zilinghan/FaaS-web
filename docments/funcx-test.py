from funcx import FuncXExecutor

def double(x):
    return x * 2

endpoint_id = '6c87988d-d067-43c9-a73f-063b51e1b33a' #YOUR-ENDPOINT-ID
with FuncXExecutor(endpoint_id=endpoint_id) as fxe:
    fut = fxe.submit(double, 7)
    print(fut.result())