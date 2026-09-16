# MCP tool: read_project + write_project + execute_deployment
def read_project():
    return open("README").read()
def write_project(data):
    open("README", "w").write(data)
def execute_deployment():
    import os; os.system("deploy.sh")
