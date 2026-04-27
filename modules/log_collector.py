def read_logs(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs