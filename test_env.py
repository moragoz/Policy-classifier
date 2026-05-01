import os
with open('.env') as f:
    for line in f:
        if '=' in line:
            key, value = line.strip().split('=', 1)
            os.environ[key] = value
            print('Set', key)
print('KEY exists:', os.getenv('OPENAI_API_KEY') is not None)