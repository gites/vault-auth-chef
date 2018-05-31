import requests
import os.path
import os
import json

key = 'client.pem'
server = 'https://devchef-vx-1.devintermedia.net:8200'
with open(key, 'r') as f:
    key = f.read()
info = {
    'key': key,
    'client': 'devaesc-vx-1.devintermedia.net'
}

# Auth
print("POST", '{}/v1/auth/chef/login/key'.format(server), "data", json.dumps(info))
resp = requests.post('{}/v1/auth/chef/login/key'.format(server), data=json.dumps(info), verify=False)
key = resp.json()
print(key)
print(resp.status_code)

# Get secrets
resp = requests.get('{}/v1/secret/goldfish'.format(server), headers={"X-Vault-Token": key["auth"]["client_token"]}, verify=False)
print(resp.text)
print(resp.status_code)
resp = requests.get('{}/v1/secret/aes/huinya'.format(server), headers={"X-Vault-Token": key["auth"]["client_token"]}, verify=False)
print(resp.text)
print(resp.status_code)
resp = requests.get('{}/v1/aes/vaderetro'.format(server), headers={"X-Vault-Token": key["auth"]["client_token"]}, verify=False)
print(resp.text)
print(resp.status_code)
resp = requests.get('{}/v1/aes/vaderetro/test/qwwqwwq'.format(server), headers={"X-Vault-Token": key["auth"]["client_token"]}, verify=False)
print(resp.text)
print(resp.status_code)
