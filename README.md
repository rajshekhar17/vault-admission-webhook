# Kubernetes mutatingwebhook to inject secrets in manifests
The project is intended to support the injection of the vault secrets to the specified resources(as defined in the MutatingWebhookConfiguration). Although this not the best way to handle the secrets but at times during the deployment of the infrastructure componemts and Custom Resources this can come real handy.

### In order to inject secret to the resource specify the following annotations
```yaml
annotations:
  vault-manifest/inject: "true" #to enable the injection on the resource
  vault-manifest-inject-secret/spec.image: secret/data/test/example.nginx_image
```

### The vault-manifest-inject-secret annotation has to be in the following format: 
1. vault-manifest-inject-secret/field_in_manifest>: path_to_secret_in_vault.key
2. field_in_manifest should be seperated by '.'
3. path_to_secret_in_vault should be in format secret/data/path and the key to the secret should be appended by a '.'
4. The project utilizes json patch so field_in_manifest should be defined appropriately to access the arrays and maps

### Following environment variables can be used to configure the deployment
|ENV |Description| Required
|:---|---|---|
TOKEN | If a token to access is to be specified explicitly | False (Will be fetched when kubernetes auth will be used)
ROLE | Role configured against kubernetes auth. In this case deployment will utilize Service Account token to access vault using kubernetes auth method | False (Only with kubernetes auth method)
VAULT_ADDR | Vault server address(https://localhost:8200)| True (either in config or as env var)
VAULT_SKIP_VERIFY | Weather or not to use insecre TLS | False
VAULT_CONFIG_PATH | Configuration can also be specified in YAML format and can be mounted to provide the token etc. | False