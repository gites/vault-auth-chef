def vault_secrets(path, name)
  secrets = ::Chef::VaultSecrets.new
  secrets.get_secret(path, name)
end
