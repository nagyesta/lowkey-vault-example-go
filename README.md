![LowkeyVault](https://raw.githubusercontent.com/nagyesta/lowkey-vault/main/.github/assets/LowkeyVault-logo-full.png)

[![GitHub license](https://img.shields.io/github/license/nagyesta/lowkey-vault-example-go?color=informational)](https://raw.githubusercontent.com/nagyesta/lowkey-vault-example-go/main/LICENSE)
[![Go package](https://img.shields.io/github/workflow/status/nagyesta/lowkey-vault-example-go/Go%20package?logo=github)](https://github.com/nagyesta/lowkey-vault-example-go/actions/workflows/go.yml)
[![Lowkey secure](https://img.shields.io/badge/lowkey-secure-0066CC)](https://github.com/nagyesta/lowkey-vault)

# Lowkey Vault - Example Go

This is an example for [Lowkey Vault](https://github.com/nagyesta/lowkey-vault). It demonstrates a basic scenario where
a key is used for encrypt/decrypt operations and database connection specific credentials.

### Points of interest

* [Client](src/lowkey-vault-example.go)
* [Tests](src/lowkey-vault-example_test.go)

### Usage

1. Start Lowkey Vault 
   1. Either by following the steps [here](https://github.com/nagyesta/lowkey-vault#quick-start-guide).
      1. Make sure to use port ```8443```
   2. Or running ```docker-compose up -d```
2. Run the tests

### Note

This is my very first Go project after using it for 2-3 hours, please have mercy when
commenting on code quality!
