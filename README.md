![LowkeyVault](https://raw.githubusercontent.com/nagyesta/lowkey-vault/main/.github/assets/LowkeyVault-logo-full.png)

[![GitHub license](https://img.shields.io/github/license/nagyesta/lowkey-vault-example-go?color=informational)](https://raw.githubusercontent.com/nagyesta/lowkey-vault-example-go/main/LICENSE)
[![Go package](https://img.shields.io/github/actions/workflow/status/nagyesta/lowkey-vault-example-go/go.yml?logo=github&branch=main)](https://github.com/nagyesta/lowkey-vault-example-go/actions/workflows/go.yml)
[![Lowkey secure](https://img.shields.io/badge/lowkey-secure-0066CC)](https://github.com/nagyesta/lowkey-vault)

# Lowkey Vault - Example Go

This is an example for [Lowkey Vault](https://github.com/nagyesta/lowkey-vault). It demonstrates a basic scenario where
a key is used for encrypt/decrypt operations and database connection specific credentials as well as getting a PKCS12 
store with a certificate and matching private key inside.

### Points of interest

* [Client](src/lowkey-vault-example.go)
* [Tests](src/lowkey-vault-example_test.go)

Note: In order to better understand what is needed in general to make similar examples work, please find a generic overview
[here](https://github.com/nagyesta/lowkey-vault/wiki/Example:-How-can-you-use-Lowkey-Vault-in-your-tests).

### Usage

1. Start Lowkey Vault 
   1. Either by following the steps [here](https://github.com/nagyesta/lowkey-vault#quick-start-guide).
      1. Make sure to use port ```8443```
   2. Or running ```docker-compose up -d```
2. Run the tests

### Note

I am not a professional Go developer. Please do not judge me by the code quality. I am open to any suggestions and
improvements.
