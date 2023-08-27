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
* Tests
  * [Using FakeCredential](src/lowkey-vault-example_test.go)
  * [Using Managed Identity with DefaultAzureCredential](src/lowkey-vault-example_mi_test.go) (requires Assumed Identity to run)

Note: In order to better understand what is needed in general to make similar examples work, please find a generic overview
[here](https://github.com/nagyesta/lowkey-vault/wiki/Example:-How-can-you-use-Lowkey-Vault-in-your-tests).

### Usage

1. Start [Lowkey Vault](https://github.com/nagyesta/lowkey-vault) and [Assumed Identity](https://github.com/nagyesta/assumed-identity)
   1. Either by following the steps [here](https://github.com/nagyesta/lowkey-vault#quick-start-guide) and [here](https://github.com/nagyesta/assumed-identity#usage).
   2. Or running ```docker-compose up -d```
2. If you are not using the default `169.254.169.254:80` address for Assumed Identity (because for example you are running it in the cloud)
   1. Set ```IDENTITY_ENDPOINT``` environment variable to point to the `/metadata/identity/oauth2/token` path of Assumed Identity e.g., http://localhost:8080/metadata/identity/oauth2/token
   2. Set ```IDENTITY_HEADER``` environment variable to anything (just needs to exist) e.g., `header`
3. Run the tests

### Note

I am not a professional Go developer. Please do not judge me by the code quality. I am open to any suggestions and
improvements.
