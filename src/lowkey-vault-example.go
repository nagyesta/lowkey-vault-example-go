package src

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"software.sslmate.com/src/go-pkcs12"
)

// Secret - Simulated production code that can fetch the value of a given secret using the provided secret client.
//
// client - The Azure secret client instance we need to use for fetching the secret value.
//
// name - The name of the secret as stored in Azure Key Vault.
func Secret(client *azsecrets.Client, name string) (string, error) {
	resp, err := client.GetSecret(context.TODO(), name, "", nil)
	if err != nil {
		return "", errors.New("failed to get the secret: " + err.Error())
	}

	return *resp.Value, err
}

// Encrypt - Simulates a production ready method performing encryption using the provided client on the parameters.
//
// client - The Azure key client used for encryption.
//
// name - The name of the key as it is stored in Azure Key Vault.
//
// message - The clear text message we want to encrypt.
func Encrypt(client *azkeys.Client, name string, message string) ([]byte, error) {
	version, _ := GetLatestVersionOfKey(client, name)
	parameters := azkeys.KeyOperationParameters{
		Value:     []byte(message),
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256)}
	resp, err := client.Encrypt(context.TODO(), name, version, parameters, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt using key: " + err.Error())
	}
	return resp.Result, nil
}

// Decrypt - Simulates a production ready method performing decryption using the provided client on the parameters.
//
// client - The Azure key client used for decryption.
//
// name - The name of the key as it is stored in Azure Key Vault.
//
// encrypted - The encrypted message we want to decrypt.
func Decrypt(client *azkeys.Client, name string, encrypted []byte) (string, error) {
	version, _ := GetLatestVersionOfKey(client, name)
	parameters := azkeys.KeyOperationParameters{
		Value:     encrypted,
		Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256)}
	resp, err := client.Decrypt(context.TODO(), name, version, parameters, nil)
	if err != nil {
		return "", errors.New("failed to decrypt using key: " + err.Error())
	}
	return string(resp.Result), err
}

// Certificate - Simulated production code that can fetch the value of a given certificate using the provided from the
//               managed secret using the secret client.
//
// client - The Azure secret client instance we need to use for fetching the secret value.
//
// name - The name of the certificate as stored in Azure Key Vault.
func Certificate(client *azsecrets.Client, name string) (*x509.Certificate, error) {
	_, cert, err := FetchCertificateStore(client, name)
	return cert, err
}

// PrivateKey - Simulated production code that can fetch the value of a given private key of the certificate using the
//               provided from the managed secret using the secret client.
//
// client - The Azure secret client instance we need to use for fetching the secret value.
//
// name - The name of the certificate as stored in Azure Key Vault.
func PrivateKey(client *azsecrets.Client, name string) (*ecdsa.PrivateKey, error) {
	key, _, err := FetchCertificateStore(client, name)
	return key, err
}

// FetchCertificateStore - Simulated production code that can fetch and load the certificate store using the provided
//                         from the managed secret using the secret client.
//
// client - The Azure secret client instance we need to use for fetching the secret value.
//
// name - The name of the certificate as stored in Azure Key Vault.
func FetchCertificateStore(client *azsecrets.Client, name string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	base64Value, _ := Secret(client, name)
	bytes, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return nil, nil, errors.New("failed to get the secret with certificate store: " + err.Error())
	}
	//use SSLMate library to decode the certificate store
	//as the x/crypto library is not fully compatible with the Java PKCS12 format
	key, cert, err := pkcs12.Decode(bytes, "")
	if err != nil {
		return nil, nil, errors.New("failed to open certificate store: " + err.Error())
	}
	ecKey := key.(*ecdsa.PrivateKey)
	return ecKey, cert, err
}

// GetLatestVersionOfKey - Returns the latest version of the key matching the provided name.
//
// client - The Azure key client used for decryption.
//
// name - The name of the key as it is stored in Azure Key Vault.
func GetLatestVersionOfKey(client *azkeys.Client, name string) (string, error) {
	key, err := client.GetKey(context.TODO(), name, "", nil)
	if err != nil {
		return "", errors.New("failed to get key: " + err.Error())
	}
	return key.Key.KID.Version(), nil
}
