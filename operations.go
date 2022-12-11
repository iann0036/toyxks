package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"github.com/aws/aws-lambda-go/events"
)

func getHealthStatusHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	resp := struct {
		XksProxyFleetSize int    `json:"xksProxyFleetSize"`
		XksProxyVendor    string `json:"xksProxyVendor"`
		XksProxyModel     string `json:"xksProxyModel"`
		EkmVendor         string `json:"ekmVendor"`
		EkmFleetDetails   []struct {
			ID           string `json:"id"`
			Model        string `json:"model"`
			HealthStatus string `json:"healthStatus"`
		} `json:"ekmFleetDetails"`
	}{
		XksProxyFleetSize: 1,
		XksProxyVendor:    "Mock XKS Proxy Vendor",
		XksProxyModel:     "0.1",
		EkmVendor:         "Mock EKM Vendor",
		EkmFleetDetails: []struct {
			ID           string "json:\"id\""
			Model        string "json:\"model\""
			HealthStatus string "json:\"healthStatus\""
		}{
			{
				ID:           "MOCKEKM1",
				Model:        "Mock EKM 1",
				HealthStatus: "ACTIVE",
			},
		},
	}

	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InternalException"}`,
			StatusCode: 500,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(b),
		StatusCode: 200,
	}, nil
}

func getKeyMetadataHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	keyID := regexp.MustCompile(`^/kms/xks/v1/keys/([a-zA-Z0-9-._]{1,128})/metadata$`).FindStringSubmatch(request.Path)[1]

	_, err := getMasterKeyForExternalKeyID(keyID)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "KeyNotFoundException"}`,
			StatusCode: 404,
		}, nil
	}

	resp := struct {
		KeySpec   string   `json:"keySpec"`
		KeyUsage  []string `json:"keyUsage"`
		KeyStatus string   `json:"keyStatus"`
	}{
		KeySpec: "AES_256",
		KeyUsage: []string{
			"ENCRYPT",
			"DECRYPT",
		},
		KeyStatus: "ENABLED",
	}

	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InternalException"}`,
			StatusCode: 500,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(b),
		StatusCode: 200,
	}, nil
}

func encryptHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	keyID := regexp.MustCompile(`^/kms/xks/v1/keys/([a-zA-Z0-9-._]{1,128})/encrypt$`).FindStringSubmatch(request.Path)[1]

	masterKey, err := getMasterKeyForExternalKeyID(keyID)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "KeyNotFoundException"}`,
			StatusCode: 404,
		}, nil
	}

	requestContents := struct {
		RequestMetadata struct {
			AwsPrincipalArn string `json:"awsPrincipalArn"`
			KmsKeyArn       string `json:"kmsKeyArn"`
			KmsOperation    string `json:"kmsOperation"`
			KmsRequestID    string `json:"kmsRequestId"`
			KmsViaService   string `json:"kmsViaService"`
		} `json:"requestMetadata"`
		AdditionalAuthenticatedData           string `json:"additionalAuthenticatedData"`
		Plaintext                             string `json:"plaintext"`
		EncryptionAlgorithm                   string `json:"encryptionAlgorithm"`
		CiphertextDataIntegrityValueAlgorithm string `json:"ciphertextDataIntegrityValueAlgorithm"`
	}{}

	err = json.Unmarshal([]byte(request.Body), &requestContents)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InternalException"}`,
			StatusCode: 500,
		}, nil
	}

	plaintextB, err := base64.StdEncoding.DecodeString(requestContents.Plaintext)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	var additionalAuthenticatedDataB []byte
	if requestContents.AdditionalAuthenticatedData != "" {
		additionalAuthenticatedDataB, err = base64.StdEncoding.DecodeString(requestContents.AdditionalAuthenticatedData)
		if err != nil {
			fmt.Println(err)
			return events.APIGatewayProxyResponse{
				Body:       `{"errorName": "InvalidCiphertextException"}`,
				StatusCode: 500,
			}, nil
		}
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	var ciphertextWithTag []byte
	if requestContents.AdditionalAuthenticatedData != "" {
		ciphertextWithTag = aesgcm.Seal(nil, iv, plaintextB, additionalAuthenticatedDataB)
	} else {
		ciphertextWithTag = aesgcm.Seal(nil, iv, plaintextB, nil)
	}

	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-aesgcm.Overhead()]
	authtag := ciphertextWithTag[len(ciphertextWithTag)-aesgcm.Overhead():]

	resp := struct {
		AuthenticationTag            string `json:"authenticationTag"`
		Ciphertext                   string `json:"ciphertext"`
		CiphertextDataIntegrityValue string `json:"ciphertextDataIntegrityValue,omitempty"`
		CiphertextMetadata           string `json:"ciphertextMetadata,omitempty"`
		InitializationVector         string `json:"initializationVector"`
	}{
		AuthenticationTag:    base64.URLEncoding.EncodeToString(authtag),
		Ciphertext:           base64.URLEncoding.EncodeToString(ciphertext),
		InitializationVector: base64.URLEncoding.EncodeToString(iv),
	}

	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InternalException"}`,
			StatusCode: 500,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(b),
		StatusCode: 200,
	}, nil
}

func decryptHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	keyID := regexp.MustCompile(`^/kms/xks/v1/keys/([a-zA-Z0-9-._]{1,128})/decrypt$`).FindStringSubmatch(request.Path)[1]

	masterKey, err := getMasterKeyForExternalKeyID(keyID)
	if err != nil {
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "KeyNotFoundException"}`,
			StatusCode: 404,
		}, nil
	}

	requestContents := struct {
		RequestMetadata struct {
			AwsPrincipalArn string `json:"awsPrincipalArn"`
			KmsKeyArn       string `json:"kmsKeyArn"`
			KmsOperation    string `json:"kmsOperation"`
			KmsRequestID    string `json:"kmsRequestId"`
			KmsViaService   string `json:"kmsViaService"`
		} `json:"requestMetadata"`
		AdditionalAuthenticatedData string `json:"additionalAuthenticatedData"`
		EncryptionAlgorithm         string `json:"encryptionAlgorithm"`
		Ciphertext                  string `json:"ciphertext"`
		CiphertextMetadata          string `json:"ciphertextMetadata"`
		InitializationVector        string `json:"initializationVector"`
		AuthenticationTag           string `json:"authenticationTag"`
	}{}

	err = json.Unmarshal([]byte(request.Body), &requestContents)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InternalException"}`,
			StatusCode: 500,
		}, nil
	}

	ciphertextB, err := base64.StdEncoding.DecodeString(requestContents.Ciphertext)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	authenticationTagB, err := base64.StdEncoding.DecodeString(requestContents.AuthenticationTag)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	ivB, err := base64.StdEncoding.DecodeString(requestContents.InitializationVector)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	var additionalAuthenticatedDataB []byte
	if requestContents.AdditionalAuthenticatedData != "" {
		additionalAuthenticatedDataB, err = base64.StdEncoding.DecodeString(requestContents.AdditionalAuthenticatedData)
		if err != nil {
			fmt.Println(err)
			return events.APIGatewayProxyResponse{
				Body:       `{"errorName": "InvalidCiphertextException"}`,
				StatusCode: 500,
			}, nil
		}
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	var plaintext []byte
	if requestContents.AdditionalAuthenticatedData != "" {
		plaintext, err = aesgcm.Open(nil, ivB, append(ciphertextB, authenticationTagB...), additionalAuthenticatedDataB)
	} else {
		plaintext, err = aesgcm.Open(nil, ivB, append(ciphertextB, authenticationTagB...), nil)
	}

	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InvalidCiphertextException"}`,
			StatusCode: 500,
		}, nil
	}

	resp := struct {
		Plaintext string `json:"plaintext"`
	}{
		Plaintext: base64.URLEncoding.EncodeToString(plaintext),
	}

	b, err := json.Marshal(resp)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{
			Body:       `{"errorName": "InternalException"}`,
			StatusCode: 500,
		}, nil
	}

	return events.APIGatewayProxyResponse{
		Body:       string(b),
		StatusCode: 200,
	}, nil
}
