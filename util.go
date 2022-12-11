package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

func getMasterKeyForExternalKeyID(keyID string) ([]byte, error) {
	if strings.HasPrefix(keyID, "mock") {
		return []byte("AES256Key-32Characters1234567890"), nil
	}

	sess := session.Must(session.NewSession())
	svc := dynamodb.New(sess)

	result, err := svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(os.Getenv("TABLE_NAME")),
		Key: map[string]*dynamodb.AttributeValue{
			"externalkeyid": {
				S: aws.String(keyID),
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, fmt.Errorf("item not found")
	}

	item := struct {
		ExternalKeyID string `json:"externalkeyid"`
		Secret        string `json:"secret"`
	}{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		return nil, err
	}

	return []byte(item.Secret), nil
}
