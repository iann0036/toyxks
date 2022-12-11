package main

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func handler(request events.APIGatewayProxyRequest) (ret events.APIGatewayProxyResponse, err error) {
	b, _ := json.Marshal(request.Body)
	fmt.Printf("Incoming Request: %s %s , Body: %s\n", request.HTTPMethod, request.Path, string(b))

	ret = events.APIGatewayProxyResponse{
		Body:       `{"errorName": "UnsupportedOperationException"}`,
		StatusCode: 501,
	}

	switch request.HTTPMethod {
	case "POST":
		switch {
		case request.Path == "/kms/xks/v1/health":
			ret, _ = getHealthStatusHandler(request)
		case regexp.MustCompile(`^/kms/xks/v1/keys/[a-zA-Z0-9-._]{1,128}/metadata$`).MatchString(request.Path):
			ret, _ = getKeyMetadataHandler(request)
		case regexp.MustCompile(`^/kms/xks/v1/keys/[a-zA-Z0-9-._]{1,128}/encrypt$`).MatchString(request.Path):
			ret, _ = encryptHandler(request)
		case regexp.MustCompile(`^/kms/xks/v1/keys/[a-zA-Z0-9-._]{1,128}/decrypt$`).MatchString(request.Path):
			ret, _ = decryptHandler(request)
		}
	}

	b, _ = json.Marshal(ret)
	fmt.Printf("Responding with: %s\n", string(b))

	return ret, nil
}

func main() {
	lambda.Start(handler)
}
