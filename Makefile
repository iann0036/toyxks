.PHONY: build

build:
	sam build

build-LambdaFunction:
	GOOS=linux GOARCH=amd64 go build -o bootstrap
	mv ./bootstrap $(ARTIFACTS_DIR)
