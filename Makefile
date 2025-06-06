.PHONY: lint
lint:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
	golangci-lint run

.PHONY: update
update:
	go get -u ./...
	go mod tidy
	go mod vendor