.PHONY: run
run:
	go run cmd/identity/*.go

.PHONY: lint
lint:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6
	golangci-lint run

.PHONY: update
update:
	go get -u ./...
	go mod tidy
	go mod vendor

.PHONY: docs
docs:
	go install github.com/swaggo/swag/cmd/swag@latest
	swag init -g cmd/identity/main.go