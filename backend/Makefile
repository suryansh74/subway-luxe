.PHONY: help build run dev test swagger migrate clean lint

help:
	@echo "Available targets:"
	@echo "  build    - Build the application"
	@echo "  run      - Run the application"
	@echo "  dev      - Run in development mode with live reload"
	@echo "  test     - Run tests"
	@echo "  swagger - Generate Swagger documentation"
	@echo "  migrate - Run database migrations"
	@echo "  lint    - Run linters"
	@echo "  clean   - Clean build artifacts"

build:
	fuser -k 8000/tcp 2>/dev/null ; go build -o bin/server ./cmd/api

run: build
	./bin/server

dev:
	fuser -k 8000/tcp 2>/dev/null ; ENABLE_SWAGGER_UI=true go run ./cmd/api

test:
	go test -v ./...

swagger:
	swag init -g internal/auth/handlers/auth_handler.go --dir . --output docs --parseDependency

migrate:
	@echo "Database migration not yet configured"

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
	rm -rf docs/swagger.json docs/swagger.yaml docs/docs.go
