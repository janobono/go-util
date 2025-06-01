.PHONY: clean fmt test vet

default: test

clean:
	@echo "  >  Cleaning build cache"
	@go clean ./...

fmt:
	@echo "  >  Formatting code"
	@go fmt ./...

test:
	@echo "  >  Executing unit tests"
	@go test -v ./...

vet:
	@echo "  >  Checking code with vet"
	@go vet ./...