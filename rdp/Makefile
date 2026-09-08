.PHONY: build test clean install

build:
	go build -o rdp-scan .

test:
	go test ./...

clean:
	rm -f rdp-scan rdp_live.txt test-output.txt test-local-out.txt

install:
	go install .

# Test with local listener
test-local:
	@echo "Starting test..."
	./rdp-scan test-local.txt -o test-local-out.txt -c 5 -t 1s
	@echo "Results:"
	@cat test-local-out.txt 2>/dev/null || echo "(no results)"

# Test with sample data
test-sample:
	./rdp-scan test-ranges.txt -o test-output.txt -c 10 -t 1s
	@echo "Results:"
	@cat test-output.txt 2>/dev/null || echo "(no results)"

# Quick syntax check
check:
	go vet ./...

# Format code
fmt:
	go fmt .
