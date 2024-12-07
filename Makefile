.PHONY: default

default:
	mkdir -p out
	GOOS=linux GOARCH=amd64 go build -o out/netchecker_linux-amd64 ./cmd/netchecker/
