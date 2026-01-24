BINARY_DIR := build
LDFLAGS := -s -w
COMMON := -trimpath -tags netgo -ldflags "$(LDFLAGS)"

all: amd64 arm64 armv7

amd64:
	mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(COMMON) -o $(BINARY_DIR)/xray-linux-amd64 ./main

arm64:
	mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(COMMON) -o $(BINARY_DIR)/xray-linux-arm64 ./main

armv7:
	mkdir -p $(BINARY_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build $(COMMON) -o $(BINARY_DIR)/xray-linux-armv7 ./main

clean:
	rm -rf $(BINARY_DIR)
