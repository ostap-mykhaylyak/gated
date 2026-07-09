APP      := gated
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)

# Installation layout (override on the command line if needed).
SBIN_DIR := /sbin
CONF_DIR := /etc/$(APP)
LOG_DIR  := /var/log/$(APP)
UNIT_DIR := /etc/systemd/system
APP_USER := $(APP)
APP_GRP  := $(APP)

.PHONY: all static build test vet fmt clean dirs install uninstall

all: static

build:
	go build -o bin/$(APP) ./cmd/$(APP)

static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(APP) ./cmd/$(APP)

test:
	go test ./... -race -count=1

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf bin

dirs:
	id -u $(APP_USER) >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin $(APP_USER)
	install -d -m 0750 -o root -g $(APP_GRP) $(CONF_DIR)
	install -d -m 0750 -o root -g $(APP_GRP) $(CONF_DIR)/vhosts
	install -d -m 0750 -o root -g $(APP_GRP) $(LOG_DIR)

install: static dirs
	install -m 0755 bin/$(APP) $(SBIN_DIR)/$(APP)
	test -f $(CONF_DIR)/config.yaml || install -m 0640 -o root -g $(APP_GRP) internal/bootstrap/skel/etc/$(APP)/config.yaml $(CONF_DIR)/config.yaml
	test -f $(CONF_DIR)/vhosts/example.com.yaml.example || install -m 0640 -o root -g $(APP_GRP) internal/bootstrap/skel/etc/$(APP)/vhosts/example.com.yaml.example $(CONF_DIR)/vhosts/example.com.yaml.example
	install -m 0644 internal/bootstrap/$(APP).service $(UNIT_DIR)/$(APP).service
	install -m 0644 internal/bootstrap/skel/etc/logrotate.d/$(APP) /etc/logrotate.d/$(APP)
	@echo ""
	@echo "$(APP) $(VERSION) installed. Next steps:"
	@echo "  1. review $(CONF_DIR)/config.yaml"
	@echo "  2. add your virtual hosts under $(CONF_DIR)/vhosts/"
	@echo "  3. systemctl daemon-reload"
	@echo "  4. systemctl enable --now $(APP)"
	@echo "  5. $(APP) --status"

uninstall:
	-systemctl disable --now $(APP) 2>/dev/null
	rm -f $(SBIN_DIR)/$(APP) $(UNIT_DIR)/$(APP).service /etc/logrotate.d/$(APP)
	@echo "config, logs and data left in place ($(CONF_DIR), $(LOG_DIR)); remove manually or with '$(APP) --purge'"
