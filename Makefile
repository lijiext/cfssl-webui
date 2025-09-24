PROJECT_DIR := $(CURDIR)
CFSSL_DIR := $(PROJECT_DIR)/cfssl_data
CFSSL_BIN := $(CFSSL_DIR)/cfssl
CFSSLJSON_BIN := $(CFSSL_DIR)/cfssljson
ROOT_PREFIX := $(CFSSL_DIR)/root_ca

.PHONY: root up clean

root:
	@echo "==> Generating root CA in $(CFSSL_DIR)"
	@if [ ! -x $(CFSSL_BIN) ] || [ ! -x $(CFSSLJSON_BIN) ]; then \
		echo "[!] cfssl binaries missing or not executable. See cfssl_data/README.md"; \
		exit 1; \
	fi
	cd $(CFSSL_DIR) && ./cfssl gencert -initca root_ca_csr.json | ./cfssljson -bare root_ca
	@echo "==> Root CA generated: $(ROOT_PREFIX).pem"

up:
	@echo "==> Starting docker compose stack"
	docker compose up --build

clean:
	@echo "==> Stopping and removing docker compose resources"
	docker compose down -v --remove-orphans
