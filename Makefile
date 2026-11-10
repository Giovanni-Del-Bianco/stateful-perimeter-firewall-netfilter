.PHONY: all deploy test status clean

all: deploy test

deploy:
	@chmod +x src/firewall.sh scripts/*.sh
	@./scripts/setup_netns.sh
	@./src/firewall.sh

test:
	@chmod +x scripts/verify_matrix.sh
	@./scripts/verify_matrix.sh

status:
	@echo "=== FILTER TABLE ==="
	@iptables -t filter -L -v -n --line-numbers
	@echo ""
	@echo "=== NAT TABLE ==="
	@iptables -t nat -L -v -n --line-numbers
	@echo ""
	@echo "=== RECENT KERNEL DROP LOGS ==="
	@dmesg | grep "DROP:" | tail -n 10 || true

clean:
	@chmod +x scripts/teardown_netns.sh
	@./scripts/teardown_netns.sh

