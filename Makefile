up:
	@echo "Starting docker images..."
	docker compose up -d
	@echo "Docker images started successfully"

down:
	@echo "Stopping docker images..."
	docker compose down
	@echo "Docker images stopped successfully"

test:
	@echo "Running tests..."
	go test ./tests/... -v
	@echo "Tests completed successfully"