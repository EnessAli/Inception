COMPOSE_FILE = srcs/docker-compose.yml
PROJECT_NAME = inception

# Default target
all: up

# Create necessary directories
dirs:
	@mkdir -p /home/egermen/data/wordpress
	@mkdir -p /home/egermen/data/mariadb

# Build all services
build: dirs
	docker-compose -f $(COMPOSE_FILE) build --no-cache

# Start all services
up: dirs
	docker-compose -f $(COMPOSE_FILE) up -d --build

# Stop all services
down:
	docker-compose -f $(COMPOSE_FILE) down

# Restart all services
restart:
	docker-compose -f $(COMPOSE_FILE) restart

# View logs
logs:
	docker-compose -f $(COMPOSE_FILE) logs -f

# Show status of containers
status:
	docker-compose -f $(COMPOSE_FILE) ps

# Stop services without removing containers
stop:
	docker-compose -f $(COMPOSE_FILE) stop

# Clean up containers and volumes
clean: down
	docker system prune -af
	sudo rm -rf /home/egermen/data

# Full clean (remove images, containers, volumes)
fclean: clean
	docker-compose -f $(COMPOSE_FILE) down -v --rmi all

# Rebuild everything
re: fclean all

.PHONY: all build up down restart logs status stop clean fclean re dirs