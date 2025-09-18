#!/bin/bash

# Read passwords from secrets
MYSQL_ROOT_PASSWORD=$(cat /run/secrets/db_root_password)
MYSQL_PASSWORD=$(cat /run/secrets/db_password)

# Set other MySQL variables from environment (.env file)
# These will be available from docker-compose env_file
: ${MYSQL_DATABASE:=wordpress}
: ${MYSQL_USER:=wp_user}

# Initialize MariaDB if not already done
if [ ! -d "/var/lib/mysql/mysql" ]; then
    echo "Initializing MariaDB data directory..."
    mysql_install_db --user=mysql --datadir=/var/lib/mysql
fi

# Check if database setup is needed (check if our app database exists)
SETUP_NEEDED=true
if [ -d "/var/lib/mysql/mysql" ]; then
    # Start MariaDB temporarily to check setup
    echo "Starting MariaDB for setup check..."
    mysqld --user=mysql --datadir=/var/lib/mysql --skip-networking --bind-address=127.0.0.1 &
    TEMP_PID=$!
    
    # Wait for MariaDB to start
    while ! mysqladmin ping --silent; do
        sleep 1
    done
    
    # Check if our database exists
    if mysql -u root -e "USE ${MYSQL_DATABASE};" 2>/dev/null; then
        echo "Database already configured, skipping setup..."
        SETUP_NEEDED=false
    fi
    
    # Stop temporary MariaDB
    kill $TEMP_PID
    wait $TEMP_PID 2>/dev/null
fi

# Setup database if needed
if [ "$SETUP_NEEDED" = true ]; then
    echo "Starting MariaDB for initial configuration..."
    mysqld --user=mysql --datadir=/var/lib/mysql --skip-networking --bind-address=127.0.0.1 &
    TEMP_PID=$!
    
    # Wait for MariaDB to start
    echo "Waiting for MariaDB to start..."
    while ! mysqladmin ping --silent; do
        sleep 1
    done
    
    echo "MariaDB started, setting up database..."
    
    # Configure MariaDB
    mysql -u root <<EOF
-- Set root password
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';

-- Create application database and user
CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}\`;
CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'%' IDENTIFIED BY '${MYSQL_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_USER}'@'%';

FLUSH PRIVILEGES;
EOF

    echo "Database configuration complete!"
    
    # Stop temporary MariaDB
    kill $TEMP_PID
    wait $TEMP_PID 2>/dev/null
fi

# Start MariaDB normally in foreground
echo "Starting MariaDB in production mode..."
exec mysqld --user=mysql --datadir=/var/lib/mysql