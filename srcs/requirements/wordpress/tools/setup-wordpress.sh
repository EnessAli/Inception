#!/bin/bash

# Read passwords from secrets
WP_ADMIN_PASSWORD=$(cat /run/secrets/credentials | head -n1)
WP_USER_PASSWORD=$(cat /run/secrets/credentials | tail -n1)
WORDPRESS_DB_PASSWORD=$(cat /run/secrets/db_password)

# Wait for MariaDB to be ready
echo "Waiting for MariaDB to be ready..."
until mysql -h"${WORDPRESS_DB_HOST}" -u"${WORDPRESS_DB_USER}" -p"${WORDPRESS_DB_PASSWORD}" -e ";" 2>/dev/null; do
    echo -n "."
    sleep 1
done
echo "MariaDB is ready!"

# Download WordPress if not already present
if [ ! -f /var/www/html/wp-config.php ]; then
    echo "Setting up WordPress..."
    
    # Download and extract WordPress
    wget https://wordpress.org/latest.tar.gz -O /tmp/wordpress.tar.gz
    tar -xzf /tmp/wordpress.tar.gz -C /tmp/
    cp -R /tmp/wordpress/* /var/www/html/
    rm -rf /tmp/wordpress /tmp/wordpress.tar.gz
    
    # Create wp-config.php
    wp config create --allow-root \
        --dbname="${WORDPRESS_DB_NAME}" \
        --dbuser="${WORDPRESS_DB_USER}" \
        --dbpass="${WORDPRESS_DB_PASSWORD}" \
        --dbhost="${WORDPRESS_DB_HOST}"
    
    # Install WordPress
    wp core install --allow-root \
        --url="https://${DOMAIN_NAME}" \
        --title="${WP_TITLE}" \
        --admin_user="${WP_ADMIN_USER}" \
        --admin_password="${WP_ADMIN_PASSWORD}" \
        --admin_email="${WP_ADMIN_EMAIL}"
    
    # Create additional user
    wp user create "${WP_USER}" "${WP_USER_EMAIL}" \
        --role=editor \
        --user_pass="${WP_USER_PASSWORD}" \
        --allow-root
    
    echo "WordPress setup completed!"
fi

# Set correct ownership
chown -R www-data:www-data /var/www/html

# Execute the command
exec "$@"