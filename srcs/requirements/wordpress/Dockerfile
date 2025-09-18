FROM debian:bullseye

# Install PHP and related packages
RUN apt-get update && \
    apt-get install -y \
    php7.4-fpm \
    php7.4-mysql \
    php7.4-cli \
    php7.4-curl \
    php7.4-gd \
    php7.4-mbstring \
    php7.4-xml \
    php7.4-zip \
    wget \
    curl \
    tar \
    mariadb-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure PHP-FPM to listen on all interfaces
RUN sed -i 's/listen = .*/listen = 9000/g' /etc/php/7.4/fpm/pool.d/www.conf && \
    sed -i 's/;listen.owner = .*/listen.owner = www-data/g' /etc/php/7.4/fpm/pool.d/www.conf && \
    sed -i 's/;listen.group = .*/listen.group = www-data/g' /etc/php/7.4/fpm/pool.d/www.conf && \
    sed -i 's/;listen.mode = .*/listen.mode = 0660/g' /etc/php/7.4/fpm/pool.d/www.conf

# Create directory for PID file
RUN mkdir -p /run/php

# Set working directory
WORKDIR /var/www/html

# Copy WordPress setup script
COPY tools/setup-wordpress.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/setup-wordpress.sh

# Download WP-CLI
RUN wget https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -O /usr/local/bin/wp && \
    chmod +x /usr/local/bin/wp

# Expose port 9000 for PHP-FPM
EXPOSE 9000

# Run setup script and start PHP-FPM
ENTRYPOINT ["setup-wordpress.sh"]
CMD ["php-fpm7.4", "-F"]