FROM debian:bullseye

# Update package list and install nginx and openssl
RUN apt-get update && \
    apt-get install -y nginx openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create SSL directory
RUN mkdir -p /etc/nginx/ssl

# Generate self-signed SSL certificate
RUN openssl req -x509 -nodes -out /etc/nginx/ssl/inception.crt \
    -keyout /etc/nginx/ssl/inception.key \
    -subj "/C=TR/ST=Istanbul/L=Istanbul/O=42/OU=42/CN=egermen.42.fr/emailAddress=egermen@student.42.fr"

# Copy nginx configuration file
COPY conf/nginx.conf /etc/nginx/nginx.conf

# Create directory for website files
RUN mkdir -p /var/www/html && \
    chown -R www-data:www-data /var/www/html

# Expose port 443 for HTTPS
EXPOSE 443

# Start nginx in foreground
CMD ["nginx", "-g", "daemon off;"]