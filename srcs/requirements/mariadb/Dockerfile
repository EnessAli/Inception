FROM debian:bullseye

# Install MariaDB
RUN apt-get update && \
    apt-get install -y mariadb-server mariadb-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create directory for socket
RUN mkdir -p /run/mysqld && \
    chown -R mysql:mysql /run/mysqld

# Configure MariaDB to accept connections from any host
RUN sed -i 's/bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf

# Copy initialization script
COPY tools/init-db.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-db.sh

# Expose MySQL port
EXPOSE 3306

# Run the initialization script and then start MariaDB
ENTRYPOINT ["init-db.sh"]
CMD ["mysqld"]