# 🚀 INCEPTION PROJESİ - KAPSAMLI REHBERİ

## 📖 İçindekiler
- [Proje Hakkında](#-proje-hakkında)
- [Mimari Genel Bakış](#-mimari-genel-bakış)
- [Proje Yapısı](#-proje-yapısı)
- [Docker Compose Analizi](#-docker-compose-analizi)
- [Servis Detayları](#-servis-detayları)
- [Güvenlik Yapılandırması](#-güvenlik-yapılandırması)
- [Kurulum ve Çalıştırma](#-kurulum-ve-çalıştırma)
- [Troubleshooting](#-troubleshooting)
- [En İyi Uygulamalar](#-en-iyi-uygulamalar)

---

## 🎯 Proje Hakkında

Bu proje, **Docker** ve **Docker Compose** kullanarak **LEMP stack** (Linux, Nginx, MariaDB, PHP) ile modern, güvenli ve ölçeklenebilir bir web sunucusu altyapısı kurar. Proje özellikle **42 School** eğitim müfredatının bir parçası olarak geliştirilmiş ve production-ready bir WordPress sitesi deploy etmeyi amaçlar.

### 🎯 Temel Hedefler:
- **Mikroservis mimarisi** ile modüler yapı
- **SSL/TLS güvenliği** (sadece HTTPS)
- **Container izolasyonu** ve güvenlik
- **Kalıcı veri depolama** (persistent volumes)
- **Otomatik kurulum** ve konfigürasyon
- **Production-ready** deployment

---

## 🏗️ Mimari Genel Bakış

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     NGINX       │    │   WordPress     │    │    MariaDB      │
│   (Web Server)  │────│   (PHP-FPM)     │────│   (Database)    │
│   Port: 443     │    │   Port: 9000    │    │   Port: 3306    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Docker Network │
                    │   (inception)   │
                    └─────────────────┘
```

### 🔄 Veri Akışı:
1. **İstemci** → HTTPS istekleri NGINX'e (Port 443)
2. **NGINX** → PHP dosyaları için WordPress'e FastCGI (Port 9000)
3. **WordPress** → Veritabanı işlemleri için MariaDB'ye (Port 3306)
4. **Volumes** → Kalıcı veri depolama (/home/egermen/data/)

---

## 📁 Proje Yapısı

```
inception/
├── Makefile                    # 🔧 Build ve deployment otomasyonu
├── README.md                   # 📖 Bu dokümantasyon
├── secrets/                    # 🔐 Güvenlik bilgileri
│   ├── credentials.txt         # WordPress admin/user şifreleri
│   ├── db_password.txt         # WordPress DB kullanıcı şifresi
│   └── db_root_password.txt    # MariaDB root şifresi
└── srcs/                       # 📦 Ana kaynak dosyalar
    ├── docker-compose.yml      # 🐳 Orchestration tanımları
    ├── .env                    # 🌍 Environment variables (oluşturulmalı)
    └── requirements/           # 🏗️ Her servis için Dockerfile'lar
        ├── mariadb/
        │   ├── Dockerfile      # MariaDB container tanımı
        │   └── tools/
        │       └── init-db.sh  # Veritabanı kurulum scripti
        ├── nginx/
        │   ├── Dockerfile      # NGINX container tanımı
        │   └── conf/
        │       └── nginx.conf  # Web sunucu konfigürasyonu
        └── wordpress/
            ├── Dockerfile      # WordPress+PHP-FPM container tanımı
            └── tools/
                └── setup-wordpress.sh  # WordPress kurulum scripti
```

---

## 🐳 Docker Compose Analizi

### 🌐 Network Konfigürasyonu
```yaml
networks:
  inception:
    driver: bridge
```

**Bridge Network'ün Avantajları:**
- Container'lar arasında izole iletişim
- Otomatik DNS çözümlemesi (container adlarıyla erişim)
- Güvenli port yönetimi
- Host sistemden izole ortam

### 💾 Volume Yönetimi

#### WordPress Data Volume:
```yaml
wordpress_data:
  driver: local
  driver_opts:
    type: none
    o: bind
    device: /home/egermen/data/wordpress
```

#### MariaDB Data Volume:
```yaml
mariadb_data:
  driver: local
  driver_opts:
    type: none
    o: bind
    device: /home/egermen/data/mariadb
```

**Bind Mount'un Kritik Önemi:**
- ✅ Veriler host sistemde kalıcı olarak saklanır
- ✅ Container silinse bile veriler korunur
- ✅ Backup ve migration işlemleri kolaylaşır
- ✅ Development'ta dosyalara direkt erişim
- ✅ Performance avantajı

### 🔐 Secrets Yönetimi
```yaml
secrets:
  credentials:
    file: ../secrets/credentials.txt      # WordPress şifreleri
  db_password:
    file: ../secrets/db_password.txt      # DB kullanıcı şifresi
  db_root_password:
    file: ../secrets/db_root_password.txt # DB root şifresi
```

**Güvenlik Özellikleri:**
- Şifreler container'a `/run/secrets/` altında mount edilir
- Environment variables'dan daha güvenli
- Dockerfile'da görünmez
- Runtime'da memory'de tutulur

---

## 🔧 Servis Detayları

### 🗄️ MariaDB Servisi

#### Dockerfile Analizi:
```dockerfile
FROM debian:bullseye

# MariaDB kurulumu
RUN apt-get update && \
    apt-get install -y mariadb-server mariadb-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Socket dizini oluştur
RUN mkdir -p /run/mysqld && \
    chown -R mysql:mysql /run/mysqld

# Tüm hostlardan bağlantı kabul et
RUN sed -i 's/bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf
```

#### init-db.sh Script Özellikleri:
- **İdempotent kurulum**: Tekrar çalıştırılabilir
- **Güvenli root şifre** ayarlama
- **Test veritabanı** silme
- **Anonim kullanıcılar** silme
- **Uygulama veritabanı** ve kullanıcısı oluşturma
- **Privilege flush** işlemi

#### MariaDB Docker Compose Konfigürasyonu:
```yaml
mariadb:
  build: ./requirements/mariadb
  container_name: mariadb
  image: mariadb:inception
  restart: unless-stopped          # Otomatik yeniden başlatma
  volumes:
    - mariadb_data:/var/lib/mysql  # Kalıcı veri depolama
  networks:
    - inception                    # İzole network
  secrets:                         # Güvenli şifre yönetimi
    - credentials
    - db_password
    - db_root_password
  env_file:
    - .env                         # Environment variables
  expose:
    - "3306"                       # Sadece network içinde erişim
```

### 🌐 WordPress Servisi

#### Dockerfile Analizi:
```dockerfile
FROM debian:bullseye

# PHP ve gerekli extensionlar
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
    mariadb-client
```

#### PHP-FPM Konfigürasyonu:
```bash
# Tüm arayüzlerde dinle
RUN sed -i 's/listen = .*/listen = 9000/g' /etc/php/7.4/fpm/pool.d/www.conf
```

#### setup-wordpress.sh Script Özellikleri:
- **MariaDB bekleme** mekanizması
- **WordPress indirme** ve kurulum
- **wp-config.php** oluşturma
- **WP-CLI** ile otomatik kurulum
- **Ek kullanıcı** oluşturma
- **Dosya sahiplik** ayarları

#### WordPress Docker Compose Konfigürasyonu:
```yaml
wordpress:
  build: ./requirements/wordpress
  container_name: wordpress
  image: wordpress:inception
  restart: unless-stopped
  depends_on:
    - mariadb                      # Başlatma sırası
  volumes:
    - wordpress_data:/var/www/html # NGINX ile paylaşılan volume
  networks:
    - inception
  secrets:
    - credentials
    - db_password
    - db_root_password
  env_file:
    - .env
  expose:
    - "9000"                       # PHP-FPM FastCGI portu
```

### 🔒 NGINX Servisi

#### Dockerfile Analizi:
```dockerfile
FROM debian:bullseye

# NGINX ve OpenSSL kurulumu
RUN apt-get update && \
    apt-get install -y nginx openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# SSL sertifikası oluştur
RUN openssl req -x509 -nodes -out /etc/nginx/ssl/inception.crt \
    -keyout /etc/nginx/ssl/inception.key \
    -subj "/C=TR/ST=Istanbul/L=Istanbul/O=42/OU=42/CN=egermen.42.fr/emailAddress=egermen@student.42.fr"
```

#### nginx.conf Güvenlik Özellikleri:
```nginx
# SSL ayarları
ssl_protocols TLSv1.2 TLSv1.3;        # Güvenli protokoller
ssl_prefer_server_ciphers on;         # Server cipher önceliği

# Güvenlik başlıkları
server_tokens off;                     # NGINX versiyon gizleme

# PHP işleme
location ~ \.php$ {
    include fastcgi_params;
    fastcgi_pass wordpress:9000;       # Container adıyla erişim
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}

# Güvenlik - .ht dosyalarını gizle
location ~ /\.ht {
    deny all;
}
```

#### NGINX Docker Compose Konfigürasyonu:
```yaml
nginx:
  build: ./requirements/nginx
  container_name: nginx
  image: nginx:inception
  restart: unless-stopped
  depends_on:
    - wordpress                    # WordPress'e bağımlı
  ports:
    - "443:443"                   # Sadece HTTPS portu açık
  volumes:
    - wordpress_data:/var/www/html # WordPress dosyalarına erişim
  networks:
    - inception
```

---

## 🔐 Güvenlik Yapılandırması

### Mevcut Güvenlik Dosyaları:

#### `/secrets/credentials.txt`:
```
AdminPass123!    # WordPress admin şifresi
EditorPass123!   # WordPress editor şifresi
```

#### `/secrets/db_password.txt`:
```
WpUserPass123!   # WordPress DB kullanıcı şifresi
```

#### `/secrets/db_root_password.txt`:
```
StrongRootPass123!   # MariaDB root şifresi
```

### 🛡️ Güvenlik Önlemleri:

#### 1. **Network Güvenliği:**
- Bridge network ile izolasyon
- Gereksiz portlar kapalı
- Container adlarıyla internal erişim

#### 2. **SSL/TLS Güvenliği:**
- Sadece HTTPS trafiği
- TLS 1.2/1.3 desteği
- Self-signed sertifika

#### 3. **Secrets Yönetimi:**
- Docker secrets ile şifre yönetimi
- Environment variables yerine dosya tabanlı
- Runtime'da memory'de tutulma

#### 4. **Container Güvenliği:**
- Non-root kullanıcılar
- Minimal base image (Debian Bullseye)
- Gereksiz paketler temizlenir

#### 5. **Dosya Sistemi Güvenliği:**
- Read-only filesystem'ler
- Proper file permissions
- .ht dosyalarına erişim engeli

### ⚠️ Güvenlik Geliştirme Önerileri:

1. **Şifre Güçlendirme:**
   - En az 16 karakter
   - Özel karakterler, sayılar, büyük/küçük harf
   - Düzenli şifre değişimi

2. **SSL Sertifikası:**
   - Production'da valid CA sertifikası
   - Let's Encrypt entegrasyonu
   - Certificate pinning

3. **Database Güvenliği:**
   - Encryption at rest
   - SSL connection'lar
   - Regular backup'lar

4. **Container Güvenliği:**
   - Security scanning
   - Vulnerability assessment
   - Regular image updates

---

## 🚀 Kurulum ve Çalıştırma

### 📋 Ön Gereksinimler:

```bash
# Docker kurulumu (Ubuntu/Debian)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Docker Compose kurulumu
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Sistem gereksinimleri
# - En az 2GB RAM
# - En az 10GB disk alanı
# - Linux kernel 3.10+
```

### 🔧 Environment Variables Oluşturma:

`srcs/.env` dosyası oluşturun:
```bash
# Database ayarları
MYSQL_DATABASE=wordpress
MYSQL_USER=wp_user

# WordPress ayarları
WORDPRESS_DB_HOST=mariadb
WORDPRESS_DB_NAME=wordpress
WORDPRESS_DB_USER=wp_user

# Site ayarları
DOMAIN_NAME=egermen.42.fr
WP_TITLE=My Inception Site
WP_ADMIN_USER=admin
WP_ADMIN_EMAIL=admin@egermen.42.fr
WP_USER=editor
WP_USER_EMAIL=editor@egermen.42.fr
```

### 🏃‍♂️ Makefile Komutları:

#### Temel Komutlar:
```bash
make all        # Tüm servisleri başlat (default)
make build      # Sadece build işlemi
make up         # Servisleri başlat
make down       # Servisleri durdur
make restart    # Servisleri yeniden başlat
```

#### Monitoring Komutları:
```bash
make logs       # Canlı logları izle
make status     # Container durumlarını göster
make stop       # Servisleri durdur (container'ları silmez)
```

#### Temizlik Komutları:
```bash
make clean      # Container'ları ve cache'i temizle
make fclean     # Tam temizlik (images dahil)
make re         # Tam yeniden build
```

### 📝 Adım Adım Kurulum:

#### 1. **Projeyi Klonlayın:**
```bash
git clone <repo-url> inception
cd inception
```

#### 2. **Environment Dosyası Oluşturun:**
```bash
cp srcs/.env.example srcs/.env  # Eğer varsa
nano srcs/.env  # Değerleri düzenleyin
```

#### 3. **Hosts Dosyasını Güncelleyin:**
```bash
# /etc/hosts dosyasına ekleyin
echo "127.0.0.1 egermen.42.fr" | sudo tee -a /etc/hosts
```

#### 4. **Projeyi Başlatın:**
```bash
make all
```

#### 5. **Durumu Kontrol Edin:**
```bash
make status
make logs
```

#### 6. **Siteye Erişin:**
```bash
# Tarayıcıda: https://egermen.42.fr
# Veya curl ile test:
curl -k https://egermen.42.fr
```

---

## 🔧 Troubleshooting

### ❗ Yaygın Sorunlar ve Çözümleri:

#### 1. **Container Başlatma Sorunları**

**Sorun:** Container'lar başlamıyor
```bash
# Durumu kontrol et
docker-compose -f srcs/docker-compose.yml ps
docker-compose -f srcs/docker-compose.yml logs
```

**Çözümler:**
- Port çakışması: `netstat -tulpn | grep :443`
- Disk alanı: `df -h`
- Memory kontrolü: `free -m`
- Permissions: `sudo chown -R $USER:$USER /home/egermen/data`

#### 2. **SSL Sertifika Sorunları**

**Sorun:** SSL sertifika hatası
```bash
# Sertifikayı yeniden oluştur
docker exec nginx openssl req -x509 -nodes -out /etc/nginx/ssl/inception.crt \
    -keyout /etc/nginx/ssl/inception.key \
    -subj "/C=TR/ST=Istanbul/L=Istanbul/O=42/OU=42/CN=egermen.42.fr"
```

#### 3. **Database Bağlantı Sorunları**

**Sorun:** WordPress MariaDB'ye bağlanamıyor
```bash
# MariaDB loglarını kontrol et
docker-compose -f srcs/docker-compose.yml logs mariadb

# Manuel bağlantı testi
docker exec wordpress mysql -h mariadb -u wp_user -p
```

**Çözümler:**
- Network kontrolü: `docker network ls`
- Secret dosyaları kontrolü: `ls -la secrets/`
- Environment variables: `docker exec wordpress env | grep DB`

#### 4. **Volume Mount Sorunları**

**Sorun:** Veriler kayboluyor
```bash
# Volume durumunu kontrol et
docker volume ls
docker volume inspect inception_wordpress_data
```

**Çözümler:**
```bash
# Dizinleri manuel oluştur
sudo mkdir -p /home/egermen/data/{wordpress,mariadb}
sudo chown -R $USER:$USER /home/egermen/data

# Permissions düzelt
sudo chmod 755 /home/egermen/data
sudo chmod 755 /home/egermen/data/wordpress
sudo chmod 755 /home/egermen/data/mariadb
```

#### 5. **PHP-FPM Sorunları**

**Sorun:** PHP dosyaları çalışmıyor
```bash
# PHP-FPM durumunu kontrol et
docker exec wordpress php-fpm7.4 -t
docker exec wordpress systemctl status php7.4-fpm
```

**Çözümler:**
- FastCGI ayarları kontrolü
- NGINX upstream kontrolü
- File permissions kontrolü

### 🔍 Debug Komutları:

#### Container İçine Erişim:
```bash
# NGINX container'ına gir
docker exec -it nginx /bin/bash

# WordPress container'ına gir
docker exec -it wordpress /bin/bash

# MariaDB container'ına gir
docker exec -it mariadb /bin/bash
```

#### Log İzleme:
```bash
# Tüm servis logları
docker-compose -f srcs/docker-compose.yml logs -f

# Belirli servis logları
docker-compose -f srcs/docker-compose.yml logs -f nginx
docker-compose -f srcs/docker-compose.yml logs -f wordpress
docker-compose -f srcs/docker-compose.yml logs -f mariadb
```

#### Network Debug:
```bash
# Network bilgileri
docker network inspect inception

# Container IP'leri
docker exec nginx nslookup wordpress
docker exec wordpress nslookup mariadb
```

#### Resource Monitoring:
```bash
# Container resource kullanımı
docker stats

# Disk kullanımı
docker system df
```

### 🆘 Acil Durum Komutları:

#### Tam Reset:
```bash
# Herşeyi durdur ve temizle
make fclean

# Docker sistemini temizle
docker system prune -af
docker volume prune -f
docker network prune -f

# Data dizinlerini sil
sudo rm -rf /home/egermen/data

# Yeniden başlat
make all
```

#### Backup ve Restore:
```bash
# Database backup
docker exec mariadb mysqldump -u root -p wordpress > backup.sql

# WordPress files backup
tar -czf wordpress_backup.tar.gz /home/egermen/data/wordpress

# Restore işlemi
docker exec -i mariadb mysql -u root -p wordpress < backup.sql
```

---

## 💡 En İyi Uygulamalar

### 🏗️ Development:

1. **Container Development:**
   - Multi-stage builds kullanın
   - Layer caching'den faydalanın
   - .dockerignore dosyası oluşturun
   - Minimal base image'lar tercih edin

2. **Configuration Management:**
   - Environment variables kullanın
   - Secrets'i güvenli yönetin
   - Configuration'ları externalize edin
   - Version control'de şifre saklamayın

3. **Monitoring ve Logging:**
   - Structured logging kullanın
   - Health check'ler ekleyin
   - Metrics toplama sistemleri kurun
   - Alert sistemleri oluşturun

### 🚀 Production:

1. **Security Hardening:**
   - Regular security updates
   - Vulnerability scanning
   - Access control implementation
   - Audit logging

2. **Performance Optimization:**
   - Resource limits set edin
   - Caching strategies implement edin
   - Database optimization yapın
   - CDN kullanımı düşünün

3. **Backup ve Recovery:**
   - Otomatik backup sistemleri
   - Disaster recovery planları
   - Data replication
   - Point-in-time recovery

4. **Scalability:**
   - Horizontal scaling planları
   - Load balancing
   - Database clustering
   - Container orchestration (Kubernetes)

### 📊 Monitoring Metrics:

```bash
# CPU ve Memory kullanımı
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"

# Disk I/O
docker stats --format "table {{.Container}}\t{{.BlockIO}}\t{{.NetIO}}"

# Container sağlık durumu
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

---

## 📚 Ek Kaynaklar

### 🔗 Faydalı Linkler:
- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Reference](https://docs.docker.com/compose/)
- [NGINX Configuration Guide](https://nginx.org/en/docs/)
- [WordPress Codex](https://codex.wordpress.org/)
- [MariaDB Documentation](https://mariadb.org/documentation/)

### 📖 İleri Seviye Konular:
- Container Security Best Practices
- Docker Image Optimization
- Kubernetes Migration
- CI/CD Pipeline Integration
- Monitoring ve Observability

---

## ⚡ Hızlı Komut Referansı

```bash
# Kurulum
make all

# Durum kontrolü
make status
make logs

# Yeniden başlatma
make restart

# Temizlik
make clean      # Soft clean
make fclean     # Hard clean
make re         # Rebuild all

# Debug
docker exec -it nginx /bin/bash
docker exec -it wordpress /bin/bash
docker exec -it mariadb /bin/bash

# Monitoring
docker stats
docker-compose -f srcs/docker-compose.yml logs -f
```

---

**📝 Not:** Bu doküman sürekli güncellenir. Herhangi bir sorun yaşarsanız veya katkıda bulunmak istiyorsanız, lütfen issue açın veya pull request gönderin.

**🎯 Geliştirici:** egermen@student.42.fr  
**📅 Son Güncelleme:** 21 Eylül 2025  
**🏷️ Versiyon:** 1.0.0
