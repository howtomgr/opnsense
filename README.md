# OPNsense Installation Guide

OPNsense is a free and open-source Firewall. An open-source firewall and routing platform

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 10GB minimum
  - Network: 443 ports required
- **Operating System**: 
  - Linux: Any modern distribution (RHEL, Debian, Ubuntu, CentOS, Fedora, Arch, Alpine, openSUSE)
  - macOS: 10.14+ (Mojave or newer)
  - Windows: Windows Server 2016+ or Windows 10 Pro
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 443 (default opnsense port)
  - Firewall rules configured
- **Dependencies**:
  - FreeBSD base system
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository if needed
sudo dnf install -y epel-release

# Install opnsense
sudo dnf install -y opnsense FreeBSD base system

# Enable and start service
sudo systemctl enable --now opnsense

# Configure firewall
sudo firewall-cmd --permanent --add-service=opnsense || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
opnsense --version || systemctl status opnsense
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install opnsense
sudo apt install -y opnsense FreeBSD base system

# Enable and start service
sudo systemctl enable --now opnsense

# Configure firewall
sudo ufw allow 443

# Verify installation
opnsense --version || systemctl status opnsense
```

### Arch Linux

```bash
# Install opnsense
sudo pacman -S opnsense

# Enable and start service
sudo systemctl enable --now opnsense

# Verify installation
opnsense --version || systemctl status opnsense
```

### Alpine Linux

```bash
# Install opnsense
apk add --no-cache opnsense

# Enable and start service
rc-update add opnsense default
rc-service opnsense start

# Verify installation
opnsense --version || rc-service opnsense status
```

### openSUSE/SLES

```bash
# Install opnsense
sudo zypper install -y opnsense FreeBSD base system

# Enable and start service
sudo systemctl enable --now opnsense

# Configure firewall
sudo firewall-cmd --permanent --add-service=opnsense || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
opnsense --version || systemctl status opnsense
```

### macOS

```bash
# Using Homebrew
brew install opnsense

# Start service
brew services start opnsense

# Verify installation
opnsense --version
```

### FreeBSD

```bash
# Using pkg
pkg install opnsense

# Enable in rc.conf
echo 'opnsense_enable="YES"' >> /etc/rc.conf

# Start service
service opnsense start

# Verify installation
opnsense --version || service opnsense status
```

### Windows

```powershell
# Using Chocolatey
choco install opnsense

# Or using Scoop
scoop install opnsense

# Verify installation
opnsense --version
```

## Initial Configuration

### Basic Configuration

```bash
# Create configuration directory if needed
sudo mkdir -p /usr/local/etc

# Set up basic configuration
sudo tee /usr/local/etc/opnsense.conf << 'EOF'
# OPNsense Configuration
net.inet.ip.forwarding=1
EOF

# Set appropriate permissions
sudo chown -R opnsense:opnsense /usr/local/etc || \
  sudo chown -R $(whoami):$(whoami) /usr/local/etc

# Test configuration
sudo opnsense --test || sudo opnsense configtest
```

### Security Hardening

```bash
# Create dedicated user (if not created by package)
sudo useradd --system --shell /bin/false opnsense || true

# Secure configuration files
sudo chmod 750 /usr/local/etc
sudo chmod 640 /usr/local/etc/*.conf

# Enable security features
# See security section for detailed hardening steps
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable service
sudo systemctl enable opnsense

# Start service
sudo systemctl start opnsense

# Stop service
sudo systemctl stop opnsense

# Restart service
sudo systemctl restart opnsense

# Reload configuration
sudo systemctl reload opnsense

# Check status
sudo systemctl status opnsense

# View logs
sudo journalctl -u opnsense -f
```

### OpenRC (Alpine Linux)

```bash
# Enable service
rc-update add opnsense default

# Start service
rc-service opnsense start

# Stop service
rc-service opnsense stop

# Restart service
rc-service opnsense restart

# Check status
rc-service opnsense status

# View logs
tail -f /var/log/opnsense.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'opnsense_enable="YES"' >> /etc/rc.conf

# Start service
service opnsense start

# Stop service
service opnsense stop

# Restart service
service opnsense restart

# Check status
service opnsense status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start opnsense
brew services stop opnsense
brew services restart opnsense

# Check status
brew services list | grep opnsense

# View logs
tail -f $(brew --prefix)/var/log/opnsense.log
```

### Windows Service Manager

```powershell
# Start service
net start opnsense

# Stop service
net stop opnsense

# Using PowerShell
Start-Service opnsense
Stop-Service opnsense
Restart-Service opnsense

# Check status
Get-Service opnsense

# Set to automatic startup
Set-Service opnsense -StartupType Automatic
```

## Advanced Configuration

### Performance Optimization

```bash
# Configure performance settings
cat >> /usr/local/etc/opnsense.conf << 'EOF'
# Performance tuning
net.inet.ip.forwarding=1
EOF

# Apply system tuning
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Restart service to apply changes
sudo systemctl restart opnsense
```

### High Availability Setup

```bash
# Configure clustering/HA (if supported)
# This varies greatly by tool - see official documentation

# Example load balancing configuration
# Configure multiple instances on different ports
# Use HAProxy or nginx for load balancing
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
upstream opnsense_backend {
    server 127.0.0.1:443;
    keepalive 32;
}

server {
    listen 80;
    server_name opnsense.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name opnsense.example.com;

    ssl_certificate /etc/ssl/certs/opnsense.crt;
    ssl_certificate_key /etc/ssl/private/opnsense.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://opnsense_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Apache Configuration

```apache
<VirtualHost *:80>
    ServerName opnsense.example.com
    Redirect permanent / https://opnsense.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName opnsense.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/opnsense.crt
    SSLCertificateKeyFile /etc/ssl/private/opnsense.key
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyRequests Off
    ProxyPreserveHost On
    
    <Location />
        ProxyPass http://127.0.0.1:443/
        ProxyPassReverse http://127.0.0.1:443/
    </Location>
    
    # WebSocket support (if needed)
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:443/$1" [P,L]
</VirtualHost>
```

### HAProxy Configuration

```haproxy
global
    maxconn 4096
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend opnsense_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/opnsense.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend opnsense_backend

backend opnsense_backend
    balance roundrobin
    option httpchk GET /health
    server opnsense1 127.0.0.1:443 check
```

### Caddy Configuration

```caddy
opnsense.example.com {
    reverse_proxy 127.0.0.1:443 {
        header_up Host {upstream_hostport}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        X-XSS-Protection "1; mode=block"
    }
    
    encode gzip
}
```

## Security Configuration

### Basic Security Setup

```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home /usr/local/etc opnsense || true

# Set ownership
sudo chown -R opnsense:opnsense /usr/local/etc
sudo chown -R opnsense:opnsense /var/log

# Set permissions
sudo chmod 750 /usr/local/etc
sudo chmod 640 /usr/local/etc/*
sudo chmod 750 /var/log

# Configure firewall (UFW)
sudo ufw allow from any to any port 443 proto tcp comment "OPNsense"

# Configure firewall (firewalld)
sudo firewall-cmd --permanent --new-service=opnsense
sudo firewall-cmd --permanent --service=opnsense --add-port={default_port}/tcp
sudo firewall-cmd --permanent --add-service=opnsense
sudo firewall-cmd --reload

# SELinux configuration (if enabled)
sudo setsebool -P httpd_can_network_connect on
sudo semanage port -a -t http_port_t -p tcp 443 || true
```

### SSL/TLS Configuration

```bash
# Generate self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/opnsense.key \
    -out /etc/ssl/certs/opnsense.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=opnsense.example.com"

# Set proper permissions
sudo chmod 600 /etc/ssl/private/opnsense.key
sudo chmod 644 /etc/ssl/certs/opnsense.crt

# For production, use Let's Encrypt
sudo certbot certonly --standalone -d opnsense.example.com
```

### Fail2ban Configuration

```ini
# /etc/fail2ban/jail.d/opnsense.conf
[opnsense]
enabled = true
port = 443
filter = opnsense
logpath = /var/log/*.log
maxretry = 5
bantime = 3600
findtime = 600
```

```ini
# /etc/fail2ban/filter.d/opnsense.conf
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Authentication failed.*from <HOST>.*$
            ^.*Invalid credentials.*from <HOST>.*$
ignoreregex =
```

## Database Setup

### PostgreSQL Backend (if applicable)

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE opnsense_db;
CREATE USER opnsense_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE opnsense_db TO opnsense_user;
\q
EOF

# Configure connection in OPNsense
echo "DATABASE_URL=postgresql://opnsense_user:secure_password_here@localhost/opnsense_db" | \
  sudo tee -a /usr/local/etc/opnsense.env
```

### MySQL/MariaDB Backend (if applicable)

```bash
# Create database and user
sudo mysql << EOF
CREATE DATABASE opnsense_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'opnsense_user'@'localhost' IDENTIFIED BY 'secure_password_here';
GRANT ALL PRIVILEGES ON opnsense_db.* TO 'opnsense_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure connection
echo "DATABASE_URL=mysql://opnsense_user:secure_password_here@localhost/opnsense_db" | \
  sudo tee -a /usr/local/etc/opnsense.env
```

### SQLite Backend (if applicable)

```bash
# Create database directory
sudo mkdir -p /var/lib/opnsense
sudo chown opnsense:opnsense /var/lib/opnsense

# Initialize database
sudo -u opnsense opnsense init-db
```

## Performance Optimization

### System Tuning

```bash
# Kernel parameters for better performance
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
# Network performance tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_tw_reuse = 1

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# Apply settings
sudo sysctl -p

# Configure system limits
cat << 'EOF' | sudo tee -a /etc/security/limits.conf
opnsense soft nofile 65535
opnsense hard nofile 65535
opnsense soft nproc 32768
opnsense hard nproc 32768
EOF
```

### Application Tuning

```bash
# Configure application-specific performance settings
cat << 'EOF' | sudo tee -a /usr/local/etc/performance.conf
# Performance configuration
net.inet.ip.forwarding=1

# Connection pooling
max_connections = 1000
connection_timeout = 30

# Cache settings
cache_size = 256M
cache_ttl = 3600

# Worker processes
workers = 4
threads_per_worker = 4
EOF

# Restart to apply settings
sudo systemctl restart opnsense
```

## Monitoring

### Prometheus Integration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'opnsense'
    static_configs:
      - targets: ['localhost:443/metrics']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/opnsense-health

# Check if service is running
if ! systemctl is-active --quiet opnsense; then
    echo "CRITICAL: OPNsense service is not running"
    exit 2
fi

# Check if port is listening
if ! nc -z localhost 443 2>/dev/null; then
    echo "CRITICAL: OPNsense is not listening on port 443"
    exit 2
fi

# Check response time
response_time=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:443/health || echo "999")
if (( $(echo "$response_time > 5" | bc -l) )); then
    echo "WARNING: Slow response time: ${response_time}s"
    exit 1
fi

echo "OK: OPNsense is healthy (response time: ${response_time}s)"
exit 0
```

### Log Monitoring

```bash
# Configure log rotation
cat << 'EOF' | sudo tee /etc/logrotate.d/opnsense
/var/log/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 opnsense opnsense
    postrotate
        systemctl reload opnsense > /dev/null 2>&1 || true
    endscript
}
EOF

# Test log rotation
sudo logrotate -d /etc/logrotate.d/opnsense
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# /usr/local/bin/opnsense-backup

BACKUP_DIR="/backup/opnsense"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/opnsense_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop service (if needed for consistency)
echo "Stopping OPNsense service..."
systemctl stop opnsense

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_FILE" \
    /usr/local/etc \
    /var/lib/opnsense \
    /var/log

# Backup database (if applicable)
if command -v pg_dump &> /dev/null; then
    echo "Backing up database..."
    sudo -u postgres pg_dump opnsense_db | gzip > "$BACKUP_DIR/opnsense_db_$DATE.sql.gz"
fi

# Start service
echo "Starting OPNsense service..."
systemctl start opnsense

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Restore Script

```bash
#!/bin/bash
# /usr/local/bin/opnsense-restore

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop service
echo "Stopping OPNsense service..."
systemctl stop opnsense

# Restore files
echo "Restoring from backup..."
tar -xzf "$BACKUP_FILE" -C /

# Restore database (if applicable)
DB_BACKUP=$(echo "$BACKUP_FILE" | sed 's/.tar.gz$/_db.sql.gz/')
if [ -f "$DB_BACKUP" ]; then
    echo "Restoring database..."
    zcat "$DB_BACKUP" | sudo -u postgres psql opnsense_db
fi

# Fix permissions
chown -R opnsense:opnsense /usr/local/etc
chown -R opnsense:opnsense /var/lib/opnsense

# Start service
echo "Starting OPNsense service..."
systemctl start opnsense

echo "Restore completed successfully"
```

## 6. Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check service status and logs
sudo systemctl status opnsense
sudo journalctl -u opnsense -n 100 --no-pager

# Check for port conflicts
sudo ss -tlnp | grep 443
sudo lsof -i :443

# Verify configuration
sudo opnsense --test || sudo opnsense configtest

# Check permissions
ls -la /usr/local/etc
ls -la /var/log
```

2. **Cannot access web interface**:
```bash
# Check if service is listening
sudo ss -tlnp | grep opnsense
curl -I http://localhost:443

# Check firewall rules
sudo firewall-cmd --list-all
sudo iptables -L -n | grep 443

# Check SELinux (if enabled)
getenforce
sudo ausearch -m avc -ts recent | grep opnsense
```

3. **High memory/CPU usage**:
```bash
# Monitor resource usage
top -p $(pgrep lighttpd)
htop -p $(pgrep lighttpd)

# Check for memory leaks
ps aux | grep lighttpd
cat /proc/$(pgrep lighttpd)/status | grep -i vm

# Analyze logs for errors
grep -i error /var/log/*.log | tail -50
```

4. **Database connection errors**:
```bash
# Test database connection
psql -U opnsense_user -d opnsense_db -c "SELECT 1;"
mysql -u opnsense_user -p opnsense_db -e "SELECT 1;"

# Check database service
sudo systemctl status postgresql
sudo systemctl status mariadb
```

### Debug Mode

```bash
# Enable debug logging
echo "debug = true" | sudo tee -a /usr/local/etc/opnsense.conf

# Restart with debug mode
sudo systemctl stop opnsense
sudo -u opnsense opnsense --debug

# Watch debug logs
tail -f /var/log/debug.log
```

### Performance Analysis

```bash
# Profile CPU usage
sudo perf record -p $(pgrep lighttpd) sleep 30
sudo perf report

# Analyze network traffic
sudo tcpdump -i any -w /tmp/opnsense.pcap port 443
sudo tcpdump -r /tmp/opnsense.pcap -nn

# Monitor disk I/O
sudo iotop -p $(pgrep lighttpd)
```

## Integration Examples

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  opnsense:
    image: opnsense:opnsense
    container_name: opnsense
    restart: unless-stopped
    ports:
      - "443:443"
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
    volumes:
      - ./config:/usr/local/etc
      - ./data:/var/lib/opnsense
      - ./logs:/var/log
    networks:
      - opnsense_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:443/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  opnsense_network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# opnsense-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opnsense
  labels:
    app: opnsense
spec:
  replicas: 1
  selector:
    matchLabels:
      app: opnsense
  template:
    metadata:
      labels:
        app: opnsense
    spec:
      containers:
      - name: opnsense
        image: opnsense:opnsense
        ports:
        - containerPort: 443
        env:
        - name: TZ
          value: UTC
        volumeMounts:
        - name: config
          mountPath: /usr/local/etc
        - name: data
          mountPath: /var/lib/opnsense
        livenessProbe:
          httpGet:
            path: /health
            port: 443
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 443
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: opnsense-config
      - name: data
        persistentVolumeClaim:
          claimName: opnsense-data
---
apiVersion: v1
kind: Service
metadata:
  name: opnsense
spec:
  selector:
    app: opnsense
  ports:
  - protocol: TCP
    port: 443
    targetPort: 443
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: opnsense-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Ansible Playbook

```yaml
---
# opnsense-playbook.yml
- name: Install and configure OPNsense
  hosts: all
  become: yes
  vars:
    opnsense_version: latest
    opnsense_port: 443
    opnsense_config_dir: /usr/local/etc
  
  tasks:
    - name: Install dependencies
      package:
        name:
          - FreeBSD base system
        state: present
    
    - name: Install OPNsense
      package:
        name: opnsense
        state: present
    
    - name: Create configuration directory
      file:
        path: "{{ opnsense_config_dir }}"
        state: directory
        owner: opnsense
        group: opnsense
        mode: '0750'
    
    - name: Deploy configuration
      template:
        src: opnsense.conf.j2
        dest: "{{ opnsense_config_dir }}/opnsense.conf"
        owner: opnsense
        group: opnsense
        mode: '0640'
      notify: restart opnsense
    
    - name: Start and enable service
      systemd:
        name: opnsense
        state: started
        enabled: yes
        daemon_reload: yes
    
    - name: Configure firewall
      firewalld:
        port: "{{ opnsense_port }}/tcp"
        permanent: yes
        immediate: yes
        state: enabled
  
  handlers:
    - name: restart opnsense
      systemd:
        name: opnsense
        state: restarted
```

### Terraform Configuration

```hcl
# opnsense.tf
resource "aws_instance" "opnsense_server" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.opnsense.id]
  
  user_data = <<-EOF
    #!/bin/bash
    # Install OPNsense
    apt-get update
    apt-get install -y opnsense FreeBSD base system
    
    # Configure OPNsense
    systemctl enable opnsense
    systemctl start opnsense
  EOF
  
  tags = {
    Name = "OPNsense Server"
    Application = "OPNsense"
  }
}

resource "aws_security_group" "opnsense" {
  name        = "opnsense-sg"
  description = "Security group for OPNsense"
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "OPNsense Security Group"
  }
}
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update opnsense
sudo dnf update opnsense

# Debian/Ubuntu
sudo apt update
sudo apt upgrade opnsense

# Arch Linux
sudo pacman -Syu opnsense

# Alpine Linux
apk update
apk upgrade opnsense

# openSUSE
sudo zypper ref
sudo zypper update opnsense

# FreeBSD
pkg update
pkg upgrade opnsense

# Always backup before updates
/usr/local/bin/opnsense-backup

# Restart after updates
sudo systemctl restart opnsense
```

### Regular Maintenance Tasks

```bash
# Clean old logs
find /var/log -name "*.log" -mtime +30 -delete

# Vacuum database (if PostgreSQL)
sudo -u postgres vacuumdb --analyze opnsense_db

# Check disk usage
df -h | grep -E "(/$|opnsense)"
du -sh /var/lib/opnsense

# Update security patches
sudo unattended-upgrade -d

# Review security logs
sudo aureport --summary
sudo journalctl -u opnsense | grep -i "error\|fail\|deny"
```

### Health Monitoring Checklist

- [ ] Service is running and enabled
- [ ] Web interface is accessible
- [ ] Database connections are healthy
- [ ] Disk usage is below 80%
- [ ] No critical errors in logs
- [ ] Backups are running successfully
- [ ] SSL certificates are valid
- [ ] Security updates are applied

## Additional Resources

- Official Documentation: https://docs.opnsense.org/
- GitHub Repository: https://github.com/opnsense/opnsense
- Community Forum: https://forum.opnsense.org/
- Wiki: https://wiki.opnsense.org/
- Docker Hub: https://hub.docker.com/r/opnsense/opnsense
- Security Advisories: https://security.opnsense.org/
- Best Practices: https://docs.opnsense.org/best-practices
- API Documentation: https://api.opnsense.org/
- Comparison with pfSense, IPFire, Sophos, Untangle: https://docs.opnsense.org/comparison

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.
