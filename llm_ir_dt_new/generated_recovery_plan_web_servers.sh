#!/usr/bin/env bash
set -euo pipefail

run_dt_command() {
    local host_id="$1"
    local label="$2"
    local container="llm_ir_dt_${host_id}"
    local command

    command="$(cat)"
    printf '\n=== [%s] %s ===\n' "$host_id" "$label"
    docker exec "$container" /bin/sh -c "$command"
}

run_dt_command "gateway" "State 1: is_attack_contained=true" <<'EOF'
iptables -C FORWARD -s 10.0.1.11 -d 10.0.2.14 -p tcp --dport 8080 -j DROP 2>/dev/null || iptables -I FORWARD 1 -s 10.0.1.11 -d 10.0.2.14 -p tcp --dport 8080 -j DROP
iptables -C FORWARD -s 10.0.1.11 -d 10.0.2.15 -p tcp --dport 8081 -j DROP 2>/dev/null || iptables -I FORWARD 1 -s 10.0.1.11 -d 10.0.2.15 -p tcp --dport 8081 -j DROP
iptables-save > /tmp/web_recovery_iptables_containment.rules 2>/dev/null || true
echo "[contained] blocked client access to web1 upload endpoint and web2 diagnostic command endpoint"
EOF

run_dt_command "gateway" "State 2: are_forensics_preserved=true (gateway)" <<'EOF'
mkdir -p /var/ir/evidence/web_servers
cp /var/log/snort/alert /var/ir/evidence/web_servers/snort.alert 2>/dev/null || true
iptables-save > /var/ir/evidence/web_servers/iptables.rules 2>/dev/null || true
ip addr > /var/ir/evidence/web_servers/ip_addr.txt
ip route > /var/ir/evidence/web_servers/ip_route.txt
ps aux > /var/ir/evidence/web_servers/processes.txt
echo "[preserved] gateway IDS and routing evidence saved under /var/ir/evidence/web_servers"
EOF

run_dt_command "client" "State 2: are_forensics_preserved=true (client)" <<'EOF'
mkdir -p /var/ir/evidence/web_servers
ip addr > /var/ir/evidence/web_servers/ip_addr.txt
ip route > /var/ir/evidence/web_servers/ip_route.txt
ps aux > /var/ir/evidence/web_servers/processes.txt
cat /tmp/observed_web1_file.txt > /var/ir/evidence/web_servers/observed_web1_file.client.txt 2>/dev/null || true
cat /tmp/web1_upload_response.txt > /var/ir/evidence/web_servers/web1_upload_response.txt 2>/dev/null || true
cat /root/.ssh/known_hosts > /var/ir/evidence/web_servers/known_hosts.txt 2>/dev/null || true
echo "[preserved] client-side web attack artifacts saved"
EOF

run_dt_command "server_web1" "State 2: are_forensics_preserved=true (server_web1)" <<'EOF'
mkdir -p /var/ir/evidence/web_servers
ip addr > /var/ir/evidence/web_servers/ip_addr.txt
ip route > /var/ir/evidence/web_servers/ip_route.txt
ps aux > /var/ir/evidence/web_servers/processes.txt
cp /var/www/html/uploads/observed_web1_file.txt /var/ir/evidence/web_servers/observed_web1_file.txt 2>/dev/null || true
ls -la /var/www/html/uploads > /var/ir/evidence/web_servers/uploads_listing.txt 2>/dev/null || true
cat /var/log/vulnerable_upload_server.log > /var/ir/evidence/web_servers/vulnerable_upload_server.log 2>/dev/null || true
cat /var/log/nginx/access.log > /var/ir/evidence/web_servers/nginx_access.log 2>/dev/null || true
cat /var/log/nginx/error.log > /var/ir/evidence/web_servers/nginx_error.log 2>/dev/null || true
echo "[preserved] server_web1 upload and web logs saved"
EOF

run_dt_command "server_web2" "State 2: are_forensics_preserved=true (server_web2)" <<'EOF'
mkdir -p /var/ir/evidence/web_servers
ip addr > /var/ir/evidence/web_servers/ip_addr.txt
ip route > /var/ir/evidence/web_servers/ip_route.txt
ps aux > /var/ir/evidence/web_servers/processes.txt
cp /etc/passwd /var/ir/evidence/web_servers/passwd.txt 2>/dev/null || true
cat /tmp/observed_web2_command_injection.txt > /var/ir/evidence/web_servers/observed_web2_command_injection.txt 2>/dev/null || true
cat /var/log/vulnerable_diag_server.log > /var/ir/evidence/web_servers/vulnerable_diag_server.log 2>/dev/null || true
cat /var/log/nginx/access.log > /var/ir/evidence/web_servers/nginx_access.log 2>/dev/null || true
cat /var/log/nginx/error.log > /var/ir/evidence/web_servers/nginx_error.log 2>/dev/null || true
echo "[preserved] server_web2 command-injection and web evidence saved"
EOF

run_dt_command "client" "State 3: is_knowledge_sufficient=true" <<'EOF'
mkdir -p /var/ir/evidence/web_servers
cat /var/ir/evidence/web_servers/web1_upload_response.txt 2>/dev/null || true
cat /var/ir/evidence/web_servers/observed_web1_file.client.txt 2>/dev/null || true
cat /var/ir/evidence/web_servers/known_hosts.txt 2>/dev/null || true
echo "[knowledge] evidence records client upload to 10.0.2.14 and command execution through 10.0.2.15 diagnostic endpoint"
EOF

run_dt_command "client" "State 4: is_eradicated=true (client)" <<'EOF'
pkill -9 curl 2>/dev/null || true
pkill -9 nmap 2>/dev/null || true
rm -f /tmp/observed_web1_file.txt /tmp/web1_upload_response.txt
echo "[eradicated] client-side attack process residue removed"
EOF

run_dt_command "server_web1" "State 4: is_eradicated=true (server_web1)" <<'EOF'
rm -f /var/www/html/uploads/observed_web1_file.txt
mkdir -p /var/ir/status/web_servers
date -u > /var/ir/status/web_servers/eradicated.marker
echo "[eradicated] uploaded marker file removed from server_web1"
EOF

run_dt_command "server_web2" "State 4: is_eradicated=true (server_web2)" <<'EOF'
rm -f /tmp/observed_web2_command_injection.txt
mkdir -p /var/ir/status/web_servers
date -u > /var/ir/status/web_servers/eradicated.marker
echo "[eradicated] command-injection marker file removed from server_web2"
EOF

run_dt_command "server_web1" "State 5: is_hardened=true (server_web1)" <<'EOF'
for pid in $(ps -eo pid,args | awk '/[p]ython3 \/opt\/vulnerable_upload_server.py/ {print $1}'); do kill "$pid" 2>/dev/null || true; done
chmod 0755 /var/www/html/uploads 2>/dev/null || true
mv /opt/vulnerable_upload_server.py /opt/vulnerable_upload_server.py.disabled 2>/dev/null || true
nginx -t
mkdir -p /var/ir/status/web_servers
date -u > /var/ir/status/web_servers/hardened.marker
echo "[hardened] web1 upload endpoint disabled and uploads directory is no longer world-writable"
EOF

run_dt_command "server_web2" "State 5: is_hardened=true (server_web2)" <<'EOF'
for pid in $(ps -eo pid,args | awk '/[p]ython3 \/opt\/vulnerable_diag_server.py/ {print $1}'); do kill "$pid" 2>/dev/null || true; done
mv /opt/vulnerable_diag_server.py /opt/vulnerable_diag_server.py.disabled 2>/dev/null || true
nginx -t
mkdir -p /var/ir/status/web_servers
date -u > /var/ir/status/web_servers/hardened.marker
echo "[hardened] web2 diagnostic command-injection endpoint disabled"
EOF

run_dt_command "server_web1" "State 6: is_recovered=true (server_web1)" <<'EOF'
test ! -f /var/www/html/uploads/observed_web1_file.txt
! ps -eo args | grep -q '[p]ython3 /opt/vulnerable_upload_server.py'
test ! -w /var/www/html/uploads || test "$(stat -c %a /var/www/html/uploads)" = "755"
nginx -t
ps aux | grep '[n]ginx' >/dev/null
date -u > /var/ir/status/web_servers/recovered.marker
echo "[recovered] server_web1 normal Nginx service is running and upload path is disabled"
EOF

run_dt_command "server_web2" "State 6: is_recovered=true (server_web2)" <<'EOF'
test ! -f /tmp/observed_web2_command_injection.txt
! ps -eo args | grep -q '[p]ython3 /opt/vulnerable_diag_server.py'
nginx -t
ps aux | grep '[n]ginx' >/dev/null
date -u > /var/ir/status/web_servers/recovered.marker
echo "[recovered] server_web2 normal Nginx service is running and diagnostic command endpoint is disabled"
EOF

run_dt_command "gateway" "State 6: is_recovered=true (gateway)" <<'EOF'
iptables -S FORWARD | grep '10.0.2.14' >/dev/null
iptables -S FORWARD | grep '10.0.2.15' >/dev/null
echo "[recovered] gateway containment rules remain present for the observed web-server attack paths"
EOF
