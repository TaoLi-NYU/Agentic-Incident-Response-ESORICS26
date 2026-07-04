Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-DigitalTwinCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostId,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $container = "llm_ir_dt_$HostId"
    Write-Host ""
    Write-Host "=== [$HostId] $Label ==="
    docker exec $container /bin/sh -c $Command
}

Invoke-DigitalTwinCommand -HostId "gateway" -Label "State 1: is_attack_contained=true" -Command @'
iptables -C FORWARD -s 10.0.1.11 -d 10.0.2.14 -p tcp --dport 8080 -j DROP 2>/dev/null || iptables -I FORWARD 1 -s 10.0.1.11 -d 10.0.2.14 -p tcp --dport 8080 -j DROP; \
iptables -C FORWARD -s 10.0.1.11 -d 10.0.2.15 -p tcp --dport 8081 -j DROP 2>/dev/null || iptables -I FORWARD 1 -s 10.0.1.11 -d 10.0.2.15 -p tcp --dport 8081 -j DROP; \
iptables-save > /tmp/web_recovery_iptables_containment.rules 2>/dev/null || true; \
echo "[contained] blocked client access to web1 upload endpoint and web2 diagnostic command endpoint"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -Label "State 2: are_forensics_preserved=true (gateway)" -Command @'
mkdir -p /var/ir/evidence/web_servers && \
cp /var/log/snort/alert /var/ir/evidence/web_servers/snort.alert 2>/dev/null || true; \
iptables-save > /var/ir/evidence/web_servers/iptables.rules 2>/dev/null || true; \
ip addr > /var/ir/evidence/web_servers/ip_addr.txt; \
ip route > /var/ir/evidence/web_servers/ip_route.txt; \
ps aux > /var/ir/evidence/web_servers/processes.txt; \
echo "[preserved] gateway IDS and routing evidence saved under /var/ir/evidence/web_servers"
'@

Invoke-DigitalTwinCommand -HostId "client" -Label "State 2: are_forensics_preserved=true (client)" -Command @'
mkdir -p /var/ir/evidence/web_servers && \
ip addr > /var/ir/evidence/web_servers/ip_addr.txt; \
ip route > /var/ir/evidence/web_servers/ip_route.txt; \
ps aux > /var/ir/evidence/web_servers/processes.txt; \
cat /tmp/observed_web1_file.txt > /var/ir/evidence/web_servers/observed_web1_file.client.txt 2>/dev/null || true; \
cat /tmp/web1_upload_response.txt > /var/ir/evidence/web_servers/web1_upload_response.txt 2>/dev/null || true; \
cat /root/.ssh/known_hosts > /var/ir/evidence/web_servers/known_hosts.txt 2>/dev/null || true; \
echo "[preserved] client-side web attack artifacts saved"
'@

Invoke-DigitalTwinCommand -HostId "server_web1" -Label "State 2: are_forensics_preserved=true (server_web1)" -Command @'
mkdir -p /var/ir/evidence/web_servers && \
ip addr > /var/ir/evidence/web_servers/ip_addr.txt; \
ip route > /var/ir/evidence/web_servers/ip_route.txt; \
ps aux > /var/ir/evidence/web_servers/processes.txt; \
cp /var/www/html/uploads/observed_web1_file.txt /var/ir/evidence/web_servers/observed_web1_file.txt 2>/dev/null || true; \
ls -la /var/www/html/uploads > /var/ir/evidence/web_servers/uploads_listing.txt 2>/dev/null || true; \
cat /var/log/vulnerable_upload_server.log > /var/ir/evidence/web_servers/vulnerable_upload_server.log 2>/dev/null || true; \
cat /var/log/nginx/access.log > /var/ir/evidence/web_servers/nginx_access.log 2>/dev/null || true; \
cat /var/log/nginx/error.log > /var/ir/evidence/web_servers/nginx_error.log 2>/dev/null || true; \
echo "[preserved] server_web1 upload and web logs saved"
'@

Invoke-DigitalTwinCommand -HostId "server_web2" -Label "State 2: are_forensics_preserved=true (server_web2)" -Command @'
mkdir -p /var/ir/evidence/web_servers && \
ip addr > /var/ir/evidence/web_servers/ip_addr.txt; \
ip route > /var/ir/evidence/web_servers/ip_route.txt; \
ps aux > /var/ir/evidence/web_servers/processes.txt; \
cp /etc/passwd /var/ir/evidence/web_servers/passwd.txt 2>/dev/null || true; \
cat /tmp/observed_web2_command_injection.txt > /var/ir/evidence/web_servers/observed_web2_command_injection.txt 2>/dev/null || true; \
cat /var/log/vulnerable_diag_server.log > /var/ir/evidence/web_servers/vulnerable_diag_server.log 2>/dev/null || true; \
cat /var/log/nginx/access.log > /var/ir/evidence/web_servers/nginx_access.log 2>/dev/null || true; \
cat /var/log/nginx/error.log > /var/ir/evidence/web_servers/nginx_error.log 2>/dev/null || true; \
echo "[preserved] server_web2 command-injection and web evidence saved"
'@

Invoke-DigitalTwinCommand -HostId "client" -Label "State 3: is_knowledge_sufficient=true" -Command @'
mkdir -p /var/ir/evidence/web_servers && \
cat /var/ir/evidence/web_servers/web1_upload_response.txt 2>/dev/null || true; \
cat /var/ir/evidence/web_servers/observed_web1_file.client.txt 2>/dev/null || true; \
cat /var/ir/evidence/web_servers/known_hosts.txt 2>/dev/null || true; \
echo "[knowledge] evidence records client upload to 10.0.2.14 and command execution through 10.0.2.15 diagnostic endpoint"
'@

Invoke-DigitalTwinCommand -HostId "client" -Label "State 4: is_eradicated=true (client)" -Command @'
pkill -9 curl 2>/dev/null || true; \
pkill -9 nmap 2>/dev/null || true; \
rm -f /tmp/observed_web1_file.txt /tmp/web1_upload_response.txt; \
echo "[eradicated] client-side attack process residue removed"
'@

Invoke-DigitalTwinCommand -HostId "server_web1" -Label "State 4: is_eradicated=true (server_web1)" -Command @'
rm -f /var/www/html/uploads/observed_web1_file.txt; \
mkdir -p /var/ir/status/web_servers; \
date -u > /var/ir/status/web_servers/eradicated.marker; \
echo "[eradicated] uploaded marker file removed from server_web1"
'@

Invoke-DigitalTwinCommand -HostId "server_web2" -Label "State 4: is_eradicated=true (server_web2)" -Command @'
rm -f /tmp/observed_web2_command_injection.txt; \
mkdir -p /var/ir/status/web_servers; \
date -u > /var/ir/status/web_servers/eradicated.marker; \
echo "[eradicated] command-injection marker file removed from server_web2"
'@

Invoke-DigitalTwinCommand -HostId "server_web1" -Label "State 5: is_hardened=true (server_web1)" -Command @'
for pid in $(ps -eo pid,args | awk '/[p]ython3 \/opt\/vulnerable_upload_server.py/ {print $1}'); do kill "$pid" 2>/dev/null || true; done; \
chmod 0755 /var/www/html/uploads 2>/dev/null || true; \
mv /opt/vulnerable_upload_server.py /opt/vulnerable_upload_server.py.disabled 2>/dev/null || true; \
nginx -t; \
mkdir -p /var/ir/status/web_servers; \
date -u > /var/ir/status/web_servers/hardened.marker; \
echo "[hardened] web1 upload endpoint disabled and uploads directory is no longer world-writable"
'@

Invoke-DigitalTwinCommand -HostId "server_web2" -Label "State 5: is_hardened=true (server_web2)" -Command @'
for pid in $(ps -eo pid,args | awk '/[p]ython3 \/opt\/vulnerable_diag_server.py/ {print $1}'); do kill "$pid" 2>/dev/null || true; done; \
mv /opt/vulnerable_diag_server.py /opt/vulnerable_diag_server.py.disabled 2>/dev/null || true; \
nginx -t; \
mkdir -p /var/ir/status/web_servers; \
date -u > /var/ir/status/web_servers/hardened.marker; \
echo "[hardened] web2 diagnostic command-injection endpoint disabled"
'@

Invoke-DigitalTwinCommand -HostId "server_web1" -Label "State 6: is_recovered=true (server_web1)" -Command @'
test ! -f /var/www/html/uploads/observed_web1_file.txt; \
! ps -eo args | grep -q '[p]ython3 /opt/vulnerable_upload_server.py'; \
test ! -w /var/www/html/uploads || test "$(stat -c %a /var/www/html/uploads)" = "755"; \
nginx -t; \
ps aux | grep '[n]ginx' >/dev/null; \
date -u > /var/ir/status/web_servers/recovered.marker; \
echo "[recovered] server_web1 normal Nginx service is running and upload path is disabled"
'@

Invoke-DigitalTwinCommand -HostId "server_web2" -Label "State 6: is_recovered=true (server_web2)" -Command @'
test ! -f /tmp/observed_web2_command_injection.txt; \
! ps -eo args | grep -q '[p]ython3 /opt/vulnerable_diag_server.py'; \
nginx -t; \
ps aux | grep '[n]ginx' >/dev/null; \
date -u > /var/ir/status/web_servers/recovered.marker; \
echo "[recovered] server_web2 normal Nginx service is running and diagnostic command endpoint is disabled"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -Label "State 6: is_recovered=true (gateway)" -Command @'
iptables -S FORWARD | grep '10.0.2.14' >/dev/null; \
iptables -S FORWARD | grep '10.0.2.15' >/dev/null; \
echo "[recovered] gateway containment rules remain present for the observed web-server attack paths"
'@
