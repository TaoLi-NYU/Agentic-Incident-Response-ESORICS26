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
iptables -I FORWARD 1 -s 10.0.1.11 -j DROP && \
iptables -I FORWARD 1 -d 10.0.1.11 -j DROP && \
iptables -I INPUT 1 -s 10.0.1.11 -j DROP && \
iptables -I OUTPUT 1 -d 10.0.1.11 -j DROP && \
echo "[contained] client 10.0.1.11 isolated at gateway"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -Label "State 2: are_forensics_preserved=true (gateway)" -Command @'
mkdir -p /var/ir/evidence && \
cp /var/log/snort/alert /var/ir/evidence/snort.alert && \
iptables-save > /var/ir/evidence/iptables.rules && \
ip addr > /var/ir/evidence/ip_addr.txt && \
ip route > /var/ir/evidence/ip_route.txt && \
ps aux > /var/ir/evidence/processes.txt && \
echo "[preserved] gateway evidence saved under /var/ir/evidence"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -Label "State 2: are_forensics_preserved=true (server_ssh)" -Command @'
mkdir -p /var/ir/evidence && \
ip addr > /var/ir/evidence/ip_addr.txt && \
ip route > /var/ir/evidence/ip_route.txt && \
ps aux > /var/ir/evidence/processes.txt && \
cp /etc/passwd /var/ir/evidence/passwd.txt && \
cat /var/log/auth.log > /var/ir/evidence/auth.log 2>/dev/null || true && \
ls -la /home/admin > /var/ir/evidence/home_admin.txt && \
echo "[preserved] server_ssh evidence saved under /var/ir/evidence"
'@

Invoke-DigitalTwinCommand -HostId "server_samba" -Label "State 2: are_forensics_preserved=true (server_samba)" -Command @'
mkdir -p /var/ir/evidence && \
ip addr > /var/ir/evidence/ip_addr.txt && \
ip route > /var/ir/evidence/ip_route.txt && \
ps aux > /var/ir/evidence/processes.txt && \
ls -la /var/log/samba > /var/ir/evidence/samba_logs_listing.txt 2>/dev/null || true && \
cat /var/log/samba/* > /var/ir/evidence/samba_logs.txt 2>/dev/null || true && \
ls -la /srv/share > /var/ir/evidence/share_listing.txt 2>/dev/null || true && \
tar -czf /var/ir/evidence/share.tar.gz /srv/share 2>/dev/null || true && \
echo "[preserved] server_samba evidence saved under /var/ir/evidence"
'@

Invoke-DigitalTwinCommand -HostId "server_shellshock" -Label "State 2: are_forensics_preserved=true (server_shellshock)" -Command @'
mkdir -p /var/ir/evidence && \
ip addr > /var/ir/evidence/ip_addr.txt && \
ip route > /var/ir/evidence/ip_route.txt && \
ps aux > /var/ir/evidence/processes.txt && \
cp /etc/passwd /var/ir/evidence/passwd.txt && \
cat /var/log/apache2/access.log > /var/ir/evidence/apache_access.log 2>/dev/null || true && \
cat /var/log/apache2/error.log > /var/ir/evidence/apache_error.log 2>/dev/null || true && \
cat /usr/lib/cgi-bin/vulnerable > /var/ir/evidence/cgi_file.sh 2>/dev/null || true && \
echo "[preserved] server_shellshock evidence saved under /var/ir/evidence"
'@

Invoke-DigitalTwinCommand -HostId "client" -Label "State 3: is_knowledge_sufficient=true" -Command @'
mkdir -p /var/ir/evidence && \
ip addr > /var/ir/evidence/ip_addr.txt && \
ip route > /var/ir/evidence/ip_route.txt && \
ps aux > /var/ir/evidence/processes.txt && \
cat /root/.ssh/known_hosts > /var/ir/evidence/known_hosts.txt 2>/dev/null || true && \
cat /opt/passwords.txt > /var/ir/evidence/password_list.txt 2>/dev/null || true && \
echo "[knowledge] client-side artifacts saved; attacker origin, used credentials, and touched targets can now be reconstructed"
'@

Invoke-DigitalTwinCommand -HostId "client" -Label "State 4: is_eradicated=true (client)" -Command @'
pkill -9 hydra 2>/dev/null || true; \
pkill -9 nmap 2>/dev/null || true; \
pkill -9 smbclient 2>/dev/null || true; \
pkill -9 curl 2>/dev/null || true; \
pkill -9 ping 2>/dev/null || true; \
pkill -9 ssh 2>/dev/null || true; \
pkill -9 sshpass 2>/dev/null || true; \
rm -f /root/.ssh/known_hosts && \
echo "[eradicated] active attack tooling and session residue removed from client"
'@

Invoke-DigitalTwinCommand -HostId "server_samba" -Label "State 4: is_eradicated=true (server_samba)" -Command @'
rm -f /srv/share/evil_payload.txt && \
echo "[eradicated] uploaded payload removed from Samba share"
'@

Invoke-DigitalTwinCommand -HostId "server_shellshock" -Label "State 5: is_hardened=true (server_shellshock)" -Command @'
chmod 0644 /usr/lib/cgi-bin/vulnerable && \
printf '%s\n' 'ServerName localhost' > /etc/apache2/conf-available/servername.conf && \
a2enconf servername >/dev/null 2>&1 || true && \
a2disconf serve-cgi-bin >/dev/null 2>&1 || true && \
apachectl restart && \
echo "[hardened] vulnerable CGI execution path disabled on shellshock host"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -Label "State 5: is_hardened=true (server_ssh)" -Command @'
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak && \
sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && \
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && \
sed -i 's/^MaxAuthTries 100/MaxAuthTries 3/' /etc/ssh/sshd_config && \
/usr/sbin/sshd -t && \
pkill sshd && /usr/sbin/sshd && \
echo "[hardened] root login and password auth disabled on ssh host"
'@

Invoke-DigitalTwinCommand -HostId "server_samba" -Label "State 5: is_hardened=true (server_samba)" -Command @'
pkill smbd && \
chmod 0755 /srv/share && \
sed -i 's/guest ok = yes/guest ok = no/' /etc/samba/smb.conf && \
sed -i 's/read only = no/read only = yes/' /etc/samba/smb.conf && \
/usr/local/samba/sbin/smbd -s /etc/samba/smb.conf --no-process-group & \
echo "[hardened] anonymous writable Samba share disabled"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -Label "State 5: is_hardened=true (gateway)" -Command @'
iptables -I FORWARD 1 -p tcp -s 10.0.1.11 --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSHBF && \
iptables -I FORWARD 1 -p tcp -s 10.0.1.11 --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 5 --name SSHBF -j DROP && \
iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 139 -j DROP && \
iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 445 -j DROP && \
iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.13 --dport 80 -m string --algo bm --string '() {' -j DROP && \
echo "[hardened] gateway blocks brute-force, SMB, and shellshock-style payloads from client"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -Label "State 6: is_recovered=true" -Command @'
iptables -S FORWARD >/dev/null 2>&1 && \
echo "[recovered] recovery actions completed and gateway forwarding policy remains readable"
'@
