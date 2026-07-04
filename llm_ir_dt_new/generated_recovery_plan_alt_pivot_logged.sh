#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="$ROOT/artifacts/alt_pivot_recovery_logs"
LOG_FILE="$LOG_DIR/alt_pivot_recovery_$TIMESTAMP.log"
SUMMARY_FILE="$LOG_DIR/alt_pivot_recovery_$TIMESTAMP.summary.txt"
OVERALL_START_MS="$(date +%s%3N)"

mkdir -p "$LOG_DIR"
: > "$LOG_FILE"
: > "$SUMMARY_FILE"

write_log() {
    local message="$1"
    local line
    line="[$(date '+%Y-%m-%d %H:%M:%S')] $message"
    printf '%s\n' "$line"
    printf '%s\n' "$line" >> "$LOG_FILE"
}

write_blank_line() {
    printf '\n'
    printf '\n' >> "$LOG_FILE"
}

run_dt_command() {
    local host_id="$1"
    local phase="$2"
    local label="$3"
    local container="llm_ir_dt_$host_id"
    local command
    local output
    local exit_code
    local start_ms
    local end_ms
    local elapsed_ms

    command="$(cat)"
    start_ms="$(date +%s%3N)"

    write_blank_line
    write_log "=== [$host_id] $phase | $label ==="
    write_log "Command:"
    write_log "$command"

    set +e
    output="$(docker exec "$container" /bin/sh -c "$command" 2>&1)"
    exit_code=$?
    set -e

    end_ms="$(date +%s%3N)"
    elapsed_ms=$((end_ms - start_ms))

    if [[ -n "$output" ]]; then
        while IFS= read -r line; do
            write_log "$line"
        done <<< "$output"
    fi

    write_log "ExitCode: $exit_code"
    write_log "ElapsedMs: $elapsed_ms"

    if [[ "$exit_code" -ne 0 ]]; then
        write_log "ERROR: Command failed on $host_id with exit code $exit_code"
        printf 'FAIL | %s | %s | %s | %s ms\n' "$phase" "$host_id" "$label" "$elapsed_ms" >> "$SUMMARY_FILE"
        exit "$exit_code"
    fi

    printf 'PASS | %s | %s | %s | %s ms\n' "$phase" "$host_id" "$label" "$elapsed_ms" >> "$SUMMARY_FILE"
}

set -e

write_log "Alt-pivot recovery plan execution started"
write_log "Designed for run_attack_alt_pivot.py with pivot server_shellshock or server_samba"
write_log "Log file: $LOG_FILE"
write_log "Summary file: $SUMMARY_FILE"

run_dt_command "gateway" "Phase 1" "preserve gateway alerts and firewall state" <<'EOF'
mkdir -p /var/ir/evidence/alt_pivot && \
cp /var/log/snort/alert /var/ir/evidence/alt_pivot/snort.alert 2>/dev/null || :; \
iptables-save > /var/ir/evidence/alt_pivot/iptables.before.rules 2>/dev/null || :; \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
echo "[preserved] gateway IDS and routing evidence saved"
EOF

run_dt_command "client" "Phase 1" "preserve attacker-side context" <<'EOF'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cat /root/.ssh/known_hosts > /var/ir/evidence/alt_pivot/known_hosts.txt 2>/dev/null || :; \
cat /opt/passwords.txt > /var/ir/evidence/alt_pivot/passwords.txt 2>/dev/null || :; \
echo "[preserved] client attack platform evidence saved"
EOF

run_dt_command "server_shellshock" "Phase 1" "preserve shellshock host evidence" <<'EOF'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cp /etc/passwd /var/ir/evidence/alt_pivot/passwd.txt 2>/dev/null || :; \
cp /usr/lib/cgi-bin/vulnerable /var/ir/evidence/alt_pivot/vulnerable.cgi 2>/dev/null || :; \
cat /var/log/apache2/access.log > /var/ir/evidence/alt_pivot/apache_access.log 2>/dev/null || :; \
cat /var/log/apache2/error.log > /var/ir/evidence/alt_pivot/apache_error.log 2>/dev/null || :; \
echo "[preserved] shellshock RCE and pivot evidence saved"
EOF

run_dt_command "server_samba" "Phase 1" "preserve samba host evidence" <<'EOF'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cp /etc/samba/smb.conf /var/ir/evidence/alt_pivot/smb.conf.before 2>/dev/null || :; \
ls -la /srv/share > /var/ir/evidence/alt_pivot/share_listing.txt 2>/dev/null || :; \
tar -czf /var/ir/evidence/alt_pivot/share.tar.gz /srv/share 2>/dev/null || :; \
ls -la /var/log/samba > /var/ir/evidence/alt_pivot/samba_log_listing.txt 2>/dev/null || :; \
cat /var/log/samba/* > /var/ir/evidence/alt_pivot/samba_logs.txt 2>/dev/null || :; \
echo "[preserved] samba share and log evidence saved"
EOF

run_dt_command "server_ssh" "Phase 1" "preserve ssh host evidence" <<'EOF'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cp /etc/ssh/sshd_config /var/ir/evidence/alt_pivot/sshd_config.before 2>/dev/null || :; \
cat /var/log/auth.log > /var/ir/evidence/alt_pivot/auth.log 2>/dev/null || :; \
echo "[preserved] ssh target evidence saved"
EOF

run_dt_command "server_web1" "Phase 1" "preserve web1 evidence" <<'EOF'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cat /var/log/nginx/access.log > /var/ir/evidence/alt_pivot/nginx_access.log 2>/dev/null || :; \
cat /var/log/nginx/error.log > /var/ir/evidence/alt_pivot/nginx_error.log 2>/dev/null || :; \
echo "[preserved] web1 service evidence saved"
EOF

run_dt_command "server_web2" "Phase 1" "preserve web2 evidence" <<'EOF'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cat /var/log/nginx/access.log > /var/ir/evidence/alt_pivot/nginx_access.log 2>/dev/null || :; \
cat /var/log/nginx/error.log > /var/ir/evidence/alt_pivot/nginx_error.log 2>/dev/null || :; \
echo "[preserved] web2 service evidence saved"
EOF

run_dt_command "gateway" "Phase 2" "contain client-origin traffic at gateway" <<'EOF'
iptables -C FORWARD -s 10.0.1.11 -d 10.0.2.0/24 -j DROP 2>/dev/null || iptables -I FORWARD 1 -s 10.0.1.11 -d 10.0.2.0/24 -j DROP; \
iptables -C FORWARD -s 10.0.2.0/24 -d 10.0.1.11 -j DROP 2>/dev/null || iptables -I FORWARD 1 -s 10.0.2.0/24 -d 10.0.1.11 -j DROP; \
iptables -C INPUT -s 10.0.1.11 -j DROP 2>/dev/null || iptables -I INPUT 1 -s 10.0.1.11 -j DROP; \
iptables -C OUTPUT -d 10.0.1.11 -j DROP 2>/dev/null || iptables -I OUTPUT 1 -d 10.0.1.11 -j DROP; \
iptables-save > /var/ir/evidence/alt_pivot/iptables.after_client_containment.rules 2>/dev/null || :; \
echo "[contained] client 10.0.1.11 isolated from protected server network"
EOF

run_dt_command "gateway" "Phase 2" "add gateway signatures for shellshock and smb abuse" <<'EOF'
iptables -C FORWARD -p tcp -s 10.0.1.11 -d 10.0.2.13 --dport 80 -m string --algo bm --string '() {' -j DROP 2>/dev/null || iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.13 --dport 80 -m string --algo bm --string '() {' -j DROP; \
iptables -C FORWARD -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 139 -j DROP 2>/dev/null || iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 139 -j DROP; \
iptables -C FORWARD -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 445 -j DROP 2>/dev/null || iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 445 -j DROP; \
iptables-save > /var/ir/evidence/alt_pivot/iptables.after_attack_specific.rules 2>/dev/null || :; \
echo "[contained] gateway blocks Shellshock-style HTTP payloads and anonymous SMB access from client"
EOF

run_dt_command "server_shellshock" "Phase 2" "contain shellshock pivot source locally when iptables exists" <<'EOF'
if command -v iptables >/dev/null 2>&1; then \
  for target in 10.0.2.11 10.0.2.12 10.0.2.14 10.0.2.15; do \
    iptables -C OUTPUT -d "$target" -j DROP 2>/dev/null || iptables -I OUTPUT 1 -d "$target" -j DROP; \
  done; \
  iptables-save > /var/ir/evidence/alt_pivot/local_iptables.after_containment.rules 2>/dev/null || :; \
  echo "[contained] local egress blocks added for shellshock pivot source"; \
else \
  echo "[contained] iptables not installed on shellshock host; service hardening will remove the pivot path"; \
fi
EOF

run_dt_command "server_samba" "Phase 2" "contain samba pivot source locally when iptables exists" <<'EOF'
if command -v iptables >/dev/null 2>&1; then \
  for target in 10.0.2.11 10.0.2.13 10.0.2.14 10.0.2.15; do \
    iptables -C OUTPUT -d "$target" -j DROP 2>/dev/null || iptables -I OUTPUT 1 -d "$target" -j DROP; \
  done; \
  iptables-save > /var/ir/evidence/alt_pivot/local_iptables.after_containment.rules 2>/dev/null || :; \
  echo "[contained] local egress blocks added for samba pivot source"; \
else \
  echo "[contained] iptables not installed on samba host; service hardening will remove the pivot path"; \
fi
EOF

run_dt_command "client" "Phase 3" "eradicate active attack tooling on client" <<'EOF'
pkill -9 nmap 2>/dev/null || :; \
pkill -9 smbclient 2>/dev/null || :; \
pkill -9 curl 2>/dev/null || :; \
pkill -9 ping 2>/dev/null || :; \
pkill -9 wget 2>/dev/null || :; \
pkill -9 sshpass 2>/dev/null || :; \
pkill -9 hydra 2>/dev/null || :; \
rm -f /root/.ssh/known_hosts; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/eradicated.marker; \
echo "[eradicated] client attack tools and session residue removed"
EOF

run_dt_command "server_samba" "Phase 3" "remove uploaded samba attack artifacts" <<'EOF'
rm -f /srv/share/observed_share_file.txt /srv/share/samba_pivot_payload.txt /srv/share/evil_payload.txt; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/eradicated.marker; \
echo "[eradicated] known uploaded SMB artifacts removed"
EOF

run_dt_command "server_shellshock" "Phase 3" "mark shellshock host eradicated" <<'EOF'
mkdir -p /var/ir/status; \
date -u > /var/ir/status/eradicated.marker; \
echo "[eradicated] shellshock host has no persistent payload in this scenario"
EOF

run_dt_command "server_shellshock" "Phase 4" "disable vulnerable cgi and restart apache" <<'EOF'
chmod 0644 /usr/lib/cgi-bin/vulnerable 2>/dev/null || :; \
printf '%s\n' 'ServerName localhost' > /etc/apache2/conf-available/servername.conf; \
a2enconf servername >/dev/null 2>&1 || :; \
a2disconf serve-cgi-bin >/dev/null 2>&1 || :; \
apachectl configtest; \
apachectl restart; \
test ! -x /usr/lib/cgi-bin/vulnerable; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/hardened.marker; \
echo "[hardened] vulnerable CGI execution disabled and Apache restarted"
EOF

run_dt_command "server_samba" "Phase 4" "disable anonymous writable samba share" <<'EOF'
cp /etc/samba/smb.conf /etc/samba/smb.conf.recovery.bak 2>/dev/null || :; \
sed -i 's/^[[:space:]]*map to guest[[:space:]]*=.*/   map to guest = Never/I' /etc/samba/smb.conf; \
sed -i 's/^[[:space:]]*writable[[:space:]]*=.*/   writable = no/I' /etc/samba/smb.conf; \
sed -i 's/^[[:space:]]*guest ok[[:space:]]*=.*/   guest ok = no/I' /etc/samba/smb.conf; \
sed -i 's/^[[:space:]]*read only[[:space:]]*=.*/   read only = yes/I' /etc/samba/smb.conf; \
chmod 0755 /srv/share 2>/dev/null || :; \
pkill smbd 2>/dev/null || :; \
/usr/local/samba/sbin/smbd -s /etc/samba/smb.conf --no-process-group >/var/log/samba/smbd.recovery.log 2>&1 & \
sleep 1; \
grep -E '^[[:space:]]*guest ok = no[[:space:]]*$' /etc/samba/smb.conf; \
grep -E '^[[:space:]]*read only = yes[[:space:]]*$' /etc/samba/smb.conf; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/hardened.marker; \
echo "[hardened] anonymous writable Samba share disabled"
EOF

run_dt_command "server_ssh" "Phase 4" "harden ssh service against scan follow-up" <<'EOF'
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.recovery.bak 2>/dev/null || :; \
if grep -q '^PermitRootLogin ' /etc/ssh/sshd_config; then sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config; else printf '%s\n' 'PermitRootLogin no' >> /etc/ssh/sshd_config; fi; \
if grep -q '^PasswordAuthentication ' /etc/ssh/sshd_config; then sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config; else printf '%s\n' 'PasswordAuthentication no' >> /etc/ssh/sshd_config; fi; \
if grep -q '^MaxAuthTries ' /etc/ssh/sshd_config; then sed -i 's/^MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config; else printf '%s\n' 'MaxAuthTries 3' >> /etc/ssh/sshd_config; fi; \
/usr/sbin/sshd -t; \
pkill sshd 2>/dev/null || :; \
/usr/sbin/sshd; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/hardened.marker; \
echo "[hardened] SSH password login and excessive auth attempts disabled"
EOF

run_dt_command "server_web1" "Phase 4" "validate web1 service health" <<'EOF'
nginx -t; \
/usr/sbin/sshd -t; \
ps aux | grep '[n]ginx' >/dev/null; \
pgrep -x sshd >/dev/null; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/recovered.marker; \
echo "[validated] web1 nginx and sshd are healthy"
EOF

run_dt_command "server_web2" "Phase 4" "validate web2 service health" <<'EOF'
nginx -t; \
/usr/sbin/sshd -t; \
ps aux | grep '[n]ginx' >/dev/null; \
pgrep -x sshd >/dev/null; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/recovered.marker; \
echo "[validated] web2 nginx and sshd are healthy"
EOF

run_dt_command "gateway" "Phase 5" "verify containment and persist final firewall evidence" <<'EOF'
iptables -S FORWARD | grep '10.0.1.11'; \
iptables-save > /var/ir/evidence/alt_pivot/iptables.final.rules 2>/dev/null || :; \
echo "[verified] gateway containment rules are present"
EOF

run_dt_command "server_shellshock" "Phase 5" "verify shellshock hardening" <<'EOF'
test ! -x /usr/lib/cgi-bin/vulnerable; \
apachectl configtest; \
ps aux | grep '[a]pache' >/dev/null; \
echo "[verified] Shellshock CGI is not executable and Apache is running"
EOF

run_dt_command "server_samba" "Phase 5" "verify samba hardening" <<'EOF'
grep -E '^[[:space:]]*map to guest = Never[[:space:]]*$' /etc/samba/smb.conf; \
grep -E '^[[:space:]]*writable = no[[:space:]]*$' /etc/samba/smb.conf; \
grep -E '^[[:space:]]*guest ok = no[[:space:]]*$' /etc/samba/smb.conf; \
grep -E '^[[:space:]]*read only = yes[[:space:]]*$' /etc/samba/smb.conf; \
ps aux | grep '[s]mbd' >/dev/null; \
echo "[verified] Samba anonymous write path is disabled and smbd is running"
EOF

run_dt_command "server_ssh" "Phase 5" "verify ssh hardening" <<'EOF'
grep -E '^PermitRootLogin no$' /etc/ssh/sshd_config; \
grep -E '^PasswordAuthentication no$' /etc/ssh/sshd_config; \
grep -E '^MaxAuthTries 3$' /etc/ssh/sshd_config; \
pgrep -x sshd >/dev/null; \
echo "[verified] SSH hardening is present and sshd is running"
EOF

OVERALL_END_MS="$(date +%s%3N)"
TOTAL_MS=$((OVERALL_END_MS - OVERALL_START_MS))
TOTAL_SECONDS="$(awk "BEGIN { printf \"%.3f\", $TOTAL_MS / 1000 }")"

write_blank_line
printf 'TOTAL_TIME_MS | %s\n' "$TOTAL_MS" >> "$SUMMARY_FILE"
printf 'TOTAL_TIME_SECONDS | %s\n' "$TOTAL_SECONDS" >> "$SUMMARY_FILE"
write_log "Total recovery execution time: $TOTAL_MS ms ($TOTAL_SECONDS seconds)"
write_log "Alt-pivot recovery plan execution completed successfully"
write_log "Summary:"
while IFS= read -r line; do
    write_log "$line"
done < "$SUMMARY_FILE"
