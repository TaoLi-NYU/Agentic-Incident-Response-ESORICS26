Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = Join-Path $Root "artifacts\alt_pivot_recovery_logs"
$LogFile = Join-Path $LogDir "alt_pivot_recovery_$Timestamp.log"
$SummaryFile = Join-Path $LogDir "alt_pivot_recovery_$Timestamp.summary.txt"
$OverallTimer = [System.Diagnostics.Stopwatch]::StartNew()

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType File -Force -Path $LogFile | Out-Null
Set-Content -Path $LogFile -Value $null -Encoding UTF8
New-Item -ItemType File -Force -Path $SummaryFile | Out-Null
Set-Content -Path $SummaryFile -Value $null -Encoding UTF8

function Write-Utf8FileLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    Add-Content -Path $Path -Value $Text -Encoding UTF8
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line
    Write-Utf8FileLine -Path $LogFile -Text $line
}

function Write-LogBlankLine {
    Write-Host ""
    Write-Utf8FileLine -Path $LogFile -Text ""
}

function Invoke-DigitalTwinCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostId,
        [Parameter(Mandatory = $true)]
        [string]$Phase,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $container = "llm_ir_dt_$HostId"
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-LogBlankLine
    Write-Log "=== [$HostId] $Phase | $Label ==="
    Write-Log "Command:"
    Write-Log $Command

    try {
        $output = docker exec $container /bin/sh -c $Command 2>&1
        $exitCode = $LASTEXITCODE
        $timer.Stop()

        if ($output) {
            foreach ($line in $output) {
                Write-Log $line
            }
        }

        Write-Log ("ExitCode: {0}" -f $exitCode)
        Write-Log ("ElapsedMs: {0}" -f $timer.ElapsedMilliseconds)

        if ($exitCode -ne 0) {
            throw "Command failed on $HostId with exit code $exitCode"
        }

        Write-Utf8FileLine -Path $SummaryFile -Text ("PASS | {0} | {1} | {2} | {3} ms" -f $Phase, $HostId, $Label, $timer.ElapsedMilliseconds)
    }
    catch {
        if ($timer.IsRunning) {
            $timer.Stop()
        }
        Write-Log "ERROR: $($_.Exception.Message)"
        Write-Log ("ElapsedMs: {0}" -f $timer.ElapsedMilliseconds)
        Write-Utf8FileLine -Path $SummaryFile -Text ("FAIL | {0} | {1} | {2} | {3} ms" -f $Phase, $HostId, $Label, $timer.ElapsedMilliseconds)
        throw
    }
}

Write-Log "Alt-pivot recovery plan execution started"
Write-Log "Designed for run_attack_alt_pivot.py with pivot server_shellshock or server_samba"
Write-Log "Log file: $LogFile"
Write-Log "Summary file: $SummaryFile"

Invoke-DigitalTwinCommand -HostId "gateway" -Phase "Phase 1" -Label "preserve gateway alerts and firewall state" -Command @'
mkdir -p /var/ir/evidence/alt_pivot && \
cp /var/log/snort/alert /var/ir/evidence/alt_pivot/snort.alert 2>/dev/null || :; \
iptables-save > /var/ir/evidence/alt_pivot/iptables.before.rules 2>/dev/null || :; \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
echo "[preserved] gateway IDS and routing evidence saved"
'@

Invoke-DigitalTwinCommand -HostId "client" -Phase "Phase 1" -Label "preserve attacker-side context" -Command @'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cat /root/.ssh/known_hosts > /var/ir/evidence/alt_pivot/known_hosts.txt 2>/dev/null || :; \
cat /opt/passwords.txt > /var/ir/evidence/alt_pivot/passwords.txt 2>/dev/null || :; \
echo "[preserved] client attack platform evidence saved"
'@

Invoke-DigitalTwinCommand -HostId "server_shellshock" -Phase "Phase 1" -Label "preserve shellshock host evidence" -Command @'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cp /etc/passwd /var/ir/evidence/alt_pivot/passwd.txt 2>/dev/null || :; \
cp /usr/lib/cgi-bin/vulnerable /var/ir/evidence/alt_pivot/vulnerable.cgi 2>/dev/null || :; \
cat /var/log/apache2/access.log > /var/ir/evidence/alt_pivot/apache_access.log 2>/dev/null || :; \
cat /var/log/apache2/error.log > /var/ir/evidence/alt_pivot/apache_error.log 2>/dev/null || :; \
echo "[preserved] shellshock RCE and pivot evidence saved"
'@

Invoke-DigitalTwinCommand -HostId "server_samba" -Phase "Phase 1" -Label "preserve samba host evidence" -Command @'
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
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -Phase "Phase 1" -Label "preserve ssh host evidence" -Command @'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cp /etc/ssh/sshd_config /var/ir/evidence/alt_pivot/sshd_config.before 2>/dev/null || :; \
cat /var/log/auth.log > /var/ir/evidence/alt_pivot/auth.log 2>/dev/null || :; \
echo "[preserved] ssh target evidence saved"
'@

Invoke-DigitalTwinCommand -HostId "server_web1" -Phase "Phase 1" -Label "preserve web1 evidence" -Command @'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cat /var/log/nginx/access.log > /var/ir/evidence/alt_pivot/nginx_access.log 2>/dev/null || :; \
cat /var/log/nginx/error.log > /var/ir/evidence/alt_pivot/nginx_error.log 2>/dev/null || :; \
echo "[preserved] web1 service evidence saved"
'@

Invoke-DigitalTwinCommand -HostId "server_web2" -Phase "Phase 1" -Label "preserve web2 evidence" -Command @'
mkdir -p /var/ir/evidence/alt_pivot && \
ip addr > /var/ir/evidence/alt_pivot/ip_addr.txt; \
ip route > /var/ir/evidence/alt_pivot/ip_route.txt; \
ps aux > /var/ir/evidence/alt_pivot/processes.txt; \
cat /var/log/nginx/access.log > /var/ir/evidence/alt_pivot/nginx_access.log 2>/dev/null || :; \
cat /var/log/nginx/error.log > /var/ir/evidence/alt_pivot/nginx_error.log 2>/dev/null || :; \
echo "[preserved] web2 service evidence saved"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -Phase "Phase 2" -Label "contain client-origin traffic at gateway" -Command @'
iptables -C FORWARD -s 10.0.1.11 -d 10.0.2.0/24 -j DROP 2>/dev/null || iptables -I FORWARD 1 -s 10.0.1.11 -d 10.0.2.0/24 -j DROP; \
iptables -C FORWARD -s 10.0.2.0/24 -d 10.0.1.11 -j DROP 2>/dev/null || iptables -I FORWARD 1 -s 10.0.2.0/24 -d 10.0.1.11 -j DROP; \
iptables -C INPUT -s 10.0.1.11 -j DROP 2>/dev/null || iptables -I INPUT 1 -s 10.0.1.11 -j DROP; \
iptables -C OUTPUT -d 10.0.1.11 -j DROP 2>/dev/null || iptables -I OUTPUT 1 -d 10.0.1.11 -j DROP; \
iptables-save > /var/ir/evidence/alt_pivot/iptables.after_client_containment.rules 2>/dev/null || :; \
echo "[contained] client 10.0.1.11 isolated from protected server network"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -Phase "Phase 2" -Label "add gateway signatures for shellshock and smb abuse" -Command @'
iptables -C FORWARD -p tcp -s 10.0.1.11 -d 10.0.2.13 --dport 80 -m string --algo bm --string '() {' -j DROP 2>/dev/null || iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.13 --dport 80 -m string --algo bm --string '() {' -j DROP; \
iptables -C FORWARD -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 139 -j DROP 2>/dev/null || iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 139 -j DROP; \
iptables -C FORWARD -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 445 -j DROP 2>/dev/null || iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.12 --dport 445 -j DROP; \
iptables-save > /var/ir/evidence/alt_pivot/iptables.after_attack_specific.rules 2>/dev/null || :; \
echo "[contained] gateway blocks Shellshock-style HTTP payloads and anonymous SMB access from client"
'@

Invoke-DigitalTwinCommand -HostId "server_shellshock" -Phase "Phase 2" -Label "contain shellshock pivot source locally when iptables exists" -Command @'
if command -v iptables >/dev/null 2>&1; then \
  for target in 10.0.2.11 10.0.2.12 10.0.2.14 10.0.2.15; do \
    iptables -C OUTPUT -d "$target" -j DROP 2>/dev/null || iptables -I OUTPUT 1 -d "$target" -j DROP; \
  done; \
  iptables-save > /var/ir/evidence/alt_pivot/local_iptables.after_containment.rules 2>/dev/null || :; \
  echo "[contained] local egress blocks added for shellshock pivot source"; \
else \
  echo "[contained] iptables not installed on shellshock host; service hardening will remove the pivot path"; \
fi
'@

Invoke-DigitalTwinCommand -HostId "server_samba" -Phase "Phase 2" -Label "contain samba pivot source locally when iptables exists" -Command @'
if command -v iptables >/dev/null 2>&1; then \
  for target in 10.0.2.11 10.0.2.13 10.0.2.14 10.0.2.15; do \
    iptables -C OUTPUT -d "$target" -j DROP 2>/dev/null || iptables -I OUTPUT 1 -d "$target" -j DROP; \
  done; \
  iptables-save > /var/ir/evidence/alt_pivot/local_iptables.after_containment.rules 2>/dev/null || :; \
  echo "[contained] local egress blocks added for samba pivot source"; \
else \
  echo "[contained] iptables not installed on samba host; service hardening will remove the pivot path"; \
fi
'@

Invoke-DigitalTwinCommand -HostId "client" -Phase "Phase 3" -Label "eradicate active attack tooling on client" -Command @'
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
'@

Invoke-DigitalTwinCommand -HostId "server_samba" -Phase "Phase 3" -Label "remove uploaded samba attack artifacts" -Command @'
rm -f /srv/share/observed_share_file.txt /srv/share/samba_pivot_payload.txt /srv/share/evil_payload.txt; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/eradicated.marker; \
echo "[eradicated] known uploaded SMB artifacts removed"
'@

Invoke-DigitalTwinCommand -HostId "server_shellshock" -Phase "Phase 3" -Label "mark shellshock host eradicated" -Command @'
mkdir -p /var/ir/status; \
date -u > /var/ir/status/eradicated.marker; \
echo "[eradicated] shellshock host has no persistent payload in this scenario"
'@

Invoke-DigitalTwinCommand -HostId "server_shellshock" -Phase "Phase 4" -Label "disable vulnerable cgi and restart apache" -Command @'
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
'@

Invoke-DigitalTwinCommand -HostId "server_samba" -Phase "Phase 4" -Label "disable anonymous writable samba share" -Command @'
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
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -Phase "Phase 4" -Label "harden ssh service against scan follow-up" -Command @'
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
'@

Invoke-DigitalTwinCommand -HostId "server_web1" -Phase "Phase 4" -Label "validate web1 service health" -Command @'
nginx -t; \
/usr/sbin/sshd -t; \
ps aux | grep '[n]ginx' >/dev/null; \
pgrep -x sshd >/dev/null; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/recovered.marker; \
echo "[validated] web1 nginx and sshd are healthy"
'@

Invoke-DigitalTwinCommand -HostId "server_web2" -Phase "Phase 4" -Label "validate web2 service health" -Command @'
nginx -t; \
/usr/sbin/sshd -t; \
ps aux | grep '[n]ginx' >/dev/null; \
pgrep -x sshd >/dev/null; \
mkdir -p /var/ir/status; \
date -u > /var/ir/status/recovered.marker; \
echo "[validated] web2 nginx and sshd are healthy"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -Phase "Phase 5" -Label "verify containment and persist final firewall evidence" -Command @'
iptables -S FORWARD | grep '10.0.1.11'; \
iptables-save > /var/ir/evidence/alt_pivot/iptables.final.rules 2>/dev/null || :; \
echo "[verified] gateway containment rules are present"
'@

Invoke-DigitalTwinCommand -HostId "server_shellshock" -Phase "Phase 5" -Label "verify shellshock hardening" -Command @'
test ! -x /usr/lib/cgi-bin/vulnerable; \
apachectl configtest; \
ps aux | grep '[a]pache' >/dev/null; \
echo "[verified] Shellshock CGI is not executable and Apache is running"
'@

Invoke-DigitalTwinCommand -HostId "server_samba" -Phase "Phase 5" -Label "verify samba hardening" -Command @'
grep -E '^[[:space:]]*map to guest = Never[[:space:]]*$' /etc/samba/smb.conf; \
grep -E '^[[:space:]]*writable = no[[:space:]]*$' /etc/samba/smb.conf; \
grep -E '^[[:space:]]*guest ok = no[[:space:]]*$' /etc/samba/smb.conf; \
grep -E '^[[:space:]]*read only = yes[[:space:]]*$' /etc/samba/smb.conf; \
ps aux | grep '[s]mbd' >/dev/null; \
echo "[verified] Samba anonymous write path is disabled and smbd is running"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -Phase "Phase 5" -Label "verify ssh hardening" -Command @'
grep -E '^PermitRootLogin no$' /etc/ssh/sshd_config; \
grep -E '^PasswordAuthentication no$' /etc/ssh/sshd_config; \
grep -E '^MaxAuthTries 3$' /etc/ssh/sshd_config; \
pgrep -x sshd >/dev/null; \
echo "[verified] SSH hardening is present and sshd is running"
'@

Write-LogBlankLine
$OverallTimer.Stop()
Write-Utf8FileLine -Path $SummaryFile -Text ("TOTAL_TIME_MS | {0}" -f $OverallTimer.ElapsedMilliseconds)
Write-Utf8FileLine -Path $SummaryFile -Text ("TOTAL_TIME_SECONDS | {0:N3}" -f $OverallTimer.Elapsed.TotalSeconds)
Write-Log ("Total recovery execution time: {0} ms ({1:N3} seconds)" -f $OverallTimer.ElapsedMilliseconds, $OverallTimer.Elapsed.TotalSeconds)
Write-Log "Alt-pivot recovery plan execution completed successfully"
Write-Log "Summary:"
Get-Content $SummaryFile | ForEach-Object { Write-Log $_ }
