Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = Join-Path $Root "artifacts\generated_recovery_logs"
$LogFile = Join-Path $LogDir "generated_recovery_211_withouttechniques_$Timestamp.log"
$SummaryFile = Join-Path $LogDir "generated_recovery_211_withouttechniques_$Timestamp.summary.txt"
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
        [string]$StateId,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $container = "llm_ir_dt_$HostId"
    Write-LogBlankLine
    Write-Log "=== [$HostId] $StateId | $Label ==="
    Write-Log "Command:"
    Write-Log $Command

    try {
        $normalizedCommand = ($Command -replace "`r`n", "`n") -replace "`r", ""
        $output = $normalizedCommand | docker exec -i $container /bin/sh 2>&1
        $exitCode = $LASTEXITCODE
        if ($output) {
            foreach ($line in $output) {
                Write-Log $line
            }
        }
        Write-Log "ExitCode: $exitCode"
        if ($exitCode -ne 0) {
            throw "Command failed on $HostId with exit code $exitCode"
        }
        Write-Utf8FileLine -Path $SummaryFile -Text ("PASS | {0} | {1} | {2}" -f $StateId, $HostId, $Label)
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)"
        Write-Utf8FileLine -Path $SummaryFile -Text ("FAIL | {0} | {1} | {2}" -f $StateId, $HostId, $Label)
        throw
    }
}

Write-Log "Generated single-server recovery plan started: without techniques"
Write-Log "Target server: 10.0.2.11 (server_ssh)"
Write-Log "Log file: $LogFile"
Write-Log "Summary file: $SummaryFile"

Invoke-DigitalTwinCommand -HostId "gateway" -StateId "State 1" -Label "is_attack_contained=true" -Command @'
iptables -I FORWARD 1 -s 10.0.1.11 -d 10.0.2.11 -j DROP && \
iptables -I FORWARD 1 -s 10.0.2.11 -d 10.0.1.11 -j DROP && \
iptables -I INPUT 1 -s 10.0.1.11 -j DROP && \
iptables -I OUTPUT 1 -d 10.0.1.11 -j DROP && \
echo "[contained] attacker 10.0.1.11 isolated from target server 10.0.2.11"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -StateId "State 2" -Label "are_forensics_preserved=true (gateway)" -Command @'
mkdir -p /var/ir/evidence211 && \
cp /var/log/snort/alert /var/ir/evidence211/snort.alert 2>/dev/null || true; \
iptables-save > /var/ir/evidence211/iptables.rules && \
ip addr > /var/ir/evidence211/ip_addr.txt && \
ip route > /var/ir/evidence211/ip_route.txt && \
ps aux > /var/ir/evidence211/processes.txt && \
echo "[preserved] gateway evidence for 10.0.2.11 saved under /var/ir/evidence211"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 2" -Label "are_forensics_preserved=true (server_ssh)" -Command @'
mkdir -p /var/ir/evidence211 && \
ip addr > /var/ir/evidence211/ip_addr.txt && \
ip route > /var/ir/evidence211/ip_route.txt && \
ps aux > /var/ir/evidence211/processes.txt && \
cp /etc/passwd /var/ir/evidence211/passwd.txt && \
cat /etc/shadow > /var/ir/evidence211/shadow.txt 2>/dev/null || true; \
cat /var/log/auth.log > /var/ir/evidence211/auth.log 2>/dev/null || true; \
cp /etc/ssh/sshd_config /var/ir/evidence211/sshd_config.before && \
ls -la /home/admin > /var/ir/evidence211/home_admin.txt 2>/dev/null || true; \
tar -czf /var/ir/evidence211/home_admin.tar.gz /home/admin 2>/dev/null || true; \
dpkg -V openssh-server > /var/ir/evidence211/openssh_integrity.txt 2>&1 || true; \
echo "[preserved] target host evidence saved under /var/ir/evidence211"
'@

Invoke-DigitalTwinCommand -HostId "client" -StateId "State 3" -Label "is_knowledge_sufficient=true" -Command @'
mkdir -p /var/ir/evidence211 && \
ip addr > /var/ir/evidence211/ip_addr.txt && \
ip route > /var/ir/evidence211/ip_route.txt && \
ps aux > /var/ir/evidence211/processes.txt && \
cat /root/.ssh/known_hosts > /var/ir/evidence211/known_hosts.txt 2>/dev/null || true; \
cat /opt/passwords.txt > /var/ir/evidence211/password_list.txt 2>/dev/null || true; \
echo "[knowledge] client artifacts saved for reconstructing the attack source and credential context"
'@

Invoke-DigitalTwinCommand -HostId "client" -StateId "State 4" -Label "is_eradicated=true (client)" -Command @'
pkill -9 hydra 2>/dev/null || true; \
pkill -9 nmap 2>/dev/null || true; \
pkill -9 sshpass 2>/dev/null || true; \
pkill -9 ssh 2>/dev/null || true; \
rm -f /root/.ssh/known_hosts && \
echo "[eradicated] active attack tooling and SSH session residue removed from client"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 4" -Label "is_eradicated=true (server_ssh)" -Command @'
mkdir -p /home/admin/.ssh && \
rm -f /home/admin/.ssh/authorized_keys && \
rm -f /tmp/lateral_* /tmp/*.probe /tmp/*.payload 2>/dev/null || true; \
passwd -l root >/dev/null 2>&1 || true; \
passwd -l admin >/dev/null 2>&1 || true; \
echo "[eradicated] unauthorized SSH keys and obvious temporary artifacts removed from target server"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 5" -Label "is_hardened=true (server_ssh)" -Command @'
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.211_withouttechniques && \
if grep -q '^PermitRootLogin ' /etc/ssh/sshd_config; then sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config; else echo 'PermitRootLogin no' >> /etc/ssh/sshd_config; fi && \
if grep -q '^PasswordAuthentication ' /etc/ssh/sshd_config; then sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config; else echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config; fi && \
if grep -q '^MaxAuthTries ' /etc/ssh/sshd_config; then sed -i 's/^MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config; else echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config; fi && \
/usr/sbin/sshd -t && \
pkill sshd 2>/dev/null || true; \
/usr/sbin/sshd && \
echo "[hardened] SSH authentication policy strengthened on 10.0.2.11"
'@

Invoke-DigitalTwinCommand -HostId "gateway" -StateId "State 5" -Label "is_hardened=true (gateway)" -Command @'
iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.11 --dport 22 -j DROP && \
iptables -I FORWARD 1 -p tcp -s 10.0.2.11 -d 10.0.1.11 --sport 22 -j DROP && \
echo "[hardened] gateway blocks attacker SSH traffic to and from 10.0.2.11"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 6" -Label "is_recovered=true" -Command @'
/usr/sbin/sshd -t && \
ps aux | grep '[s]shd' && \
echo "[recovered] sshd remains running after recovery actions"
'@

Write-LogBlankLine
$OverallTimer.Stop()
Write-Utf8FileLine -Path $SummaryFile -Text ("TOTAL_TIME_MS | {0}" -f $OverallTimer.ElapsedMilliseconds)
Write-Utf8FileLine -Path $SummaryFile -Text ("TOTAL_TIME_SECONDS | {0:N3}" -f $OverallTimer.Elapsed.TotalSeconds)
Write-Log ("Total recovery execution time: {0} ms ({1:N3} seconds)" -f $OverallTimer.ElapsedMilliseconds, $OverallTimer.Elapsed.TotalSeconds)
Write-Log "Generated single-server recovery plan completed: without techniques"
Write-Log "Summary:"
Get-Content $SummaryFile | ForEach-Object { Write-Log $_ }
