Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = Join-Path $Root "artifacts\generated_recovery_logs"
$LogFile = Join-Path $LogDir "generated_recovery_211_faithtechniques_$Timestamp.log"
$SummaryFile = Join-Path $LogDir "generated_recovery_211_faithtechniques_$Timestamp.summary.txt"
$OverallTimer = [System.Diagnostics.Stopwatch]::StartNew()
$HadFailure = $false

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
        [AllowEmptyString()]
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

function Write-Summary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status,
        [Parameter(Mandatory = $true)]
        [string]$StateId,
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    Write-Utf8FileLine -Path $SummaryFile -Text ("{0} | {1} | {2} | {3}" -f $Status, $StateId, $Scope, $Label)
}

function Invoke-HostCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StateId,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Script
    )

    Write-LogBlankLine
    Write-Log "=== [host] $StateId | $Label ==="
    Write-Log "Command:"
    Write-Log $Script.ToString()

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Script 2>&1
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) {
            $exitCode = 0
        }
        if ($output) {
            foreach ($line in $output) {
                Write-Log $line.ToString()
            }
        }
        Write-Log "ExitCode: $exitCode"
        if ($exitCode -eq 0) {
            Write-Summary -Status "PASS" -StateId $StateId -Scope "host" -Label $Label
        }
        else {
            $script:HadFailure = $true
            Write-Summary -Status "FAIL" -StateId $StateId -Scope "host" -Label $Label
        }
    }
    catch {
        $script:HadFailure = $true
        Write-Log "ERROR: $($_.Exception.Message)"
        Write-Summary -Status "FAIL" -StateId $StateId -Scope "host" -Label $Label
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
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

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $normalizedCommand = ($Command -replace "`r`n", "`n") -replace "`r", ""
        $output = $normalizedCommand | docker exec -i $container /bin/sh 2>&1
        $exitCode = $LASTEXITCODE
        if ($output) {
            foreach ($line in $output) {
                Write-Log $line.ToString()
            }
        }
        Write-Log "ExitCode: $exitCode"
        if ($exitCode -eq 0) {
            Write-Summary -Status "PASS" -StateId $StateId -Scope $HostId -Label $Label
        }
        else {
            $script:HadFailure = $true
            Write-Summary -Status "FAIL" -StateId $StateId -Scope $HostId -Label $Label
        }
    }
    catch {
        $script:HadFailure = $true
        Write-Log "ERROR: $($_.Exception.Message)"
        Write-Summary -Status "FAIL" -StateId $StateId -Scope $HostId -Label $Label
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Add-UnsupportedAction {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StateId,
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    Write-LogBlankLine
    Write-Log "=== [$Scope] $StateId | $Label ==="
    Write-Log "UNSUPPORTED: $Reason"
    Write-Summary -Status "UNSUPPORTED" -StateId $StateId -Scope $Scope -Label $Label
}

Write-Log "Generated single-server recovery plan started: faithful techniques"
Write-Log "Target server: 10.0.2.11 (server_ssh)"
Write-Log "Mode: faithful to high-level technique-aware recovery actions; unsupported DT NEW actions are logged and execution continues"
Write-Log "Log file: $LogFile"
Write-Log "Summary file: $SummaryFile"

Invoke-DigitalTwinCommand -HostId "gateway" -StateId "State 1" -Label "block all attacker traffic at gateway firewall" -Command @'
iptables -I FORWARD 1 -s 10.0.1.11 -j DROP && \
iptables -I FORWARD 1 -d 10.0.1.11 -j DROP && \
iptables -I INPUT 1 -s 10.0.1.11 -j DROP && \
iptables -I OUTPUT 1 -d 10.0.1.11 -j DROP && \
echo "[contained] all observed traffic to/from attacker 10.0.1.11 blocked at gateway"
'@

Invoke-HostCommand -StateId "State 1" -Label "move 10.0.2.11 to quarantine VLAN equivalent" -Script {
    docker network inspect llm_ir_dt_net_quarantine_211 *> $null
    if ($LASTEXITCODE -ne 0) {
        docker network create --driver bridge --subnet 10.0.99.0/24 llm_ir_dt_net_quarantine_211
    }
    docker network connect --ip 10.0.99.11 llm_ir_dt_net_quarantine_211 llm_ir_dt_server_ssh
    docker network disconnect llm_ir_dt_net_server_net llm_ir_dt_server_ssh
}

Invoke-DigitalTwinCommand -HostId "gateway" -StateId "State 2" -Label "export Snort and gateway logs to evidence storage" -Command @'
mkdir -p /var/ir/evidence211faith && \
cp /var/log/snort/alert /var/ir/evidence211faith/snort.alert 2>/dev/null || true; \
iptables-save > /var/ir/evidence211faith/iptables.rules && \
ip addr > /var/ir/evidence211faith/ip_addr.txt && \
ip route > /var/ir/evidence211faith/ip_route.txt && \
ps aux > /var/ir/evidence211faith/processes.txt && \
chmod -R a-w /var/ir/evidence211faith && \
echo "[forensics] gateway evidence exported and marked read-only"
'@

Invoke-DigitalTwinCommand -HostId "client" -StateId "State 2" -Label "export attacker-side context for timeline reconstruction" -Command @'
mkdir -p /var/ir/evidence211faith && \
ip addr > /var/ir/evidence211faith/ip_addr.txt && \
ip route > /var/ir/evidence211faith/ip_route.txt && \
ps aux > /var/ir/evidence211faith/processes.txt && \
cat /root/.ssh/known_hosts > /var/ir/evidence211faith/known_hosts.txt 2>/dev/null || true; \
cat /opt/passwords.txt > /var/ir/evidence211faith/password_list.txt 2>/dev/null || true; \
chmod -R a-w /var/ir/evidence211faith && \
echo "[forensics] attacker-side context exported and marked read-only"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 2" -Label "acquire target server disk image approximation and SSH logs" -Command @'
mkdir -p /var/ir/evidence211faith && \
ip addr > /var/ir/evidence211faith/ip_addr.txt && \
ip route > /var/ir/evidence211faith/ip_route.txt && \
ps aux > /var/ir/evidence211faith/processes.txt && \
cp /etc/passwd /var/ir/evidence211faith/passwd.txt && \
cat /etc/shadow > /var/ir/evidence211faith/shadow.txt 2>/dev/null || true; \
cat /var/log/auth.log > /var/ir/evidence211faith/auth.log 2>/dev/null || true; \
cp /etc/ssh/sshd_config /var/ir/evidence211faith/sshd_config.before && \
ls -la /home/admin > /var/ir/evidence211faith/home_admin.txt 2>/dev/null || true; \
tar --one-file-system --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run --exclude=/var/ir -czf /var/ir/evidence211faith/rootfs_image.tar.gz / 2>/var/ir/evidence211faith/rootfs_image.stderr || true; \
chmod -R a-w /var/ir/evidence211faith && \
echo "[forensics] target disk-image approximation and SSH artifacts exported"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 2" -Label "acquire target server memory image" -Command @'
mkdir -p /var/ir/evidence211faith 2>/dev/null || true; \
if command -v lime >/dev/null 2>&1; then \
  lime "path=/var/ir/evidence211faith/memory.lime format=lime"; \
elif command -v makedumpfile >/dev/null 2>&1; then \
  makedumpfile -d 31 /proc/vmcore /var/ir/evidence211faith/memory.dump; \
else \
  echo "memory imaging tool not available in DT NEW server_ssh container" > /var/ir/evidence211faith/memory_image.unsupported.txt; \
  exit 2; \
fi
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 2" -Label "export web logs from prioritized server" -Command @'
mkdir -p /var/ir/evidence211faith 2>/dev/null || true; \
cat /var/log/apache2/access.log > /var/ir/evidence211faith/apache_access.log 2>/dev/null || true; \
cat /var/log/apache2/error.log > /var/ir/evidence211faith/apache_error.log 2>/dev/null || true; \
cat /var/log/nginx/access.log > /var/ir/evidence211faith/nginx_access.log 2>/dev/null || true; \
cat /var/log/nginx/error.log > /var/ir/evidence211faith/nginx_error.log 2>/dev/null || true; \
test -s /var/ir/evidence211faith/apache_access.log -o -s /var/ir/evidence211faith/nginx_access.log
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 3" -Label "reset local credentials and revoke SSH keys" -Command @'
mkdir -p /home/admin/.ssh && \
rm -f /home/admin/.ssh/authorized_keys && \
passwd -l root >/dev/null 2>&1 || true; \
passwd -l admin >/dev/null 2>&1 || true; \
echo "[eradication] local credentials locked and SSH keys revoked on 10.0.2.11"
'@

Add-UnsupportedAction -StateId "State 3" -Scope "server_ssh" -Label "reset domain credentials" -Reason "DT NEW has no domain controller, directory service, or domain credential store."

Invoke-HostCommand -StateId "State 3" -Label "rebuild server_ssh image from clean image" -Script {
    Push-Location $Root
    docker compose build server_ssh
    Pop-Location
}

Add-UnsupportedAction -StateId "State 3" -Scope "host" -Label "selectively redeploy 10.0.2.11 from clean patched image" -Reason "The current project provides full-lab start/stop/recovery entrypoints, but no safe single-host redeploy workflow that preserves the rest of the running topology."

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 4" -Label "apply OS and SSH service patches" -Command @'
if command -v timeout >/dev/null 2>&1; then \
  timeout 30 sh -c "apt-get update && apt-get install -y --only-upgrade openssh-server"; \
else \
  apt-get update && apt-get install -y --only-upgrade openssh-server; \
fi
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 4" -Label "disable unnecessary services and enforce SSH key-based authentication" -Command @'
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.211_faithtechniques && \
if grep -q '^PermitRootLogin ' /etc/ssh/sshd_config; then sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config; else echo 'PermitRootLogin no' >> /etc/ssh/sshd_config; fi && \
if grep -q '^PasswordAuthentication ' /etc/ssh/sshd_config; then sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config; else echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config; fi && \
if grep -q '^PubkeyAuthentication ' /etc/ssh/sshd_config; then sed -i 's/^PubkeyAuthentication .*/PubkeyAuthentication yes/' /etc/ssh/sshd_config; else echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config; fi && \
if grep -q '^MaxAuthTries ' /etc/ssh/sshd_config; then sed -i 's/^MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config; else echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config; fi && \
/usr/sbin/sshd -t && \
pkill sshd 2>/dev/null || true; \
/usr/sbin/sshd && \
echo "[hardened] SSH key-based authentication enforced and sshd restarted"
'@

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 4" -Label "deploy fail2ban protection" -Command @'
if command -v fail2ban-client >/dev/null 2>&1; then \
  fail2ban-client status sshd || fail2ban-client start; \
else \
  echo "fail2ban is not installed in DT NEW server_ssh container"; \
  exit 2; \
fi
'@

Invoke-DigitalTwinCommand -HostId "gateway" -StateId "State 4" -Label "enforce gateway SSH brute-force filtering" -Command @'
iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.11 --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSHBF211FAITH && \
iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.11 --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 5 --name SSHBF211FAITH -j DROP && \
iptables -I FORWARD 1 -p tcp -s 10.0.1.11 -d 10.0.2.11 --dport 22 -j DROP && \
echo "[hardened] gateway SSH brute-force filtering deployed for 10.0.2.11"
'@

Invoke-HostCommand -StateId "State 4" -Label "restore target server services to production network" -Script {
    docker network connect --ip 10.0.2.11 llm_ir_dt_net_server_net llm_ir_dt_server_ssh
    docker network disconnect llm_ir_dt_net_quarantine_211 llm_ir_dt_server_ssh
}

Invoke-DigitalTwinCommand -HostId "server_ssh" -StateId "State 4" -Label "validate restored SSH service" -Command @'
/usr/sbin/sshd -t && \
ps aux | grep '[s]shd' && \
echo "[recovered] required SSH service is running after faithful recovery actions"
'@

Write-LogBlankLine
$OverallTimer.Stop()
Write-Utf8FileLine -Path $SummaryFile -Text ("TOTAL_TIME_MS | {0}" -f $OverallTimer.ElapsedMilliseconds)
Write-Utf8FileLine -Path $SummaryFile -Text ("TOTAL_TIME_SECONDS | {0:N3}" -f $OverallTimer.Elapsed.TotalSeconds)
Write-Utf8FileLine -Path $SummaryFile -Text ("OVERALL_STATUS | {0}" -f $(if ($HadFailure) { "COMPLETED_WITH_FAILURES" } else { "COMPLETED" }))
Write-Log ("Total recovery execution time: {0} ms ({1:N3} seconds)" -f $OverallTimer.ElapsedMilliseconds, $OverallTimer.Elapsed.TotalSeconds)
Write-Log ("Generated faithful single-server recovery plan completed with status: {0}" -f $(if ($HadFailure) { "COMPLETED_WITH_FAILURES" } else { "COMPLETED" }))
Write-Log "Summary:"
Get-Content $SummaryFile | ForEach-Object { Write-Log $_ }
