Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = Join-Path $Root "artifacts\recovery_state_verification"
$LogFile = Join-Path $LogDir "verify_recovery_state_$Timestamp.log"
$SummaryFile = Join-Path $LogDir "verify_recovery_state_$Timestamp.summary.txt"
$JsonFile = Join-Path $LogDir "verify_recovery_state_$Timestamp.json"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

New-Item -ItemType File -Force -Path $LogFile | Out-Null
Set-Content -Path $LogFile -Value $null -Encoding UTF8
New-Item -ItemType File -Force -Path $SummaryFile | Out-Null
Set-Content -Path $SummaryFile -Value $null -Encoding UTF8

$StateResults = @()

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

function Invoke-ContainerCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostId,
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $container = "llm_ir_dt_$HostId"
    $output = docker exec $container /bin/sh -c $Command 2>&1
    $exitCode = $LASTEXITCODE
    return [PSCustomObject]@{
        HostId = $HostId
        Command = $Command
        ExitCode = $exitCode
        Output = ($output -join "`n")
    }
}

function Add-StateResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StateKey,
        [Parameter(Mandatory = $true)]
        [string]$Meaning,
        [Parameter(Mandatory = $true)]
        [bool]$Passed,
        [Parameter(Mandatory = $true)]
        [string[]]$Checks,
        [Parameter(Mandatory = $true)]
        [object[]]$Evidence
    )

    $status = if ($Passed) { "PASS" } else { "FAIL" }
    $StateResults += [PSCustomObject]@{
        state_key = $StateKey
        meaning = $Meaning
        passed = $Passed
        checks = $Checks
        evidence = $Evidence
    }

    Write-Utf8FileLine -Path $SummaryFile -Text ("{0} | {1} | {2}" -f $status, $StateKey, $Meaning)
    Write-LogBlankLine
    Write-Log ("[{0}] {1} - {2}" -f $status, $StateKey, $Meaning)
    foreach ($check in $Checks) {
        Write-Log ("check: {0}" -f $check)
    }
    foreach ($item in $Evidence) {
        Write-Log ("evidence[{0}] exit={1}" -f $item.host, $item.exit_code)
        if ($item.output) {
            foreach ($line in ($item.output -split "`r?`n")) {
                if ($line -ne "") {
                    Write-Log ("  {0}" -f $line)
                }
            }
        }
    }
}

Write-Log "Recovery state verification started"
Write-Log "Log file: $LogFile"
Write-Log "Summary file: $SummaryFile"
Write-Log "JSON file: $JsonFile"

# State 1: is_attack_contained
$s1a = Invoke-ContainerCommand -HostId "gateway" -Command "iptables -S FORWARD | grep 10.0.1.11"
$s1b = Invoke-ContainerCommand -HostId "client" -Command "ping -c 1 -W 1 10.0.2.11 >/dev/null 2>&1; echo $?"
$s1Passed = ($s1a.ExitCode -eq 0) -and ($s1a.Output -match '10\.0\.1\.11') -and ($s1b.Output.Trim() -ne '0')
Add-StateResult -StateKey "is_attack_contained" `
    -Meaning "Attack source is isolated and no longer has normal reachability to protected targets." `
    -Passed $s1Passed `
    -Checks @(
        "Gateway FORWARD chain contains rules referencing attacker IP 10.0.1.11.",
        "Client can no longer ping server_ssh at 10.0.2.11."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "gateway"; exit_code = $s1a.ExitCode; output = $s1a.Output },
        [PSCustomObject]@{ host = "client"; exit_code = $s1b.ExitCode; output = $s1b.Output }
    )

# State 2: is_knowledge_sufficient
$s2a = Invoke-ContainerCommand -HostId "client" -Command "test -s /var/ir/evidence/password_list.txt && test -f /var/ir/evidence/ip_addr.txt && echo OK"
$s2b = Invoke-ContainerCommand -HostId "server_ssh" -Command "test -s /var/ir/evidence/passwd.txt && test -f /var/ir/evidence/home_admin.txt && echo OK"
$s2c = Invoke-ContainerCommand -HostId "server_shellshock" -Command "test -s /var/ir/evidence/apache_access.log && test -s /var/ir/evidence/cgi_file.sh && echo OK"
$s2Passed = ($s2a.Output -match 'OK') -and ($s2b.Output -match 'OK') -and ($s2c.Output -match 'OK')
Add-StateResult -StateKey "is_knowledge_sufficient" `
    -Meaning "Enough host and attack-context artifacts exist to reconstruct origin, targets, and attack path." `
    -Passed $s2Passed `
    -Checks @(
        "Client-side evidence exists for attacker tooling and network context.",
        "server_ssh evidence exists for account and host context.",
        "server_shellshock evidence exists for HTTP exploitation context."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "client"; exit_code = $s2a.ExitCode; output = $s2a.Output },
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s2b.ExitCode; output = $s2b.Output },
        [PSCustomObject]@{ host = "server_shellshock"; exit_code = $s2c.ExitCode; output = $s2c.Output }
    )

# State 3: are_forensics_preserved
$s3a = Invoke-ContainerCommand -HostId "gateway" -Command "test -s /var/ir/evidence/snort.alert && test -s /var/ir/evidence/iptables.rules && echo OK"
$s3b = Invoke-ContainerCommand -HostId "server_ssh" -Command "test -f /var/ir/evidence/auth.log && test -s /var/ir/evidence/passwd.txt && echo OK"
$s3c = Invoke-ContainerCommand -HostId "server_samba" -Command "test -f /var/ir/evidence/samba_logs_listing.txt && test -f /var/ir/evidence/samba_logs.txt && test -f /var/ir/evidence/share.tar.gz && echo OK"
$s3d = Invoke-ContainerCommand -HostId "server_shellshock" -Command "test -f /var/ir/evidence/apache_access.log && test -f /var/ir/evidence/apache_error.log && echo OK"
$s3Passed = ($s3a.Output -match 'OK') -and ($s3b.Output -match 'OK') -and ($s3c.Output -match 'OK') -and ($s3d.Output -match 'OK')
Add-StateResult -StateKey "are_forensics_preserved" `
    -Meaning "Key logs and artifacts have been copied into evidence locations for later analysis." `
    -Passed $s3Passed `
    -Checks @(
        "Gateway Snort alerts and firewall state are preserved.",
        "server_ssh host and auth artifacts are preserved.",
        "server_samba logs and share snapshot are preserved.",
        "server_shellshock web logs are preserved."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "gateway"; exit_code = $s3a.ExitCode; output = $s3a.Output },
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s3b.ExitCode; output = $s3b.Output },
        [PSCustomObject]@{ host = "server_samba"; exit_code = $s3c.ExitCode; output = $s3c.Output },
        [PSCustomObject]@{ host = "server_shellshock"; exit_code = $s3d.ExitCode; output = $s3d.Output }
    )

# State 4: is_eradicated
$s4a = Invoke-ContainerCommand -HostId "client" -Command "ps aux | egrep 'hydra|nmap|smbclient|sshpass' | grep -v grep || true"
$s4b = Invoke-ContainerCommand -HostId "server_samba" -Command "test ! -e /srv/share/evil_payload.txt && echo OK"
$s4Passed = [string]::IsNullOrWhiteSpace($s4a.Output) -and ($s4b.Output -match 'OK')
Add-StateResult -StateKey "is_eradicated" `
    -Meaning "Observed attacker tooling and dropped artifacts are removed from the affected lab hosts." `
    -Passed $s4Passed `
    -Checks @(
        "No attack-tool processes remain on the client container.",
        "Dropped Samba payload file is no longer present."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "client"; exit_code = $s4a.ExitCode; output = if ($s4a.Output) { $s4a.Output } else { "<no matching processes>" } },
        [PSCustomObject]@{ host = "server_samba"; exit_code = $s4b.ExitCode; output = $s4b.Output }
    )

# State 5: is_hardened
$s5a = Invoke-ContainerCommand -HostId "server_ssh" -Command "grep -E '^[[:space:]]*(PermitRootLogin no|PasswordAuthentication no|MaxAuthTries 3)[[:space:]]*$' /etc/ssh/sshd_config"
$s5b = Invoke-ContainerCommand -HostId "server_samba" -Command "grep -E '^[[:space:]]*(guest ok = no|read only = yes)[[:space:]]*$' /etc/samba/smb.conf"
$s5c = Invoke-ContainerCommand -HostId "server_shellshock" -Command "test ! -x /usr/lib/cgi-bin/vulnerable && echo OK"
$s5d = Invoke-ContainerCommand -HostId "gateway" -Command "iptables -S FORWARD | egrep '10.0.1.11|445|139|\\(\\) \\{' || true"
$s5Passed = ($s5a.Output -match 'PermitRootLogin no') -and `
    ($s5a.Output -match 'PasswordAuthentication no') -and `
    ($s5a.Output -match 'MaxAuthTries 3') -and `
    ($s5b.Output -match 'guest ok = no') -and `
    ($s5b.Output -match 'read only = yes') -and `
    ($s5c.Output -match 'OK') -and `
    ($s5d.Output -match '10\.0\.1\.11')
Add-StateResult -StateKey "is_hardened" `
    -Meaning "Compromised paths are restricted by stronger service configuration and gateway filtering." `
    -Passed $s5Passed `
    -Checks @(
        "server_ssh disables root login, password auth, and excessive auth attempts.",
        "server_samba disables anonymous writable share behavior.",
        "server_shellshock CGI path is no longer executable.",
        "Gateway filter rules exist for attacker-specific SSH/SMB/Shellshock controls."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s5a.ExitCode; output = $s5a.Output },
        [PSCustomObject]@{ host = "server_samba"; exit_code = $s5b.ExitCode; output = $s5b.Output },
        [PSCustomObject]@{ host = "server_shellshock"; exit_code = $s5c.ExitCode; output = $s5c.Output },
        [PSCustomObject]@{ host = "gateway"; exit_code = $s5d.ExitCode; output = $s5d.Output }
    )

# State 6: is_recovered
$s6a = Invoke-ContainerCommand -HostId "gateway" -Command "iptables -S FORWARD >/dev/null 2>&1 && echo OK"
$s6b = Invoke-ContainerCommand -HostId "server_ssh" -Command "ps aux | grep '[s]shd'"
$s6c = Invoke-ContainerCommand -HostId "server_samba" -Command "ps aux | grep '[s]mbd'"
$s6d = Invoke-ContainerCommand -HostId "server_shellshock" -Command "ps aux | grep '[a]pache'"
$s6e = Invoke-ContainerCommand -HostId "server_web1" -Command "ps aux | grep '[n]ginx'"
$s6f = Invoke-ContainerCommand -HostId "server_web2" -Command "ps aux | grep '[n]ginx'"
$s6Passed = ($s6a.Output -match 'OK') -and `
    -not [string]::IsNullOrWhiteSpace($s6b.Output) -and `
    -not [string]::IsNullOrWhiteSpace($s6c.Output) -and `
    -not [string]::IsNullOrWhiteSpace($s6d.Output) -and `
    -not [string]::IsNullOrWhiteSpace($s6e.Output) -and `
    -not [string]::IsNullOrWhiteSpace($s6f.Output)
Add-StateResult -StateKey "is_recovered" `
    -Meaning "Core services are running and main service hosts remain reachable after recovery actions." `
    -Passed $s6Passed `
    -Checks @(
        "Gateway forwarding configuration remains readable after recovery actions.",
        "sshd is running on server_ssh.",
        "smbd is running on server_samba.",
        "apache is running on server_shellshock.",
        "nginx is running on both normal web hosts."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "gateway"; exit_code = $s6a.ExitCode; output = $s6a.Output },
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s6b.ExitCode; output = $s6b.Output },
        [PSCustomObject]@{ host = "server_samba"; exit_code = $s6c.ExitCode; output = $s6c.Output },
        [PSCustomObject]@{ host = "server_shellshock"; exit_code = $s6d.ExitCode; output = $s6d.Output },
        [PSCustomObject]@{ host = "server_web1"; exit_code = $s6e.ExitCode; output = $s6e.Output },
        [PSCustomObject]@{ host = "server_web2"; exit_code = $s6f.ExitCode; output = $s6f.Output }
    )

$overall = @($StateResults | Where-Object { -not $_.passed }).Count -eq 0
$json = [PSCustomObject]@{
    generated_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    overall_passed = $overall
    states = $StateResults
}
$json | ConvertTo-Json -Depth 8 | Set-Content -Path $JsonFile -Encoding UTF8

Write-LogBlankLine
Write-Log ("Overall result: {0}" -f $(if ($overall) { "PASS" } else { "FAIL" }))
Write-Log "Recovery state verification completed"


