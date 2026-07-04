Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = Join-Path $Root "artifacts\recovery_state_verification"
$LogFile = Join-Path $LogDir "verify_recovery_state211_$Timestamp.log"
$SummaryFile = Join-Path $LogDir "verify_recovery_state211_$Timestamp.summary.txt"
$JsonFile = Join-Path $LogDir "verify_recovery_state211_$Timestamp.json"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType File -Force -Path $LogFile | Out-Null
Set-Content -Path $LogFile -Value $null -Encoding UTF8
New-Item -ItemType File -Force -Path $SummaryFile | Out-Null
Set-Content -Path $SummaryFile -Value $null -Encoding UTF8

$script:StateResults = @()

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
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $normalizedCommand = ($Command -replace "`r`n", "`n") -replace "`r", ""
        $output = $normalizedCommand | docker exec -i $container /bin/sh 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
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
    $script:StateResults += [PSCustomObject]@{
        state_key = $StateKey
        target = "10.0.2.11"
        host_id = "server_ssh"
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

Write-Log "Single-server recovery state verification started"
Write-Log "Target server: 10.0.2.11 (server_ssh)"
Write-Log "Log file: $LogFile"
Write-Log "Summary file: $SummaryFile"
Write-Log "JSON file: $JsonFile"

# State 1: is_attack_contained
$s1a = Invoke-ContainerCommand -HostId "gateway" -Command 'iptables -S FORWARD | grep 10.0.1.11'
$s1b = Invoke-ContainerCommand -HostId "client" -Command 'ping -c 1 -W 1 10.0.2.11 >/dev/null 2>&1; echo $?'
$s1Passed = ($s1a.ExitCode -eq 0) -and ($s1a.Output -match '10\.0\.1\.11') -and ($s1b.Output.Trim() -ne '0')
Add-StateResult -StateKey "is_attack_contained" `
    -Meaning "Attacker 10.0.1.11 is isolated from target server 10.0.2.11." `
    -Passed $s1Passed `
    -Checks @(
        "Gateway FORWARD chain contains blocking rules referencing attacker 10.0.1.11.",
        "Client can no longer ping server_ssh at 10.0.2.11."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "gateway"; exit_code = $s1a.ExitCode; output = $s1a.Output },
        [PSCustomObject]@{ host = "client"; exit_code = $s1b.ExitCode; output = $s1b.Output }
    )

# State 2: is_knowledge_sufficient
$s2a = Invoke-ContainerCommand -HostId "client" -Command 'for d in /var/ir/evidence211 /var/ir/evidence211faith; do test -s "$d/password_list.txt" && test -f "$d/ip_addr.txt" && echo OK:$d && exit 0; done; exit 1'
$s2b = Invoke-ContainerCommand -HostId "server_ssh" -Command 'for d in /var/ir/evidence211 /var/ir/evidence211faith; do test -s "$d/passwd.txt" && test -f "$d/home_admin.txt" && test -f "$d/sshd_config.before" && echo OK:$d && exit 0; done; exit 1'
$s2c = Invoke-ContainerCommand -HostId "gateway" -Command 'for d in /var/ir/evidence211 /var/ir/evidence211faith; do test -f "$d/snort.alert" && test -f "$d/iptables.rules" && echo OK:$d && exit 0; done; exit 1'
$s2Passed = ($s2a.Output -match 'OK') -and ($s2b.Output -match 'OK') -and ($s2c.Output -match 'OK')
Add-StateResult -StateKey "is_knowledge_sufficient" `
    -Meaning "Enough client, gateway, and server_ssh artifacts exist to reconstruct the 10.0.2.11 attack path." `
    -Passed $s2Passed `
    -Checks @(
        "Client-side evidence exists for attacker tooling and credential context.",
        "server_ssh evidence exists for account, home-directory, and SSH configuration context.",
        "Gateway evidence exists for alert and filtering context."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "client"; exit_code = $s2a.ExitCode; output = $s2a.Output },
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s2b.ExitCode; output = $s2b.Output },
        [PSCustomObject]@{ host = "gateway"; exit_code = $s2c.ExitCode; output = $s2c.Output }
    )

# State 3: are_forensics_preserved
$s3a = Invoke-ContainerCommand -HostId "gateway" -Command 'for d in /var/ir/evidence211 /var/ir/evidence211faith; do test -f "$d/snort.alert" && test -s "$d/iptables.rules" && echo OK:$d && exit 0; done; exit 1'
$s3b = Invoke-ContainerCommand -HostId "server_ssh" -Command 'for d in /var/ir/evidence211 /var/ir/evidence211faith; do test -f "$d/auth.log" && test -s "$d/passwd.txt" && test -s "$d/sshd_config.before" && echo OK:$d && exit 0; done; exit 1'
$s3c = Invoke-ContainerCommand -HostId "server_ssh" -Command 'for d in /var/ir/evidence211 /var/ir/evidence211faith; do test -f "$d/processes.txt" && test -f "$d/ip_route.txt" && echo OK:$d && exit 0; done; exit 1'
$s3Passed = ($s3a.Output -match 'OK') -and ($s3b.Output -match 'OK') -and ($s3c.Output -match 'OK')
Add-StateResult -StateKey "are_forensics_preserved" `
    -Meaning "Target-specific network, SSH, and host artifacts have been copied into evidence locations." `
    -Passed $s3Passed `
    -Checks @(
        "Gateway Snort alerts and firewall state are preserved for the target scenario.",
        "server_ssh auth, account, and SSH configuration artifacts are preserved.",
        "server_ssh process and routing context are preserved."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "gateway"; exit_code = $s3a.ExitCode; output = $s3a.Output },
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s3b.ExitCode; output = $s3b.Output },
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s3c.ExitCode; output = $s3c.Output }
    )

# State 4: is_eradicated
$s4a = Invoke-ContainerCommand -HostId "client" -Command "ps aux | egrep 'hydra|nmap|sshpass' | grep -v grep || true"
$s4b = Invoke-ContainerCommand -HostId "server_ssh" -Command 'test ! -s /home/admin/.ssh/authorized_keys && echo OK'
$s4Passed = [string]::IsNullOrWhiteSpace($s4a.Output) -and ($s4b.Output -match 'OK')
Add-StateResult -StateKey "is_eradicated" `
    -Meaning "Observed SSH attack tooling and unauthorized SSH trust material are absent for the 10.0.2.11 scenario." `
    -Passed $s4Passed `
    -Checks @(
        "No hydra, nmap, or sshpass processes remain on the client container.",
        "server_ssh has no non-empty admin authorized_keys file."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "client"; exit_code = $s4a.ExitCode; output = if ($s4a.Output) { $s4a.Output } else { "<no matching processes>" } },
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s4b.ExitCode; output = $s4b.Output }
    )

# State 5: is_hardened
$s5a = Invoke-ContainerCommand -HostId "server_ssh" -Command "grep -E '^[[:space:]]*(PermitRootLogin no|PasswordAuthentication no|MaxAuthTries 3)[[:space:]]*$' /etc/ssh/sshd_config"
$s5b = Invoke-ContainerCommand -HostId "gateway" -Command "iptables -S FORWARD | grep 10.0.1.11"
$s5Passed = ($s5a.Output -match 'PermitRootLogin no') -and `
    ($s5a.Output -match 'PasswordAuthentication no') -and `
    ($s5a.Output -match 'MaxAuthTries 3') -and `
    ($s5b.Output -match '10\.0\.1\.11') -and `
    (($s5b.Output -match '10\.0\.2\.11') -or ($s5b.Output -match 'DROP'))
Add-StateResult -StateKey "is_hardened" `
    -Meaning "The SSH attack path to 10.0.2.11 is restricted by stronger SSH configuration and gateway filtering." `
    -Passed $s5Passed `
    -Checks @(
        "server_ssh disables root login, password authentication, and excessive authentication attempts.",
        "Gateway filter rules exist for attacker-specific SSH access to 10.0.2.11."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s5a.ExitCode; output = $s5a.Output },
        [PSCustomObject]@{ host = "gateway"; exit_code = $s5b.ExitCode; output = $s5b.Output }
    )

# State 6: is_recovered
$s6a = Invoke-ContainerCommand -HostId "gateway" -Command 'iptables -S FORWARD >/dev/null 2>&1 && echo OK'
$s6b = Invoke-ContainerCommand -HostId "server_ssh" -Command '/usr/sbin/sshd -t >/dev/null 2>&1 && echo OK'
$s6c = Invoke-ContainerCommand -HostId "server_ssh" -Command "ps aux | grep '[s]shd'"
$s6Passed = ($s6a.Output -match 'OK') -and ($s6b.Output -match 'OK') -and -not [string]::IsNullOrWhiteSpace($s6c.Output)
Add-StateResult -StateKey "is_recovered" `
    -Meaning "The target SSH service remains valid and running after single-server recovery actions." `
    -Passed $s6Passed `
    -Checks @(
        "Gateway forwarding configuration remains readable after recovery actions.",
        "server_ssh SSH daemon configuration validates successfully.",
        "sshd is running on server_ssh."
    ) `
    -Evidence @(
        [PSCustomObject]@{ host = "gateway"; exit_code = $s6a.ExitCode; output = $s6a.Output },
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s6b.ExitCode; output = $s6b.Output },
        [PSCustomObject]@{ host = "server_ssh"; exit_code = $s6c.ExitCode; output = $s6c.Output }
    )

$overall = @($script:StateResults | Where-Object { -not $_.passed }).Count -eq 0
$json = [PSCustomObject]@{
    generated_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    target = "10.0.2.11"
    host_id = "server_ssh"
    overall_passed = $overall
    states = $script:StateResults
}
$json | ConvertTo-Json -Depth 8 | Set-Content -Path $JsonFile -Encoding UTF8

Write-LogBlankLine
Write-Log ("Overall result: {0}" -f $(if ($overall) { "PASS" } else { "FAIL" }))
Write-Log "Single-server recovery state verification completed"
