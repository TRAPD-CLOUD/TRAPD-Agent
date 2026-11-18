# T1 (WP2): a copied credentials.json must be useless AND the identity key must
# not be exportable from the TPM / key store, even for an administrator.
# Safe: read-only probes, nothing is created or modified. Run elevated on a
# Windows host with a bound agent.
$ErrorActionPreference = 'Continue'
if ($env:TRAPD_ADVERSARIAL_OK -ne '1') { Write-Host 'refusing: set TRAPD_ADVERSARIAL_OK=1'; exit 2 }
$keyName = 'TRAPD-Agent-Identity'
$fail = 0
$probed = 0   # private-export attempts that were really made

# 1. credentials.json carries no secret once bound.
$creds = Join-Path $env:ProgramData 'TRAPD\state\credentials.json'
if (-not (Test-Path $creds)) { $creds = Join-Path $env:ProgramData 'TRAPD\credentials.json' }
if (Test-Path $creds) {
    $j = Get-Content $creds -Raw | ConvertFrom-Json
    if ($j.agent_secret) { Write-Host 'FAIL: credentials.json still holds agent_secret'; $fail++ }
    else { Write-Host 'PASS: credentials.json holds no bearer secret' }
} else { Write-Host 'FAIL: credentials.json not found, the host has no bound agent to test'; $fail++ }

# 2. certutil export attempt against both providers.
foreach ($csp in 'Microsoft Platform Crypto Provider', 'Microsoft Software Key Storage Provider') {
    $out = & certutil -csp $csp -key 2>&1 | Out-String
    if ($out -notmatch [regex]::Escape($keyName)) { continue }   # key lives in the other provider
    $tmp = Join-Path $env:TEMP 'trapd-t1-export.pfx'
    $exp = & certutil -csp $csp -exportPFX -p 'x' $keyName $tmp 2>&1 | Out-String
    $probed++
    if (Test-Path $tmp) { Remove-Item $tmp -Force; Write-Host "FAIL: key exported from '$csp'"; $fail++ }
    else { Write-Host "PASS: certutil could not export the key from '$csp'" }
}

# 3. .NET / CNG export attempt (machine key).
Add-Type -AssemblyName System.Security
foreach ($prov in 'Microsoft Platform Crypto Provider', 'Microsoft Software Key Storage Provider') {
    try {
        $p = [System.Security.Cryptography.CngProvider]::new($prov)
        $opts = [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey
        if (-not [System.Security.Cryptography.CngKey]::Exists($keyName, $p, $opts)) { continue }
        $k = [System.Security.Cryptography.CngKey]::Open($keyName, $p, $opts)
        $probed++
        try {
            $blob = $k.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob)
            Write-Host "FAIL: private blob exported from '$prov' ($($blob.Length) bytes)"; $fail++
        } catch { Write-Host "PASS: private export refused by '$prov' ($($_.Exception.InnerException.Message))" }
        finally { $k.Dispose() }
    } catch { Write-Host "NOTE: '$prov' not usable here: $($_.Exception.Message)" }
}

# A probe that never ran proves nothing: no key found, or no provider usable.
if ($probed -eq 0) { Write-Host "FAIL: no export attempt was made (identity key '$keyName' not found in any provider)"; $fail++ }

if ($fail -eq 0) { Write-Host 'RESULT: PASS'; exit 0 } else { Write-Host 'RESULT: FAIL'; exit 1 }
