# #438: what the machine does while the native browser tests run. Evidence only: it changes
# nothing and fails nothing. Every 10 s for 20 minutes, the busiest processes by CPU, the services
# in a busy svchost, free memory, and process names not seen before. Names and numbers only.
param([Parameter(Mandatory = $true)][string]$Log)
$clock = [Diagnostics.Stopwatch]::StartNew()
$last = @{}
$known = @{}
while ($clock.Elapsed.TotalMinutes -lt 20) {
  $rows = @()
  $fresh = @()
  foreach ($p in Get-Process) {
    $cpu = 0.0
    try { $cpu = $p.TotalProcessorTime.TotalSeconds } catch {}
    if ($last.ContainsKey($p.Id)) { $rows += [pscustomobject]@{ n = $p.ProcessName; d = $cpu - $last[$p.Id]; i = $p.Id } }
    $last[$p.Id] = $cpu
    if (-not $known.ContainsKey($p.ProcessName)) { $known[$p.ProcessName] = $true; $fresh += $p.ProcessName }
  }
  $top = ($rows | Sort-Object d -Descending | Select-Object -First 6 | ForEach-Object { "{0}={1:n1}" -f $_.n, $_.d }) -join " "
  $os = Get-CimInstance Win32_OperatingSystem
  $line = "{0} free {1}MB top {2}" -f (Get-Date).ToUniversalTime().ToString("HH:mm:ss"), [int]($os.FreePhysicalMemory / 1024), $top
  foreach ($busy in ($rows | Where-Object { $_.n -eq "svchost" -and $_.d -ge 4 })) {
    $services = (Get-CimInstance Win32_Service -Filter "ProcessId=$($busy.i)" | ForEach-Object Name) -join "+"
    $line += " svc[$services]"
  }
  if ($fresh -and $clock.Elapsed.TotalSeconds -gt 15) { $line += " new " + ($fresh -join ",") }
  Add-Content $Log $line
  Start-Sleep -Seconds 10
}
