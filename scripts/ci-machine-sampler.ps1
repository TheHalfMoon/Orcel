# #438: what the machine does while the native browser tests run. Evidence only: it changes
# nothing and fails nothing. Every 10 s for 20 minutes, the busiest processes by CPU, the services
# in a busy svchost, free memory, each disk's latency and queue over the sample, and process names
# not seen before. Names and numbers only. At most three CIM queries a sample, each cut off after
# 5 s; a part that fails is left out of its line.
param([Parameter(Mandatory = $true)][string]$Log)
$clock = [Diagnostics.Stopwatch]::StartNew()
$last = @{}
$known = @{}
$disks = @{}

# The average of a PERF_AVERAGE_TIMER between two raw readings, in ms, and how many operations it
# covers. The raw counters are 32 bits and wrap.
function Get-Latency($before, $after, [string]$name) {
  $ticks = [long]$after.$name - [long]$before.$name
  $count = [long]$after."${name}_Base" - [long]$before."${name}_Base"
  if ($ticks -lt 0) { $ticks += 4294967296 }
  if ($count -lt 0) { $count += 4294967296 }
  $ms = if ($count -gt 0) { 1000.0 * $ticks / $after.Frequency_PerfTime / $count } else { 0.0 }
  "{0:n1}ms/{1}" -f $ms, $count
}
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
  $free = "?"
  try { $free = [int]((Get-CimInstance Win32_OperatingSystem -Property FreePhysicalMemory -OperationTimeoutSec 5 -ErrorAction Stop).FreePhysicalMemory / 1024) } catch {}
  $line = "{0} free {1}MB top {2}" -f (Get-Date).ToUniversalTime().ToString("HH:mm:ss"), $free, $top
  # From 0.8 CPU-seconds a sample: a disk-bound service uses little CPU. One query for all of them.
  $busy = @($rows | Where-Object { $_.n -eq "svchost" -and $_.d -ge 0.8 } | Sort-Object d -Descending | Select-Object -First 6)
  if ($busy.Count -gt 0) {
    try {
      $filter = ($busy | ForEach-Object { "ProcessId=$($_.i)" }) -join " OR "
      $services = Get-CimInstance Win32_Service -Filter $filter -Property Name, ProcessId -OperationTimeoutSec 5 -ErrorAction Stop
      foreach ($b in $busy) {
        $names = ($services | Where-Object ProcessId -eq $b.i | ForEach-Object Name) -join "+"
        $line += " svc[{0}={1:n1}]" -f $names, $b.d
      }
    } catch {}
  }
  # Raw counters, so each figure is the whole sample's: latency and operations for reads and writes,
  # the average queue, and the queue now.
  try {
    foreach ($disk in Get-CimInstance Win32_PerfRawData_PerfDisk_PhysicalDisk -OperationTimeoutSec 5 -ErrorAction Stop) {
      if ($disk.Name -eq "_Total") { continue }
      $before = $disks[$disk.Name]
      $disks[$disk.Name] = $disk
      if (-not $before) { continue }
      $span = [double]($disk.Timestamp_Sys100NS - $before.Timestamp_Sys100NS)
      if ($span -le 0) { continue }
      $queue = ([double]$disk.AvgDiskQueueLength - [double]$before.AvgDiskQueueLength) / $span
      $line += " disk[{0} r {1} w {2} q {3:n2} now {4}]" -f $disk.Name, (Get-Latency $before $disk "AvgDisksecPerRead"), (Get-Latency $before $disk "AvgDisksecPerWrite"), $queue, $disk.CurrentDiskQueueLength
    }
  } catch {}
  if ($fresh -and $clock.Elapsed.TotalSeconds -gt 15) { $line += " new " + ($fresh -join ",") }
  Add-Content $Log $line
  Start-Sleep -Seconds 10
}
