# More ground truth for `allymacb --carve`: one VHD per case, each with a shadow
# copy taken before the changes so the previous state of every rewritten $MFT
# and $I30 block survives in the diff area. Run as Administrator on a disposable
# Windows VM; see scripts/carve_lab.ps1 for the basic case and the output layout.
#
# Cases (each under C:\rf-carve\cases\<case>\ as deleted.vhd + truth.json):
#   names      Unicode, long (8.3 twin) and formula-looking names, hard links, an
#              ADS, timestomped files (1975, 1960, 2050), a 25-level directory
#              chain deleted whole, a file moved between directories, a deleted
#              directory whose record gets reused.
#   bigdir     600 files in one directory (multi-block $I30 B-tree); the first and
#              the last 100 in sort order deleted, 150 new files.
#   manyfiles  3,000 files in 50 directories so the $MFT grows past its first
#              extent; 25 directories deleted whole, 500 new files.
#   twoparts   two NTFS partitions in one VHD, deletions on both: parents must be
#              resolved against the right volume.
#   4k         (only if the Hyper-V module is present) a 4 KiB-sector VHD, which
#              gives 4 KiB FILE records.
$ErrorActionPreference = 'Stop'
$root = 'C:\rf-carve'
$cases = "$root\cases"
New-Item -ItemType Directory -Force $cases | Out-Null
$trimWas = (& fsutil behavior query DisableDeleteNotify) -join ' '
& fsutil behavior set DisableDeleteNotify 1 | Out-Null

function Run-Diskpart([string[]]$lines) {
    $script = "$root\dp.txt"
    Set-Content -Path $script -Value $lines -Encoding ASCII
    $out = & diskpart /s $script 2>&1
    if ($LASTEXITCODE -ne 0) { throw "diskpart failed: $out" }
    $out
}
function Make-File($path, $size) {
    $bytes = New-Object byte[] $size
    (New-Object Random ($path.GetHashCode())).NextBytes($bytes)
    [IO.File]::WriteAllBytes($path, $bytes)
}
function Snapshot-Tree([string[]]$letters, $label) {
    foreach ($l in $letters) {
        Get-ChildItem "${l}:\" -Recurse -Force | Where-Object { $_.FullName -notlike '*System Volume Information*' } | ForEach-Object {
            $id = $null
            if (-not $_.PSIsContainer) {
                $fi = & fsutil file queryfileid $_.FullName 2>$null
                if ($fi -match '0x([0-9a-f]+)') { $id = [Convert]::ToInt64($matches[1], 16) -band 0xFFFFFFFFFFFF }
            }
            [pscustomobject]@{
                stage = $label
                volume = $l
                path = $_.FullName.Substring(2)
                dir = $_.PSIsContainer
                size = $(if ($_.PSIsContainer) { 0 } else { $_.Length })
                created = $_.CreationTimeUtc.ToString('o')
                modified = $_.LastWriteTimeUtc.ToString('o')
                record = $id
            }
        }
    }
}
# Creates the VHD with one NTFS partition per letter (equal sizes).
function New-LabVolume($vhd, $sizeMB, [string[]]$letters) {
    $lines = @("create vdisk file=$vhd maximum=$sizeMB type=fixed", "select vdisk file=$vhd", "attach vdisk")
    $per = [int](($sizeMB - 2) / $letters.Count)
    foreach ($l in $letters) {
        $lines += "create partition primary size=$per"
        $lines += "format fs=ntfs quick label=LAB$l"
        $lines += "assign letter=$l"
    }
    Run-Diskpart $lines | Out-Null
    Start-Sleep -Seconds 2
    foreach ($l in $letters) { if (-not (Test-Path "${l}:\")) { throw "volume $l not mounted" } }
}
function Shadow([string[]]$letters) {
    $out = @()
    foreach ($l in $letters) { $out += (& vssadmin create shadow /for="${l}:" 2>&1) -join ' ' }
    Start-Sleep -Seconds 3
    $out -join ' | '
}
function Finish-Case($name, $vhd, [string[]]$letters, $pop, $after, $deleted, $modified, $renamed, $notes, $shadow) {
    Run-Diskpart @("select vdisk file=$vhd", "detach vdisk") | Out-Null
    $dir = "$cases\$name"
    New-Item -ItemType Directory -Force $dir | Out-Null
    Copy-Item $vhd "$dir\deleted.vhd" -Force
    @{
        case = $name
        host = $env:COMPUTERNAME
        created_utc = (Get-Date).ToUniversalTime().ToString('o')
        shadow = $shadow
        volumes = $letters
        populated = $pop
        after_changes = $after
        deleted = $deleted
        modified = $modified
        renamed = $renamed
        notes = $notes
    } | ConvertTo-Json -Depth 6 | Set-Content -Path "$dir\truth.json" -Encoding UTF8
    Remove-Item $vhd -Force
    "case $name done: $($pop.Count) entries before, $($after.Count) after"
}

# ============================================================ names
$vhd = "$root\names.vhd"
New-LabVolume $vhd 64 @('V')
$v = 'V:'
$u = {
    param($cps) ($cps | ForEach-Object { [char]::ConvertFromUtf32($_) }) -join ''
}
$nandu = 'informe ' + (& $u @(0xF1, 0x61, 0x6E, 0x64, 0xFA)) + ' ' + (& $u @(0xE1, 0x67, 0x69, 0x6C)) + '.txt'   # informe ñandú ágil.txt
$cjk = (& $u @(0x5831, 0x544A, 0x66F8)) + ' 2026.txt'                                                           # 報告書 2026.txt
$emoji = 'emoji ' + (& $u @(0x1F600)) + ' file.txt'
$long = 'a very long file name that definitely exceeds eight dot three.docx'
$formula = '=SUM(A1).txt'
$plus = '+evil.txt'
New-Item -ItemType Directory -Force "$v\docs", "$v\keep", "$v\moveme", "$v\gone_dir" | Out-Null
foreach ($n in @($nandu, $cjk, $emoji, $long, $formula, $plus)) { Make-File "$v\docs\$n" 777 }
Set-Content -Path "$v\docs\ads_host.txt" -Value 'host'
Set-Content -Path "$v\docs\ads_host.txt:secret" -Value 'hidden stream content'
Make-File "$v\docs\hl_original.txt" 999
& cmd /c mklink /H "$v\keep\hl_link.txt" "$v\docs\hl_original.txt" | Out-Null
Make-File "$v\docs\ts1975.txt" 100; (Get-Item "$v\docs\ts1975.txt").CreationTimeUtc = [datetime]::Parse('1975-06-15T12:00:00Z').ToUniversalTime()
Make-File "$v\docs\ts1960.txt" 100; (Get-Item "$v\docs\ts1960.txt").CreationTimeUtc = [datetime]::Parse('1960-02-29T00:00:00Z').ToUniversalTime()
Make-File "$v\docs\ts2050.txt" 100; (Get-Item "$v\docs\ts2050.txt").LastWriteTimeUtc = [datetime]::Parse('2050-01-01T00:00:00Z').ToUniversalTime()
$deep = "$v"
1..25 | ForEach-Object { $deep = "$deep\d{0:00}" -f $_ }
New-Item -ItemType Directory -Force $deep | Out-Null
Make-File "$deep\deep_file.txt" 321
Make-File "$v\moveme\moved.txt" 456
1..3 | ForEach-Object { Make-File "$v\gone_dir\g$_.txt" 200 }
Start-Sleep -Seconds 2
$pop = @(Snapshot-Tree @('V') 'populated')
$shadow = Shadow @('V')
Start-Sleep -Seconds 4
Remove-Item -Force "$v\docs\$cjk", "$v\docs\$long", "$v\docs\ads_host.txt", "$v\docs\hl_original.txt", "$v\docs\ts1975.txt", "$v\docs\ts1960.txt", "$v\docs\ts2050.txt"
Remove-Item -Recurse -Force "$v\d01", "$v\gone_dir"
Move-Item "$v\moveme\moved.txt" "$v\keep\moved.txt"
Start-Sleep -Seconds 2
New-Item -ItemType Directory -Force "$v\new" | Out-Null
1..40 | ForEach-Object { Make-File "$v\new\n_$_.txt" (300 + $_) }
Start-Sleep -Seconds 2
$after = @(Snapshot-Tree @('V') 'after_changes')
$deleted = @("\docs\$cjk", "\docs\$long", '\docs\ads_host.txt', '\docs\hl_original.txt', '\docs\ts1975.txt', '\docs\ts1960.txt', '\docs\ts2050.txt', '\d01', '\gone_dir')
Finish-Case 'names' $vhd @('V') $pop $after $deleted @() @('\moveme\moved.txt') @(
    'hl_link.txt in keep is a hard link of docs\hl_original.txt; only the docs name was deleted',
    'ads_host.txt had an ADS named secret', 'ts1960 creation time predates 1970: its $I30 slack entry is filtered, its FILE record is not',
    'moved.txt went from moveme to keep: the old path is listed under renamed') $shadow

# ============================================================ bigdir
$vhd = "$root\bigdir.vhd"
New-LabVolume $vhd 64 @('V')
New-Item -ItemType Directory -Force "$v\big" | Out-Null
1..600 | ForEach-Object { Make-File ("$v\big\f_{0:0000}.dat" -f $_) (100 + $_) }
Start-Sleep -Seconds 2
$pop = @(Snapshot-Tree @('V') 'populated')
$shadow = Shadow @('V')
Start-Sleep -Seconds 4
$del = @()
foreach ($i in (1..100) + (501..600)) { $p = "\big\f_{0:0000}.dat" -f $i; Remove-Item -Force "$v$p"; $del += $p }
Start-Sleep -Seconds 2
New-Item -ItemType Directory -Force "$v\new" | Out-Null
1..150 | ForEach-Object { Make-File "$v\new\r_$_.dat" (50 + $_) }
Start-Sleep -Seconds 2
$after = @(Snapshot-Tree @('V') 'after_changes')
Finish-Case 'bigdir' $vhd @('V') $pop $after $del @() @() @('600 entries in one $I30 B-tree; first and last 100 in sort order deleted') $shadow

# ============================================================ manyfiles
$vhd = "$root\manyfiles.vhd"
New-LabVolume $vhd 128 @('V')
0..49 | ForEach-Object {
    $d = "$v\d{0:00}" -f $_
    New-Item -ItemType Directory -Force $d | Out-Null
    $dd = $d
    1..60 | ForEach-Object { Make-File "$dd\m_$_.txt" (120 + $_) }
}
Start-Sleep -Seconds 2
$pop = @(Snapshot-Tree @('V') 'populated')
$shadow = Shadow @('V')
Start-Sleep -Seconds 4
$del = @()
0..24 | ForEach-Object { $p = "\d{0:00}" -f $_; Remove-Item -Recurse -Force "$v$p"; $del += $p }
Start-Sleep -Seconds 2
New-Item -ItemType Directory -Force "$v\new" | Out-Null
1..500 | ForEach-Object { Make-File "$v\new\x_$_.txt" (60 + $_) }
Start-Sleep -Seconds 2
$after = @(Snapshot-Tree @('V') 'after_changes')
Finish-Case 'manyfiles' $vhd @('V') $pop $after $del @() @() @('3000 files; $MFT grows beyond its first extent; 25 directories (1500 files) deleted whole') $shadow

# ============================================================ twoparts
$vhd = "$root\twoparts.vhd"
New-LabVolume $vhd 96 @('V', 'W')
foreach ($l in @('V', 'W')) {
    $p = if ($l -eq 'V') { 'p1' } else { 'p2' }
    New-Item -ItemType Directory -Force "${l}:\docs_$p", "${l}:\keep_$p" | Out-Null
    1..40 | ForEach-Object { Make-File "${l}:\docs_$p\${p}_file_$_.txt" (200 + $_) }
    1..10 | ForEach-Object { Make-File "${l}:\keep_$p\${p}_cfg_$_.ini" (90 + $_) }
}
Start-Sleep -Seconds 2
$pop = @(Snapshot-Tree @('V', 'W') 'populated')
$shadow = Shadow @('V', 'W')
Start-Sleep -Seconds 4
$del = @()
foreach ($l in @('V', 'W')) {
    $p = if ($l -eq 'V') { 'p1' } else { 'p2' }
    21..40 | ForEach-Object { $x = "\docs_$p\${p}_file_$_.txt"; Remove-Item -Force "${l}:$x"; $del += $x }
    New-Item -ItemType Directory -Force "${l}:\new_$p" | Out-Null
    1..25 | ForEach-Object { Make-File "${l}:\new_$p\${p}_new_$_.txt" (70 + $_) }
}
Start-Sleep -Seconds 2
$after = @(Snapshot-Tree @('V', 'W') 'after_changes')
Finish-Case 'twoparts' $vhd @('V', 'W') $pop $after $del @() @() @('two NTFS partitions; p1_* lives on the first, p2_* on the second') $shadow

# ============================================================ 4k (optional)
if (Get-Command New-VHD -ErrorAction SilentlyContinue) {
    $vhd = "$root\4k.vhdx"
    New-VHD -Path $vhd -SizeBytes 64MB -Fixed -LogicalSectorSizeBytes 4096 -PhysicalSectorSizeBytes 4096 | Out-Null
    "4k: created with New-VHD (not used further: VHDX is not decoded by allymacb)"
    Remove-Item $vhd -Force
} else {
    "4k: Hyper-V module not present, case skipped"
}

& fsutil behavior set DisableDeleteNotify 0 | Out-Null
Get-ChildItem $cases -Recurse -File | ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash)  $($_.FullName)" } | Set-Content "$cases\sha256.txt"
Compress-Archive -Path "$cases\*" -DestinationPath "$root\cases.zip" -Force
Get-Content "$cases\sha256.txt"
"zip: $((Get-Item "$root\cases.zip").Length) bytes"
