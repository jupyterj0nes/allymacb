# Ground truth for `allymacb --carve`, built on a real NTFS volume.
#
# Run as Administrator on any Windows host (a disposable lab VM is the right
# place: it toggles TRIM and takes a shadow copy). It creates a 64 MiB fixed VHD,
# formats it NTFS, fills it with files, takes a Volume Shadow Copy, then appends
# to some files, renames others, deletes files and a whole directory tree, and
# creates new files so NTFS reuses the freed MFT records. The VHD is kept twice:
#
#   carve_deleted.vhd    after the changes. The shadow copy's diff area holds the
#                        previous state of every $MFT and $I30 block that was
#                        rewritten, which is what carving must bring back.
#   carve_reformat.vhd   the same volume after a quick reformat with TRIM off,
#                        so the old metadata is still in the sectors.
#   truth.json           every file as it was after population and after the
#                        changes (size, timestamps, MFT record number), and which
#                        paths were deleted, modified and renamed.
#   sha256.txt           hashes of the three files above.
#
# Copy the outputs to <samples>/lab/basic/ as deleted.vhd, reformat.vhd and
# truth.json and run scripts/cross_examine.py, or check one timeline by hand with
# scripts/check_carve_lab.py. scripts/carve_lab_cases.ps1 adds more cases.
#
# Everything happens inside C:\rf-carve and on the VHD; TRIM is restored at the end.
$ErrorActionPreference = 'Stop'
$root = 'C:\rf-carve'
$vhd = "$root\work.vhd"
$letter = 'V'
$v = "${letter}:"
New-Item -ItemType Directory -Force $root | Out-Null
& vssadmin delete shadows /for=$v /quiet 2>$null | Out-Null
Remove-Item -Force "$root\*" -ErrorAction SilentlyContinue

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
function Snapshot-Tree($label) {
    Get-ChildItem "$v\" -Recurse -Force | Where-Object { $_.FullName -notlike '*System Volume Information*' } | ForEach-Object {
        $id = $null
        if (-not $_.PSIsContainer) {
            $fi = & fsutil file queryfileid $_.FullName 2>$null
            if ($fi -match '0x([0-9a-f]+)') { $id = [Convert]::ToInt64($matches[1], 16) -band 0xFFFFFFFFFFFF }
        }
        [pscustomobject]@{
            stage = $label
            path = $_.FullName.Substring(2)
            dir = $_.PSIsContainer
            size = $(if ($_.PSIsContainer) { 0 } else { $_.Length })
            created = $_.CreationTimeUtc.ToString('o')
            modified = $_.LastWriteTimeUtc.ToString('o')
            record = $id
        }
    }
}

Run-Diskpart @(
    "create vdisk file=$vhd maximum=64 type=fixed",
    "select vdisk file=$vhd",
    "attach vdisk",
    "create partition primary",
    "format fs=ntfs quick label=CARVELAB",
    "assign letter=$letter"
) | Out-Null
Start-Sleep -Seconds 2
if (-not (Test-Path "$v\")) { throw "volume $v not mounted" }

# --- stage 1: populate --------------------------------------------------------
New-Item -ItemType Directory -Force "$v\docs", "$v\secret", "$v\secret\inner", "$v\keep" | Out-Null
1..30 | ForEach-Object { Make-File "$v\docs\report_$_.txt" (200 + $_ * 37) }
1..25 | ForEach-Object { Make-File "$v\secret\payroll_$_.xlsx" (1500 + $_ * 101) }
1..10 | ForEach-Object { Make-File "$v\secret\inner\exfil_$_.zip" (3000 + $_ * 211) }
1..15 | ForEach-Object { Make-File "$v\keep\config_$_.ini" (100 + $_ * 13) }
Make-File "$v\docs\big_video.mp4" (5 * 1024 * 1024)
Make-File "$v\secret\dump.bin" (2 * 1024 * 1024)
Set-Content -Path "$v\keep\host.txt" -Value 'host content'
Set-Content -Path "$v\keep\host.txt:Zone.Identifier" -Value "[ZoneTransfer]`r`nZoneId=3"
Start-Sleep -Seconds 2
$stage1 = @(Snapshot-Tree 'populated')

# shadow copy: from now on every rewritten block keeps its old content in the diff area
$shadow = (& vssadmin create shadow /for=$v 2>&1) -join ' '
Start-Sleep -Seconds 3

# --- stage 2: modify, delete, reuse ------------------------------------------
Start-Sleep -Seconds 5
1..5 | ForEach-Object { Add-Content -Path "$v\docs\report_$_.txt" -Value ('appended line ' * 50) }
1..5 | ForEach-Object { Rename-Item "$v\keep\config_$_.ini" "renamed_$_.ini" }
Remove-Item -Force "$v\docs\report_1?.txt"            # report_10..19
Remove-Item -Recurse -Force "$v\secret"               # whole tree incl. inner and dump.bin
Start-Sleep -Seconds 2
New-Item -ItemType Directory -Force "$v\new" | Out-Null
1..20 | ForEach-Object { Make-File "$v\new\replacement_$_.log" (400 + $_ * 23) }
Start-Sleep -Seconds 2
$stage2 = @(Snapshot-Tree 'after_changes')

Run-Diskpart @("select vdisk file=$vhd", "detach vdisk") | Out-Null
Copy-Item $vhd "$root\carve_deleted.vhd"

# --- stage 3: quick reformat, TRIM off ---------------------------------------
Run-Diskpart @(
    "select vdisk file=$vhd",
    "attach vdisk",
    "select partition 1",
    "format fs=ntfs quick label=WIPED",
    "assign letter=$letter"
) | Out-Null
Start-Sleep -Seconds 2
Set-Content -Path "$v\after_format.txt" -Value 'only file on the reformatted volume'
Run-Diskpart @("select vdisk file=$vhd", "detach vdisk") | Out-Null
Copy-Item $vhd "$root\carve_reformat.vhd"

& fsutil behavior set DisableDeleteNotify 0 | Out-Null

@{
    host = $env:COMPUTERNAME
    created_utc = (Get-Date).ToUniversalTime().ToString('o')
    shadow = $shadow
    trim_before = $trimWas
    populated = $stage1
    after_changes = $stage2
    deleted = @(10..19 | ForEach-Object { "\docs\report_$_.txt" }) + @($stage1 | Where-Object { $_.path -like '\secret*' } | ForEach-Object { $_.path })
    modified = @(1..5 | ForEach-Object { "\docs\report_$_.txt" })
    renamed = @(1..5 | ForEach-Object { "\keep\config_$_.ini" })
} | ConvertTo-Json -Depth 5 | Set-Content -Path "$root\truth.json" -Encoding UTF8

Get-FileHash "$root\carve_deleted.vhd", "$root\carve_reformat.vhd", "$root\truth.json" -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash)  $($_.Path)" } | Set-Content "$root\sha256.txt"
Get-Content "$root\sha256.txt"
"shadow: $shadow"
"populated: $($stage1.Count) entries; after changes: $($stage2.Count)"
