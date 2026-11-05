Output demo-hunt.gif
Set Shell "pwsh"
Set FontSize 14
Set Width 1600
Set Height 700
Set Theme { "name": "allymacb", "black": "#1F1B2E", "red": "#FF5C7A", "green": "#5FE39A", "yellow": "#FFE14D", "blue": "#6FA8FF", "magenta": "#FF8FA3", "cyan": "#7FE7F2", "white": "#FFF4E6", "brightBlack": "#6E6888", "brightRed": "#FF8FA3", "brightGreen": "#8AF0B6", "brightYellow": "#FFEB85", "brightBlue": "#9CC2FF", "brightMagenta": "#FFB3C1", "brightCyan": "#A8F0F7", "brightWhite": "#FFFFFF", "background": "#1F1B2E", "foreground": "#FFF4E6", "selection": "#3A3452", "cursor": "#FFE14D" }
Set WindowBar Colorful
Set BorderRadius 14
Set Margin 22
Set MarginFill "#FF5C7A"
Set TypingSpeed 35ms
Set Padding 24
Hide
Type `cd <evidence dir>; function prompt { '> ' }; $env:PATH = '<allymacb dir>;' + $env:PATH; Remove-Item nist.csv -ErrorAction SilentlyContinue; Clear-Host`
Enter
Sleep 2s
Show
Type `# The NIST Hacking Case $MFT with 20 files timestomped after 26 Aug 2004. One run: the timeline, with the verdict in its last columns.`
Enter
Sleep 500ms
Type `allymacb -q -f nist_stomped.mft --investigation-from 2004-08-26 -o nist.csv`
Enter
Sleep 3s
Hide
Wait@600s
Show
Sleep 3s
Type `Clear-Host; Import-Csv nist.csv | ? hunt -eq significant | sort meta -Unique | sort {[int]$_.hunt_score} -Desc | select hunt,hunt_score,@{n='file';e={Split-Path $_.file_name -Leaf}},hunt_why | ft -AutoSize`
Enter
Sleep 12s
