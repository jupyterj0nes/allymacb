Output demo-carve.gif
Set Shell "pwsh"
Set FontSize 15
Set Width 1500
Set Height 820
Set Theme { "name": "allymacb", "black": "#1F1B2E", "red": "#FF5C7A", "green": "#5FE39A", "yellow": "#FFE14D", "blue": "#6FA8FF", "magenta": "#FF8FA3", "cyan": "#7FE7F2", "white": "#FFF4E6", "brightBlack": "#6E6888", "brightRed": "#FF8FA3", "brightGreen": "#8AF0B6", "brightYellow": "#FFEB85", "brightBlue": "#9CC2FF", "brightMagenta": "#FFB3C1", "brightCyan": "#A8F0F7", "brightWhite": "#FFFFFF", "background": "#1F1B2E", "foreground": "#FFF4E6", "selection": "#3A3452", "cursor": "#FFE14D" }
Set WindowBar Colorful
Set BorderRadius 14
Set Margin 22
Set MarginFill "#FF5C7A"
Set TypingSpeed 35ms
Set Padding 24
Hide
Type `cd <evidence dir>; function prompt { '> ' }; $env:PATH = '<allymacb dir>;' + $env:PATH; Remove-Item live.csv,carved.csv -ErrorAction SilentlyContinue; Clear-Host`
Enter
Sleep 2s
Show
Type `# A quick-formatted NTFS volume. The live $MFT knows nothing of C:\docs any more:`
Enter
Sleep 500ms
Type `allymacb -q -f reformat.vhd -o live.csv; Import-Csv live.csv | ? file_name -like 'C:\docs*' | measure | select Count`
Enter
Sleep 3s
Hide
Wait@600s
Show
Sleep 4s
Type `# Carve its sectors for the old FILE records and $I30 entries:`
Enter
Sleep 500ms
Type `allymacb -f reformat.vhd --carve -o carved.csv`
Enter
Sleep 3s
Hide
Wait@600s
Show
Sleep 4s
Type `Clear-Host; Import-Csv carved.csv | ? source -eq carved | ? file_name -like 'C:\docs*' | select -First 14 time_created,type,source,file_name | ft -AutoSize`
Enter
Sleep 10s
