# sshrack TUI demo: launch -> fuzzy-filter -> connect.
Output assets/tui.gif

Set FontFamily "Hack Nerd Font Mono"
Set FontSize 16
Set Width 1200
Set Height 600
Set Framerate 25
Set Padding 20
Set Theme "Dracula"

# Launch the TUI.
Type "sshrack"
Enter
Sleep 1200ms

# Fuzzy-filter to the local host.
Type "loc"
Sleep 900ms

# Connect (Enter on the selected host) and let the remote shell render.
Enter
Sleep 2500ms
