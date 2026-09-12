#!/bin/sh
# Bootstrap for a-Shell on iOS.
#
# One-liner install (paste into a-Shell):
#
#   curl -sL https://raw.githubusercontent.com/Prevalent0453/Personal/claude/mobile-game-network-packets-l9xv32/install-ashell.sh | sh
#
# Downloads mobile_game_packet_sim.py into ~/Documents/ (where the iOS
# Files app can see it under "On My iPhone -> a-Shell") and prints how
# to run it.

set -e

BRANCH="claude/mobile-game-network-packets-l9xv32"
BASE="https://raw.githubusercontent.com/Prevalent0453/Personal/${BRANCH}"
DEST="${HOME}/Documents/mobile_game_packet_sim.py"

echo "==> Downloading simulator..."
curl -fsSL -o "${DEST}" "${BASE}/mobile_game_packet_sim.py"

echo "==> Installed: ${DEST}"
echo
echo "Run it:"
echo "  python3 ~/Documents/mobile_game_packet_sim.py --seconds 10"
echo
echo "Options:"
echo "  --seconds N          how long the client plays (default 15)"
echo "  --quiet              hide per-packet trace, keep summary only"
echo "  --server --host 0.0.0.0 --port 40000    listen for a remote client"
echo "  --client --host <IP> --port 40000       connect to a remote server"
echo
echo "Optional: add a short alias so you can just type 'gamesim'."
echo "  echo \"alias gamesim='python3 ~/Documents/mobile_game_packet_sim.py'\" >> ~/.profile"
echo "  source ~/.profile"
