#!/usr/bin/env bash
# Copy pynq-pl to a board over ssh.
#
#   BOARD=xilinx@192.168.2.99 ./deploy.sh            # PYNQ image (password: xilinx)
#   BOARD=root@192.168.1.10   ./deploy.sh zedboard   # name the overlay if it can't be guessed
#
# The first argument picks which overlay to copy (pynq-z2, zedboard, or all;
# default all). Files go to ~/jupyter_notebooks/pynq-pl when the board has
# Jupyter (PYNQ), otherwise to ~/pynq-pl. Set DEST to choose another folder.
set -euo pipefail
cd "$(dirname "$0")"

BOARD="${BOARD:-xilinx@192.168.2.99}"
WHICH="${1:-all}"
SAMPLE_PACKETS="${SAMPLE_PACKETS:-100000}"

case $WHICH in
    all) overlays=(overlay/pynq-z2 overlay/zedboard) ;;
    pynq-z2|zedboard) overlays=("overlay/$WHICH") ;;
    *) echo "usage: $0 [pynq-z2|zedboard|all]" >&2; exit 1 ;;
esac
present=()
for o in "${overlays[@]}"; do
    if [[ -f $o/svdd_pl.bit && -f $o/svdd_pl.hwh ]]; then
        present+=("$o/svdd_pl.bit" "$o/svdd_pl.hwh")
    else
        echo "skipping $o: not built (vivado/build.sh ${o#overlay/})" >&2
    fi
done
[[ ${#present[@]} -gt 0 ]] || { echo "no overlay built" >&2; exit 1; }

# The first 100k packets of UNSW-NB15 1.pcap for selftest and the notebook.
if [[ ! -f samples/unsw_sample.pcap && -f ../pcap/1.pcap ]]; then
    mkdir -p samples
    python3 -m svdd_ps slice ../pcap/1.pcap samples/unsw_sample.pcap --packets "$SAMPLE_PACKETS"
fi

if [[ -z ${DEST:-} ]]; then
    DEST=$(ssh "$BOARD" 'if [ -d ~/jupyter_notebooks ]; then echo ~/jupyter_notebooks/pynq-pl; else echo ~/pynq-pl; fi')
fi
ssh "$BOARD" "mkdir -p '$DEST'"
tar --exclude='__pycache__' --exclude='.pytest_cache' -cf - \
    svdd_pl svdd_ps assets notebooks README.md "${present[@]}" $(ls -d samples 2>/dev/null) \
  | ssh "$BOARD" "tar -xf - -C '$DEST'"

echo "Deployed to $BOARD:$DEST"
echo "Then on the board:"
echo "  cd $DEST && sudo python3 -m svdd_pl selftest"
