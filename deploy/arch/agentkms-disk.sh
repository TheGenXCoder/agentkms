#!/usr/bin/ash
# /usr/lib/initcpio/hooks/agentkms-disk
# mkinitcpio RUNTIME hook — called during early userspace

run_hook() {
  # Read kernel cmdline parameters
  local server machine device
  for param in $(cat /proc/cmdline); do
    case "$param" in
      agentkms.server=*) server="${param#agentkms.server=}" ;;
      agentkms.machine=*) machine="${param#agentkms.machine=}" ;;
      agentkms.device=*) device="${param#agentkms.device=}" ;;
    esac
  done

  if [ -z "$server" ] || [ -z "$machine" ] || [ -z "$device" ]; then
    echo "agentkms-disk: missing kernel parameters, skipping"
    return 0  # Fall through to standard encrypt hook
  fi

  echo "agentkms-disk: unlocking $device via $server..."
  if /usr/local/bin/agentkms-disk \
    --server "$server" \
    --machine-id "$machine" \
    --device "$device" \
    --mapper root; then
    echo "agentkms-disk: unlocked successfully"
    return 0
  else
    echo "agentkms-disk: unlock failed — falling through to passphrase prompt"
    return 0  # Return 0 so initramfs continues to standard encrypt hook
  fi
}
