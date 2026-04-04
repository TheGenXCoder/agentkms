# AgentKMS NBDE — Arch Linux Setup

Network-Bound Disk Encryption (NBDE) ties your LUKS disk encryption to your
AgentKMS token validity. If the token is revoked (stolen laptop, employee
departure), the drive is destroyed on the next boot OR actively on the
running system.

## Prerequisites

- AgentKMS server running (e.g. at https://kms.yourdomain.com)
- LUKS-encrypted root partition
- Machine enrolled as a service account in AgentKMS

---

## Step 1: Enroll the Machine

On the machine to protect:

```bash
# Enroll as a service account with disk_unlock permission
agentkms enroll \
  --server https://kms.yourdomain.com \
  --role service \
  --caller-id "arch-laptop-01@machines" \
  --scope "credential_vend:disk/arch-laptop-01"
# Certs written to /etc/agentkms/
```

## Step 2: Store the LUKS Key in OpenBao

Get your existing LUKS master key (or generate a new slot):

```bash
# Get the LUKS master key (requires existing passphrase)
LUKS_KEY=$(sudo cryptsetup luksDump /dev/nvme0n1p2 | grep 'Master key:' || \
  # Alternative: create a new key slot with a random key
  dd if=/dev/urandom bs=64 count=1 | base64)

# Store it in AgentKMS's OpenBao backend
vault kv put kv/generic/disk/arch-laptop-01 \
  luks_key="$LUKS_KEY"

# Add the key as a new LUKS slot (so it can unlock the drive)
echo -n "$LUKS_KEY" | sudo cryptsetup luksAddKey /dev/nvme0n1p2 \
  --key-file=-

# IMPORTANT: Keep your existing passphrase as a recovery slot!
# The AgentKMS slot can be removed via cryptsetup luksRemoveKey
# if you ever migrate away from NBDE.
```

## Step 3: Install the initramfs Hook

```bash
# Copy the unlock binary
sudo cp agentkms-disk /usr/local/bin/agentkms-disk
sudo chmod 755 /usr/local/bin/agentkms-disk

# Install the mkinitcpio hook
sudo cp agentkms-disk.hook /usr/lib/initcpio/install/agentkms-disk
sudo cp agentkms-disk.sh   /usr/lib/initcpio/hooks/agentkms-disk

# Add to /etc/mkinitcpio.conf HOOKS line:
# HOOKS=(... keymap encrypt agentkms-disk filesystems ...)
# Note: agentkms-disk must come BEFORE 'encrypt'

# Rebuild initramfs
sudo mkinitcpio -P
```

## Step 4: Install the Watchdog

```bash
# Copy the watchdog binary
sudo cp agentkms-watchdog /usr/local/bin/agentkms-watchdog
sudo chmod 700 /usr/local/bin/agentkms-watchdog

# Edit the service file with your server address and device
sudo cp deploy/arch/agentkms-watchdog.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now agentkms-watchdog
sudo systemctl status agentkms-watchdog
```

## Step 5: Test (log-only mode first!)

```bash
# First, test with log-only mode
sudo agentkms-watchdog \
  --server https://kms.yourdomain.com \
  --device /dev/nvme0n1p2 \
  --grace 2 \
  --mode log-only &

# Revoke the machine's cert from the Web UI
# Watch the logs:
sudo journalctl -u agentkms-watchdog -f

# When confident, switch to --mode erase
```

## Threat Model

| Threat | Protection |
|---|---|
| Laptop stolen while OFF | Drive can't be unlocked on boot (AgentKMS won't serve key to revoked cert) |
| Laptop stolen while ON | Watchdog detects revocation within grace × interval (default: 3 min) and calls luksErase |
| AgentKMS server unreachable | Grace period (default 3 × 60s = 3 min) before action — prevents false positives from network blips |
| Attacker copies the cert | Cert is in /etc/agentkms — protected by running system. Still need cert + key + AgentKMS reachable |
| Total AgentKMS loss | Recovery slot (passphrase) preserved in separate LUKS slot — you can still unlock manually |

## Recovery

If you need to unlock the drive without AgentKMS (e.g. server is down):

```bash
# At the boot prompt when agentkms-disk fails:
# Press Ctrl-C to fall through to the standard passphrase prompt
# Enter your LUKS recovery passphrase (the one you kept in Step 2)
```

The recovery passphrase should be stored in your AgentKMS recovery codes
or a hardware-backed password manager.
