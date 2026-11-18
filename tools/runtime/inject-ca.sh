#!/system/bin/sh
# Make every app on a rooted Android emulator trust one extra CA certificate (k1d's mitmproxy CA),
# without rebooting. Android 14+ reads system CAs from the Conscrypt APEX, which is read-only, so
# the certificate store is copied to a tmpfs, the CA is added, and the tmpfs is bind-mounted over
# the APEX store in the mount namespace of zygote and of every running app.
# Technique as described publicly by HTTP Toolkit for Android 14. Runs as root (adb root).
# Usage (on the device): sh /data/local/tmp/inject-ca.sh /data/local/tmp/<subject_hash_old>.0
set -e
CA="$1"
[ -f "$CA" ] || { echo "no CA file: $CA"; exit 1; }
STAGE=/data/local/tmp/k1d-cacerts
rm -rf "$STAGE"; mkdir -p -m 700 "$STAGE"
if [ -d /apex/com.android.conscrypt/cacerts ]; then cp /apex/com.android.conscrypt/cacerts/* "$STAGE/"; else cp /system/etc/security/cacerts/* "$STAGE/"; fi
mount -t tmpfs tmpfs /system/etc/security/cacerts
cp "$STAGE"/* /system/etc/security/cacerts/
cp "$CA" /system/etc/security/cacerts/
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/* 2>/dev/null || true
if [ -d /apex/com.android.conscrypt/cacerts ]; then
  for Z in $(pidof zygote) $(pidof zygote64); do
    nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
  done
  for P in $( (for Z in $(pidof zygote) $(pidof zygote64); do ps -o PID -P $Z | grep -v PID; done) ); do
    nsenter --mount=/proc/$P/ns/mnt -- /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts 2>/dev/null &
  done
  wait
fi
rm -rf "$STAGE"
echo "k1d CA installed: $(basename "$CA")"
