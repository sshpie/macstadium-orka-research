#!/bin/bash

set -ex -o pipefail

REPARTITION_SIZE=$1

DISK_LIST=$(mktemp)
diskutil list | tee $DISK_LIST

DISK_INFO=$(mktemp)
diskutil info / | tee $DISK_INFO

trap "echo done && rm -f $DISK_INFO && rm -f $DISK_LIST" EXIT

set -u

# Find disk on which APFS container is located, e.g. 'disk1' for store 'disk1s2'
APFS_DISK_IDS=$(awk '{print $2, $4, $7}' $DISK_LIST | grep -i 'apple_apfs disk')
APFS_STORE=$(echo $APFS_DISK_IDS | awk '{print $3}' | sed 's/^\(disk[0-9]*\).*/\1/' | grep 'disk')
APFS_CONTAINER=$(echo $APFS_DISK_IDS | awk '{print $2}' | sed 's/^\(disk[0-9]*\).*/\1/' | grep 'disk')
echo "*** repairing partition map ***"
echo -n 'y' | diskutil repairDisk $APFS_STORE
echo "*** resizing apfs container ***"
diskutil apfs resizeContainer /dev/${APFS_CONTAINER} ${REPARTITION_SIZE}
diskutil list

# compare disk size before and after resize
set +e

# verify apfs container disk size changed
diff \
  <(grep -i "apple_apfs " $DISK_LIST | awk '{print $5 $6}') \
  <(diskutil list | grep -i "apple_apfs " | awk '{print $5 $6}')
# diff exits with status code 1 if inputs are same, 0 if different
if [[ $? -eq 0 ]]; then
  echo "fatal: failed to resize partition!"
  exit 1
fi

# verify apfs container scheme - physical store repartitioned
diff \
  <(grep -i "apple_apfs " $DISK_LIST | awk '{print $5 $6}') \
  <(diskutil list | grep -i "apfs container scheme" | awk '{print $6 $7}' | sed 's/+//g')
# diff exits with status code 1 if inputs are same, 0 if different
if [[ $? -eq 0 ]]; then
  echo "fatal: 'apple_apfs' size does not match 'apfs container scheme' size"
  exit 1
fi
