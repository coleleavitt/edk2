/** @file
Find and extract QEMU SMBIOS data from fw_cfg.

  This file has been modified to disable SMBIOS table loading from QEMU
  in order to bypass Virtual Machine detection mechanisms.

  Copyright (C) 2014, Gabriel L. Somlo <somlo@cmu.edu>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/QemuFwCfgLib.h>

/**
  Locates and extracts the QEMU SMBIOS data if present in fw_cfg.

  This function is intentionally neutralized to always return NULL. This
  prevents the firmware from using the default SMBIOS tables provided by
  QEMU, which contain obvious virtualization signatures (e.g., "QEMU",
  "Standard PC").

  By returning NULL, we force the calling driver (SmbiosPlatformDxe) to
  generate its own SMBIOS tables using PCD values, which we can control
  to present a more realistic, non-virtualized hardware profile.

  @return    Always returns NULL.

**/
UINT8 *
GetQemuSmbiosTables (
  VOID
  )
{
  //
  // Forcefully disable loading of SMBIOS tables from QEMU fw_cfg.
  // This is a deliberate modification to bypass VM detection.
  //
  return NULL;
}