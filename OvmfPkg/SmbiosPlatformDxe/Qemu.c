/** @file
  Find and extract QEMU SMBIOS data from fw_cfg.

  This file has been completely rewritten to generate fake SMBIOS tables
  to bypass Virtual Machine detection mechanisms by providing realistic
  hardware vendor information instead of QEMU/virtualization signatures.

  Copyright (C) 2014, Gabriel L. Somlo <somlo@cmu.edu>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/QemuFwCfgLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <IndustryStandard/SmBios.h>

//
// STEALTH SMBIOS: Hardcoded realistic hardware values to bypass VM detection
//
#define STEALTH_BIOS_VENDOR         "American Megatrends Inc."
#define STEALTH_BIOS_VERSION        "F.43"
#define STEALTH_BIOS_RELEASE_DATE   "04/01/2023"
#define STEALTH_SYSTEM_MANUFACTURER "Dell Inc."
#define STEALTH_SYSTEM_PRODUCT      "PowerEdge R740"
#define STEALTH_SYSTEM_VERSION      "1.0"
#define STEALTH_SYSTEM_SERIAL       "2M3WK73"
#define STEALTH_SYSTEM_SKU          "SKU=NotProvided;ModelName=PowerEdge R740"
#define STEALTH_SYSTEM_FAMILY       "PowerEdge"

/**
  Calculate and append strings to SMBIOS table

  @param  TablePtr      Pointer to the table
  @param  Strings       Array of string pointers
  @param  StringCount   Number of strings

  @return  Total size including strings
**/
STATIC
UINTN
AppendSmbiosStrings(
    IN UINT8 *TablePtr,
    IN CHAR8 **Strings,
    IN UINTN StringCount
) {
    UINTN Index;
    UINTN Offset;
    UINTN StringLen;

    Offset = 0;

    for (Index = 0; Index < StringCount; Index++) {
        StringLen = AsciiStrLen(Strings[Index]) + 1; // Include null terminator
        CopyMem(TablePtr + Offset, Strings[Index], StringLen);
        Offset += StringLen;
    }

    // Add final null terminator for end of strings
    *(TablePtr + Offset) = 0;
    Offset++;

    return Offset;
}

/**
  Generate fake SMBIOS tables to bypass VM detection

  @return  Pointer to fake SMBIOS table data, or NULL on failure
**/
STATIC
UINT8 *
GenerateFakeSmbiosTables(
    VOID) {
    UINT8 *SmbiosData;
    UINT8 *CurrentPtr;
    SMBIOS_TABLE_TYPE0 *Type0;
    SMBIOS_TABLE_TYPE1 *Type1;
    SMBIOS_STRUCTURE *Type127;
    UINTN TotalSize;
    UINTN StringsSize;
    CHAR8 *Type0Strings[3];
    CHAR8 *Type1Strings[6];
    GUID SystemUuid = {
        0x12345678, 0x1234, 0x5678, {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
    };

    DEBUG((DEBUG_INFO, "STEALTH QEMU: Generating fake SMBIOS tables to bypass VM detection\n"));

    //
    // Setup string arrays for SMBIOS tables
    //
    Type0Strings[0] = STEALTH_BIOS_VENDOR;
    Type0Strings[1] = STEALTH_BIOS_VERSION;
    Type0Strings[2] = STEALTH_BIOS_RELEASE_DATE;

    Type1Strings[0] = STEALTH_SYSTEM_MANUFACTURER;
    Type1Strings[1] = STEALTH_SYSTEM_PRODUCT;
    Type1Strings[2] = STEALTH_SYSTEM_VERSION;
    Type1Strings[3] = STEALTH_SYSTEM_SERIAL;
    Type1Strings[4] = STEALTH_SYSTEM_SKU;
    Type1Strings[5] = STEALTH_SYSTEM_FAMILY;

    //
    // Calculate total size needed
    //
    TotalSize = sizeof(SMBIOS_TABLE_TYPE0) +
                AsciiStrLen(STEALTH_BIOS_VENDOR) + 1 +
                AsciiStrLen(STEALTH_BIOS_VERSION) + 1 +
                AsciiStrLen(STEALTH_BIOS_RELEASE_DATE) + 1 + 1 + // Extra null terminator
                sizeof(SMBIOS_TABLE_TYPE1) +
                AsciiStrLen(STEALTH_SYSTEM_MANUFACTURER) + 1 +
                AsciiStrLen(STEALTH_SYSTEM_PRODUCT) + 1 +
                AsciiStrLen(STEALTH_SYSTEM_VERSION) + 1 +
                AsciiStrLen(STEALTH_SYSTEM_SERIAL) + 1 +
                AsciiStrLen(STEALTH_SYSTEM_SKU) + 1 +
                AsciiStrLen(STEALTH_SYSTEM_FAMILY) + 1 + 1 + // Extra null terminator
                sizeof(SMBIOS_STRUCTURE) + 2; // Type 127 + double null

    SmbiosData = AllocateZeroPool(TotalSize);
    if (SmbiosData == NULL) {
        DEBUG((DEBUG_ERROR, "STEALTH QEMU: Failed to allocate memory for fake SMBIOS tables\n"));
        return NULL;
    }

    CurrentPtr = SmbiosData;

    //
    // Create SMBIOS Type 0 (BIOS Information) - STEALTH VALUES WITH REALISTIC CHARACTERISTICS
    //
    Type0 = (SMBIOS_TABLE_TYPE0 *) CurrentPtr;
    Type0->Hdr.Type = SMBIOS_TYPE_BIOS_INFORMATION;
    Type0->Hdr.Length = sizeof(SMBIOS_TABLE_TYPE0);
    Type0->Hdr.Handle = 0x0000;
    Type0->Vendor = 1; // String 1
    Type0->BiosVersion = 2; // String 2
    Type0->BiosSegment = 0xE800;
    Type0->BiosReleaseDate = 3; // String 3
    Type0->BiosSize = 0;

    // STEALTH FIX: Set realistic BIOS characteristics instead of "not supported"
    // Clear the entire characteristics structure first
    SetMem(&Type0->BiosCharacteristics, sizeof(Type0->BiosCharacteristics), 0);

    // Set realistic PC BIOS characteristics
    Type0->BiosCharacteristics.PciIsSupported = 1;
    Type0->BiosCharacteristics.PlugAndPlayIsSupported = 1;
    Type0->BiosCharacteristics.BiosIsUpgradable = 1; // Fixed: BiosIsUpgradable not BiosIsUpgradeable
    Type0->BiosCharacteristics.BiosShadowingAllowed = 1;
    Type0->BiosCharacteristics.BootFromCdIsSupported = 1;
    Type0->BiosCharacteristics.SelectableBootIsSupported = 1;
    Type0->BiosCharacteristics.EDDSpecificationIsSupported = 1; // FIXED: EDDSpecificationIsSupported (double D)
    Type0->BiosCharacteristics.PrintScreenIsSupported = 1;
    Type0->BiosCharacteristics.Keyboard8042IsSupported = 1;
    Type0->BiosCharacteristics.SerialIsSupported = 1;
    Type0->BiosCharacteristics.PrinterIsSupported = 1;
    // CRITICAL: Do NOT set BiosCharacteristicsNotSupported = 1

    Type0->BIOSCharacteristicsExtensionBytes[0] = 0x0B; // ACPI, USB Legacy, LS-120 Boot supported
    // CRITICAL STEALTH FIX: Ensure VM flag (bit 2) is absolutely cleared
    Type0->BIOSCharacteristicsExtensionBytes[1] = 0x10; // Only UEFI supported (bit 4), VM flag cleared
    Type0->SystemBiosMajorRelease = 2; // Realistic values instead of 0
    Type0->SystemBiosMinorRelease = 43; // Matches version F.43
    Type0->EmbeddedControllerFirmwareMajorRelease = 0xFF;
    Type0->EmbeddedControllerFirmwareMinorRelease = 0xFF;

    CurrentPtr += sizeof(SMBIOS_TABLE_TYPE0);
    StringsSize = AppendSmbiosStrings(CurrentPtr, Type0Strings, 3);
    CurrentPtr += StringsSize;

    //
    // Create SMBIOS Type 1 (System Information) - STEALTH VALUES
    //
    Type1 = (SMBIOS_TABLE_TYPE1 *) CurrentPtr;
    Type1->Hdr.Type = SMBIOS_TYPE_SYSTEM_INFORMATION;
    Type1->Hdr.Length = sizeof(SMBIOS_TABLE_TYPE1);
    Type1->Hdr.Handle = 0x0001;
    Type1->Manufacturer = 1; // String 1
    Type1->ProductName = 2; // String 2
    Type1->Version = 3; // String 3
    Type1->SerialNumber = 4; // String 4
    CopyMem(&Type1->Uuid, &SystemUuid, sizeof(GUID));
    Type1->WakeUpType = SystemWakeupTypePowerSwitch;
    Type1->SKUNumber = 5; // String 5
    Type1->Family = 6; // String 6

    CurrentPtr += sizeof(SMBIOS_TABLE_TYPE1);
    StringsSize = AppendSmbiosStrings(CurrentPtr, Type1Strings, 6);
    CurrentPtr += StringsSize;

    //
    // Create SMBIOS Type 127 (End-of-Table)
    //
    Type127 = (SMBIOS_STRUCTURE *) CurrentPtr;
    Type127->Type = 127;
    Type127->Length = sizeof(SMBIOS_STRUCTURE);
    Type127->Handle = 0x007F;

    CurrentPtr += sizeof(SMBIOS_STRUCTURE);

    // Add double null terminator for end of table
    *CurrentPtr++ = 0;
    *CurrentPtr++ = 0;

    DEBUG((DEBUG_INFO, "STEALTH QEMU: Successfully generated %d bytes of fake SMBIOS data\n",
        (UINTN)(CurrentPtr - SmbiosData)));
    DEBUG((DEBUG_INFO, "STEALTH QEMU: BIOS Vendor: %a\n", STEALTH_BIOS_VENDOR));
    DEBUG((DEBUG_INFO, "STEALTH QEMU: BIOS Version: %a\n", STEALTH_BIOS_VERSION));
    DEBUG((DEBUG_INFO, "STEALTH QEMU: System Manufacturer: %a\n", STEALTH_SYSTEM_MANUFACTURER));
    DEBUG((DEBUG_INFO, "STEALTH QEMU: System Product: %a\n", STEALTH_SYSTEM_PRODUCT));
    DEBUG((DEBUG_INFO, "STEALTH QEMU: Applied realistic BIOS characteristics and cleared VM flag\n"));

    return SmbiosData;
}

/**
  Locates and extracts the QEMU SMBIOS data if present in fw_cfg.

  This function has been completely rewritten to generate fake SMBIOS tables
  instead of loading real QEMU SMBIOS data. This bypasses VM detection by
  presenting realistic hardware vendor information.

  @return    Pointer to fake SMBIOS table data

**/
UINT8 *
GetQemuSmbiosTables(
    VOID) {
    DEBUG((DEBUG_INFO, "STEALTH QEMU: GetQemuSmbiosTables called - generating fake SMBIOS data\n"));

    //
    // Instead of loading QEMU's real SMBIOS tables (which contain virtualization
    // signatures), we generate completely fake tables with realistic hardware info
    //
    return GenerateFakeSmbiosTables();
}
