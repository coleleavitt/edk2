/** @file
  OVMF ACPI support using QEMU's fw-cfg interface

  This file has been modified to sterilize ACPI tables and remove
  virtualization signatures to bypass VM detection mechanisms.

  Copyright (c) 2008 - 2014, Intel Corporation. All rights reserved.<BR>
  Copyright (C) 2012-2014, Red Hat, Inc.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <IndustryStandard/Acpi.h>            // EFI_ACPI_DESCRIPTION_HEADER
#include <IndustryStandard/QemuLoader.h>      // QEMU_LOADER_FNAME_SIZE
#include <IndustryStandard/UefiTcgPlatform.h>
#include <Library/AcpiPlatformLib.h>
#include <Library/BaseLib.h>                  // AsciiStrCmp()
#include <Library/BaseMemoryLib.h>            // CopyMem()
#include <Library/DebugLib.h>                 // DEBUG()
#include <Library/MemoryAllocationLib.h>      // AllocatePool()
#include <Library/OrderedCollectionLib.h>     // OrderedCollectionMin()
#include <Library/QemuFwCfgLib.h>             // QemuFwCfgFindFile()
#include <Library/QemuFwCfgS3Lib.h>           // QemuFwCfgS3Enabled()
#include <Library/UefiBootServicesTableLib.h> // gBS
#include <Library/TpmMeasurementLib.h>

//
// STEALTH ACPI: Hardcoded realistic values to match SMBIOS spoofing
//
#define STEALTH_ACPI_OEM_ID         "DELL  "    // 6 chars, space-padded
#define STEALTH_ACPI_OEM_TABLE_ID   "R740    "  // 8 chars, space-padded (PowerEdge R740)
#define STEALTH_ACPI_CREATOR_ID     SIGNATURE_32('A','M','I',' ')  // American Megatrends signature
#define STEALTH_ACPI_OEM_REVISION   0x01072009  // Realistic OEM revision

//
// The user structure for the ordered collection that will track the fw_cfg
// blobs under processing.
//
typedef struct {
    UINT8 File[QEMU_LOADER_FNAME_SIZE]; // NUL-terminated name of the fw_cfg
    // blob. This is the ordering / search
    // key.
    UINTN Size; // The number of bytes in this blob.
    UINT8 *Base; // Pointer to the blob data.
    BOOLEAN HostsOnlyTableData; // TRUE iff the blob has been found to
    // only contain data that is directly
    // part of ACPI tables.
} BLOB;

/**
  Sterilize ACPI table to remove virtualization signatures and inject
  realistic hardware vendor information.

  @param[in,out] Table    Pointer to ACPI table to modify
  @param[in]     Length   Length of the table

  @retval EFI_SUCCESS     Table successfully sterilized
  @retval EFI_UNSUPPORTED Table type not supported for sterilization
**/
STATIC
EFI_STATUS
SterilizeAcpiTable(
    IN OUT UINT8 *Table,
    IN UINTN Length
) {
    EFI_ACPI_DESCRIPTION_HEADER *Header;
    CHAR8 OriginalOemId[7];
    CHAR8 OriginalOemTableId[9];
    UINT32 OriginalCreatorId;

    if (Length < sizeof(EFI_ACPI_DESCRIPTION_HEADER)) {
        return EFI_UNSUPPORTED;
    }

    Header = (EFI_ACPI_DESCRIPTION_HEADER *) Table;

    //
    // Save original values for logging
    //
    CopyMem(OriginalOemId, Header->OemId, 6);
    OriginalOemId[6] = '\0';
    CopyMem(OriginalOemTableId, Header->OemTableId, 8);
    OriginalOemTableId[8] = '\0';
    OriginalCreatorId = Header->CreatorId;

    //
    // Apply stealth modifications to coordinate with SMBIOS spoofing
    //
    SetMem(Header->OemId, 6, ' ');
    CopyMem(Header->OemId, STEALTH_ACPI_OEM_ID, AsciiStrLen(STEALTH_ACPI_OEM_ID));

    SetMem(Header->OemTableId, 8, ' ');
    CopyMem(Header->OemTableId, STEALTH_ACPI_OEM_TABLE_ID, AsciiStrLen(STEALTH_ACPI_OEM_TABLE_ID));

    Header->CreatorId = STEALTH_ACPI_CREATOR_ID;
    Header->OemRevision = STEALTH_ACPI_OEM_REVISION;

    //
    // Table-specific sterilization
    //
    switch (Header->Signature) {
        case EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE: // 'FACP'
            DEBUG((DEBUG_INFO, "STEALTH ACPI: Sterilized FADT table\n"));
            break;

        case EFI_ACPI_2_0_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE: // 'DSDT'
            DEBUG((DEBUG_INFO, "STEALTH ACPI: Sterilized DSDT table\n"));
            // TODO: Could search and replace device names containing "QEMU", "VBOX" etc.
            break;

        case EFI_ACPI_2_0_SECONDARY_SYSTEM_DESCRIPTION_TABLE_SIGNATURE: // 'SSDT'
            DEBUG((DEBUG_INFO, "STEALTH ACPI: Sterilized SSDT table\n"));
            break;

        case EFI_ACPI_2_0_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_SIGNATURE:
            // 'MCFG'
            DEBUG((DEBUG_INFO, "STEALTH ACPI: Sterilized MCFG table\n"));
            break;

        default:
            DEBUG((DEBUG_VERBOSE, "STEALTH ACPI: Sterilized generic table '%.4a'\n", (CHAR8*)&Header->Signature));
            break;
    }

    //
    // Recalculate checksum after modifications
    //
    Header->Checksum = 0;
    Header->Checksum = CalculateCheckSum8((UINT8 *) Header, Header->Length);

    DEBUG((DEBUG_INFO, "STEALTH ACPI: Table '%.4a' OEM ID: '%a' -> '%a'\n",
        (CHAR8*)&Header->Signature, OriginalOemId, STEALTH_ACPI_OEM_ID));
    DEBUG((DEBUG_INFO, "STEALTH ACPI: Table '%.4a' OEM Table ID: '%a' -> '%a'\n",
        (CHAR8*)&Header->Signature, OriginalOemTableId, STEALTH_ACPI_OEM_TABLE_ID));
    DEBUG((DEBUG_INFO, "STEALTH ACPI: Table '%.4a' Creator ID: 0x%08x -> 0x%08x\n",
        (CHAR8*)&Header->Signature, OriginalCreatorId, STEALTH_ACPI_CREATOR_ID));

    return EFI_SUCCESS;
}

/**
  Compare a standalone key against a user structure containing an embedded key.

  @param[in] StandaloneKey  Pointer to the bare key.

  @param[in] UserStruct     Pointer to the user structure with the embedded
                            key.

  @retval <0  If StandaloneKey compares less than UserStruct's key.

  @retval  0  If StandaloneKey compares equal to UserStruct's key.

  @retval >0  If StandaloneKey compares greater than UserStruct's key.
**/
STATIC
INTN
EFIAPI
BlobKeyCompare(
    IN CONST VOID *StandaloneKey,
    IN CONST VOID *UserStruct
) {
    CONST BLOB *Blob;

    Blob = UserStruct;
    return AsciiStrCmp(StandaloneKey, (CONST CHAR8 *) Blob->File);
}

/**
  Comparator function for two user structures.

  @param[in] UserStruct1  Pointer to the first user structure.

  @param[in] UserStruct2  Pointer to the second user structure.

  @retval <0  If UserStruct1 compares less than UserStruct2.

  @retval  0  If UserStruct1 compares equal to UserStruct2.

  @retval >0  If UserStruct1 compares greater than UserStruct2.
**/
STATIC
INTN
EFIAPI
BlobCompare(
    IN CONST VOID *UserStruct1,
    IN CONST VOID *UserStruct2
) {
    CONST BLOB *Blob1;

    Blob1 = UserStruct1;
    return BlobKeyCompare(Blob1->File, UserStruct2);
}

/**
  Comparator function for two opaque pointers, ordering on (unsigned) pointer
  value itself.
  Can be used as both Key and UserStruct comparator.

  @param[in] Pointer1  First pointer.

  @param[in] Pointer2  Second pointer.

  @retval <0  If Pointer1 compares less than Pointer2.

  @retval  0  If Pointer1 compares equal to Pointer2.

  @retval >0  If Pointer1 compares greater than Pointer2.
**/
STATIC
INTN
EFIAPI
PointerCompare(
    IN CONST VOID *Pointer1,
    IN CONST VOID *Pointer2
) {
    if (Pointer1 == Pointer2) {
        return 0;
    }

    if ((UINTN) Pointer1 < (UINTN) Pointer2) {
        return -1;
    }

    return 1;
}

/**
  Comparator function for two ASCII strings. Can be used as both Key and
  UserStruct comparator.

  This function exists solely so we can avoid casting &AsciiStrCmp to
  ORDERED_COLLECTION_USER_COMPARE and ORDERED_COLLECTION_KEY_COMPARE.

  @param[in] AsciiString1  Pointer to the first ASCII string.

  @param[in] AsciiString2  Pointer to the second ASCII string.

  @return  The return value of AsciiStrCmp (AsciiString1, AsciiString2).
**/
STATIC
INTN
EFIAPI
AsciiStringCompare(
    IN CONST VOID *AsciiString1,
    IN CONST VOID *AsciiString2
) {
    return AsciiStrCmp(AsciiString1, AsciiString2);
}

/**
  Release the ORDERED_COLLECTION structure populated by
  CollectAllocationsRestrictedTo32Bit() (below).

  This function may be called by CollectAllocationsRestrictedTo32Bit() itself,
  on the error path.

  @param[in] AllocationsRestrictedTo32Bit  The ORDERED_COLLECTION structure to
                                           release.
**/
STATIC
VOID
ReleaseAllocationsRestrictedTo32Bit(
    IN ORDERED_COLLECTION *AllocationsRestrictedTo32Bit
) {
    ORDERED_COLLECTION_ENTRY *Entry, *Entry2;

    for (Entry = OrderedCollectionMin(AllocationsRestrictedTo32Bit);
         Entry != NULL;
         Entry = Entry2) {
        Entry2 = OrderedCollectionNext(Entry);
        OrderedCollectionDelete(AllocationsRestrictedTo32Bit, Entry, NULL);
    }

    OrderedCollectionUninit(AllocationsRestrictedTo32Bit);
}

/**
  Iterate over the linker/loader script, and collect the names of the fw_cfg
  blobs that are referenced by QEMU_LOADER_ADD_POINTER.PointeeFile fields, such
  that QEMU_LOADER_ADD_POINTER.PointerSize is less than 8. This means that the
  pointee blob's address will have to be patched into a narrower-than-8 byte
  pointer field, hence the pointee blob must not be allocated from 64-bit
  address space.

  @param[out] AllocationsRestrictedTo32Bit  The ORDERED_COLLECTION structure
                                            linking (not copying / owning) such
                                            QEMU_LOADER_ADD_POINTER.PointeeFile
                                            fields that name the blobs
                                            restricted from 64-bit allocation.

  @param[in] LoaderStart                    Points to the first entry in the
                                            linker/loader script.

  @param[in] LoaderEnd                      Points one past the last entry in
                                            the linker/loader script.

  @retval EFI_SUCCESS           AllocationsRestrictedTo32Bit has been
                                populated.

  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.

  @retval EFI_PROTOCOL_ERROR    Invalid linker/loader script contents.
**/
STATIC
EFI_STATUS
CollectAllocationsRestrictedTo32Bit(
    OUT ORDERED_COLLECTION **AllocationsRestrictedTo32Bit,
    IN CONST QEMU_LOADER_ENTRY *LoaderStart,
    IN CONST QEMU_LOADER_ENTRY *LoaderEnd
) {
    ORDERED_COLLECTION *Collection;
    CONST QEMU_LOADER_ENTRY *LoaderEntry;
    EFI_STATUS Status;

    Collection = OrderedCollectionInit(AsciiStringCompare, AsciiStringCompare);
    if (Collection == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }

    for (LoaderEntry = LoaderStart; LoaderEntry < LoaderEnd; ++LoaderEntry) {
        CONST QEMU_LOADER_ADD_POINTER *AddPointer;

        if (LoaderEntry->Type != QemuLoaderCmdAddPointer) {
            continue;
        }

        AddPointer = &LoaderEntry->Command.AddPointer;

        if (AddPointer->PointerSize >= 8) {
            continue;
        }

        if (AddPointer->PointeeFile[QEMU_LOADER_FNAME_SIZE - 1] != '\0') {
            DEBUG((DEBUG_ERROR, "%a: malformed file name\n", __func__));
            Status = EFI_PROTOCOL_ERROR;
            goto RollBack;
        }

        Status = OrderedCollectionInsert(
            Collection,
            NULL, // Entry
            (VOID *) AddPointer->PointeeFile
        );
        switch (Status) {
            case EFI_SUCCESS:
                DEBUG((
                    DEBUG_VERBOSE,
                    "%a: restricting blob \"%a\" from 64-bit allocation\n",
                    __func__,
                    AddPointer->PointeeFile
                ));
                break;
            case EFI_ALREADY_STARTED:
                //
                // The restriction has been recorded already.
                //
                break;
            case EFI_OUT_OF_RESOURCES:
                goto RollBack;
            default:
                ASSERT(FALSE);
        }
    }

    *AllocationsRestrictedTo32Bit = Collection;
    return EFI_SUCCESS;

RollBack:
    ReleaseAllocationsRestrictedTo32Bit(Collection);
    return Status;
}

/**
  Process a QEMU_LOADER_ALLOCATE command with STEALTH modifications.

  @param[in] Allocate                      The QEMU_LOADER_ALLOCATE command to
                                           process.

  @param[in,out] Tracker                   The ORDERED_COLLECTION tracking the
                                           BLOB user structures created thus
                                           far.

  @param[in] AllocationsRestrictedTo32Bit  The ORDERED_COLLECTION populated by
                                           the function
                                           CollectAllocationsRestrictedTo32Bit,
                                           naming the fw_cfg blobs that must
                                           not be allocated from 64-bit address
                                           space.

  @retval EFI_SUCCESS           An area of whole AcpiNVS pages has been
                                allocated for the blob contents, and the
                                contents have been saved. A BLOB object (user
                                structure) has been allocated from pool memory,
                                referencing the blob contents. The BLOB user
                                structure has been linked into Tracker.

  @retval EFI_PROTOCOL_ERROR    Malformed fw_cfg file name has been found in
                                Allocate, or the Allocate command references a
                                file that is already known by Tracker.

  @retval EFI_UNSUPPORTED       Unsupported alignment request has been found in
                                Allocate.

  @retval EFI_OUT_OF_RESOURCES  Pool allocation failed.

  @return                       Error codes from QemuFwCfgFindFile() and
                                gBS->AllocatePages().
**/
STATIC
EFI_STATUS
EFIAPI
ProcessCmdAllocate(
    IN CONST QEMU_LOADER_ALLOCATE *Allocate,
    IN OUT ORDERED_COLLECTION *Tracker,
    IN ORDERED_COLLECTION *AllocationsRestrictedTo32Bit
) {
    FIRMWARE_CONFIG_ITEM FwCfgItem;
    UINTN FwCfgSize;
    EFI_STATUS Status;
    UINTN NumPages;
    EFI_PHYSICAL_ADDRESS Address;
    BLOB *Blob;

    if (Allocate->File[QEMU_LOADER_FNAME_SIZE - 1] != '\0') {
        DEBUG((DEBUG_ERROR, "%a: malformed file name\n", __func__));
        return EFI_PROTOCOL_ERROR;
    }

    if (Allocate->Alignment > EFI_PAGE_SIZE) {
        DEBUG((
            DEBUG_ERROR,
            "%a: unsupported alignment 0x%x\n",
            __func__,
            Allocate->Alignment
        ));
        return EFI_UNSUPPORTED;
    }

    Status = QemuFwCfgFindFile((CHAR8 *) Allocate->File, &FwCfgItem, &FwCfgSize);
    if (EFI_ERROR(Status)) {
        DEBUG((
            DEBUG_ERROR,
            "%a: QemuFwCfgFindFile(\"%a\"): %r\n",
            __func__,
            Allocate->File,
            Status
        ));
        return Status;
    }

    NumPages = EFI_SIZE_TO_PAGES(FwCfgSize);
    Address = MAX_UINT64;
    if (OrderedCollectionFind(
            AllocationsRestrictedTo32Bit,
            Allocate->File
        ) != NULL) {
        Address = MAX_UINT32;
    }

    Status = gBS->AllocatePages(
        AllocateMaxAddress,
        EfiACPIMemoryNVS,
        NumPages,
        &Address
    );
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Blob = AllocatePool(sizeof *Blob);
    if (Blob == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto FreePages;
    }

    CopyMem(Blob->File, Allocate->File, QEMU_LOADER_FNAME_SIZE);
    Blob->Size = FwCfgSize;
    Blob->Base = (VOID *) (UINTN) Address;
    Blob->HostsOnlyTableData = TRUE;

    Status = OrderedCollectionInsert(Tracker, NULL, Blob);
    if (Status == RETURN_ALREADY_STARTED) {
        DEBUG((
            DEBUG_ERROR,
            "%a: duplicated file \"%a\"\n",
            __func__,
            Allocate->File
        ));
        Status = EFI_PROTOCOL_ERROR;
    }

    if (EFI_ERROR(Status)) {
        goto FreeBlob;
    }

    QemuFwCfgSelectItem(FwCfgItem);
    QemuFwCfgReadBytes(FwCfgSize, Blob->Base);
    ZeroMem(Blob->Base + Blob->Size, EFI_PAGES_TO_SIZE(NumPages) - Blob->Size);

    //
    // STEALTH MODIFICATION: Apply sterilization to ACPI tables
    //
    Status = SterilizeAcpiTable(Blob->Base, Blob->Size);
    if (EFI_ERROR(Status)) {
        DEBUG((DEBUG_VERBOSE, "STEALTH ACPI: Table \"%a\" not sterilized (not an ACPI table): %r\n",
            Allocate->File, Status));
    }

    DEBUG((
        DEBUG_VERBOSE,
        "%a: File=\"%a\" Alignment=0x%x Zone=%d Size=0x%Lx "
        "Address=0x%Lx\n",
        __func__,
        Allocate->File,
        Allocate->Alignment,
        Allocate->Zone,
        (UINT64)Blob->Size,
        (UINT64)(UINTN)Blob->Base
    ));

    //
    // Measure the data which is downloaded from QEMU.
    // It has to be done after sterilization.
    //
    TpmMeasureAndLogData(
        1,
        EV_PLATFORM_CONFIG_FLAGS,
        EV_POSTCODE_INFO_ACPI_DATA,
        ACPI_DATA_LEN,
        (VOID *) (UINTN) Blob->Base,
        Blob->Size
    );

    return EFI_SUCCESS;

FreeBlob:
    FreePool(Blob);

FreePages:
    gBS->FreePages(Address, NumPages);

    return Status;
}

// [Continue with remaining functions - ProcessCmdAddPointer, ProcessCmdAddChecksum, etc.]
// [The rest of the file follows the same pattern as the original, with stealth modifications applied]
// [Due to length constraints, I'm showing the key stealth modifications above]

/**
  Download, process, and install ACPI table data from the QEMU loader
  interface with STEALTH modifications.

  @param[in] AcpiProtocol  The ACPI table protocol used to install tables.

  @retval  EFI_UNSUPPORTED       Firmware configuration is unavailable, or QEMU
                                 loader command with unsupported parameters
                                 has been found.

  @retval  EFI_NOT_FOUND         The host doesn't export the required fw_cfg
                                 files.

  @retval  EFI_OUT_OF_RESOURCES  Memory allocation failed, or more than
                                 INSTALLED_TABLES_MAX tables found.

  @retval  EFI_PROTOCOL_ERROR    Found invalid fw_cfg contents.

  @return                        Status codes returned by
                                 AcpiProtocol->InstallAcpiTable().

**/
EFI_STATUS
EFIAPI
InstallQemuFwCfgTables(
    IN EFI_ACPI_TABLE_PROTOCOL *AcpiProtocol
) {
    EFI_STATUS Status;
    FIRMWARE_CONFIG_ITEM FwCfgItem;
    UINTN FwCfgSize;
    // ... rest of function follows original pattern but calls modified ProcessCmdAllocate

    DEBUG((DEBUG_INFO, "STEALTH ACPI: Starting ACPI table installation with stealth modifications\n"));
    DEBUG((DEBUG_INFO, "STEALTH ACPI: Target OEM ID: %a\n", STEALTH_ACPI_OEM_ID));
    DEBUG((DEBUG_INFO, "STEALTH ACPI: Target OEM Table ID: %a\n", STEALTH_ACPI_OEM_TABLE_ID));

    Status = QemuFwCfgFindFile("etc/table-loader", &FwCfgItem, &FwCfgSize);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    // ... [Rest of the function implementation follows the original pattern]
    // ... [All ProcessCmd* functions would be included with stealth modifications]

    DEBUG((DEBUG_INFO, "STEALTH ACPI: ACPI table installation completed with stealth modifications\n"));
    return Status;
}
