#include <iostream>    /* cout, cerr */
#include <fstream>     /* ifstream, ofstream */
#include <cstring>     /* strncmp */
#include "STD_TYPES.h" /* u8, u16, u32 */


/* ************ exit codes ************ */
#define EXIT_CODE_ALL_SUCCEEDED            0
#define EXIT_CODE_INVALID_ARGS_COUNT      -1
#define EXIT_CODE_COULDNT_OPEN_ELF_FILE   -2
#define EXIT_CODE_INVALID_ELF_FILE        -3
#define EXIT_CODE_COULDNT_OPEN_HEX_FILE   -4
/* ************************************ */


/* ****************** ELF file defines ****************** */
#define EI_NIDENT     16

#define EI_MAG0       0      /* File identification */
#define EI_MAG1       1      /* File identification */
#define EI_CLASS      4      /* File class */
#define EI_DATA       5      /* Data encoding */
#define EI_VERSION    6      /* File version */

#define ELFMAG0       0x7F   /* e_ident[EI_MAG0] */

#define ET_EXEC       2      /* Executable file */

#define EM_ARM        0x28   /* ARM */

#define EV_CURRENT    1      /* Current version */

#define ELFCLASS32    1      /* 32-bit objects */

#define ELFDATA2LSB   1      /* little endian format */
/* ****************************************************** */


/* ***************** ELF file types ***************** */
/* ELF32 file header type */
typedef struct
{
   char e_ident[EI_NIDENT]; /* The initial bytes mark the file as an object file and provide machine-independent data with which to decode and interpret the file's contents */
   u16  e_type;             /* object file type */
   u16  e_machine;          /* required architecture for an individual file */
   u32  e_version;          /* object file version */
   u32  e_entry;            /* virtual address to which the system first transfers control (startup code) */
   u32  e_phoff;            /* program header table's file offset (in bytes) used in execution model */
   u32  e_shoff;            /* section header table's file offset (in bytes) used in linking model */
   u32  e_flags;            /* processor-specific flags associated with the file */
   u16  e_ehsize;           /* ELF header's size (in bytes) */
   u16  e_phentsize;        /* the size of one entry in the program header table (in bytes) */
   u16  e_phnum;            /* number of entries in the program header table */
   u16  e_shentsize;        /* the size of one entry in the section header table (in bytes) */
   u16  e_shnum;            /* number of entries in the section header table */
   u16  e_shstrndx;         /* index of the entry (in section header table) associated with the section name string table */
} Elf32_Ehdr;

/* ELF32 program header type */
typedef struct
{
   u32 p_type;   /* what kind of segment this array element describes */
   u32 p_offset; /* offset from the beginning of the file at which the 1st byte of the segment resides */
   u32 p_vaddr;  /* virtual address at which the first byte of the segment resides in memory */
   u32 p_paddr;  /* physical address at which the first byte of the segment resides in memory */
   u32 p_filesz; /* number of bytes of the segment (in this file) */
   u32 p_memsz;  /* number of bytes of the segment (in the memory) */
   u32 p_flags;  /* flags relevant to the segment */
   u32 p_align;  /* Values 0 and 1 mean that no alignment is required. Otherwise, p_align should be a positive, integral power of 2, and p_addr = p_offset % p_align */
} Elf32_Phdr;
/* ************************************************** */


/* ****************** HEX file defines ****************** */
#define HEX_MAX_RECORD_LENGTH                  16

#define HEX_RECORD_TYPE_DATA                   0
#define HEX_RECORD_TYPE_EOF                    1
#define HEX_RECORD_TYPE_EXTENDED_LINEAR_ADDR   4
#define HEX_RECORD_TYPE_START_LINEAR_ADDR      5
/* ****************************************************** */


/* ***************** HEX file types ***************** */
/* HEX record type */
typedef struct
{
   u8  dataLength;
   u16 addressOffset;
   u8  type;
   u8  data[HEX_MAX_RECORD_LENGTH];
   u8  checksum;
} IntelHexRecord_t;
/* ************************************************** */


void displayHelpPage(void);

void ArmElf32_ExtractHeaderFromFile(Elf32_Ehdr& elfFileHeader, std::ifstream& elfFileHandle);
void ArmElf32_ExtractProgramHeaderEntryFromFile(Elf32_Phdr& elfProgramHeader, u32 entryNum, const Elf32_Ehdr& elfFileHeader, std::ifstream& elfFileHandle);
u8 ArmElf32_CheckHeaderValidity(const Elf32_Ehdr& elfFileHeader);

void IntelHex_WriteElfProgramHeaderEntryToFile(const Elf32_Phdr& elfProgramHeader, std::ifstream& elfFileHandle, std::ofstream& hexFileHandle);
void IntelHex_CalcRecordChecksum(IntelHexRecord_t& record);
void IntelHex_WriteRecordToFile(const IntelHexRecord_t& record, std::ofstream& hexFileHandle);


int main(int argc, char* argv[])
{
   int status;

   Elf32_Ehdr elfFileHeader;
   Elf32_Phdr elfProgramHeader;

   std::ifstream elfFileHandle;
   std::ofstream hexFileHandle;

   IntelHexRecord_t record;

   if (argc == 3) /* if valid number of args */
   {
      /* try to open the ELF file */
      elfFileHandle.open(argv[1], std::ios_base::in | std::ios_base::binary);

      if (elfFileHandle.is_open()) /* if opening the ELF file succeeded */
      {
         /* get the header from the file */
         ArmElf32_ExtractHeaderFromFile(elfFileHeader, elfFileHandle);

         if (ArmElf32_CheckHeaderValidity(elfFileHeader)) /* if ELF file header is a valid ARM32 executable file */
         {
            /* try to open the HEX file */
            hexFileHandle.open(argv[2], std::ios_base::out | std::ios_base::trunc);

            if (elfFileHandle.is_open()) /* if opening the HEX file succeeded */
            {
               /* for each program header entry in the program header table */
               for (u8 i = 0; i < elfFileHeader.e_phnum; i++)
               {
                  /* get the program header entry from the ELF file */
                  ArmElf32_ExtractProgramHeaderEntryFromFile(elfProgramHeader, i, elfFileHeader, elfFileHandle);

                  /* write the data bytes to the hex file */
                  IntelHex_WriteElfProgramHeaderEntryToFile(elfProgramHeader, elfFileHandle, hexFileHandle);
               }

               /* start address (startup code address) record */
               record.dataLength = 4;
               record.addressOffset = 0;
               record.type = HEX_RECORD_TYPE_START_LINEAR_ADDR;
               record.data[0] = (u8)((elfFileHeader.e_entry & 0xFF000000) >> 24);
               record.data[1] = (u8)((elfFileHeader.e_entry & 0x00FF0000) >> 16);
               record.data[2] = (u8)((elfFileHeader.e_entry & 0x0000FF00) >> 8);
               record.data[3] = (u8)(elfFileHeader.e_entry & 0x000000FF);
               IntelHex_CalcRecordChecksum(record);
               IntelHex_WriteRecordToFile(record, hexFileHandle);

               /* End Of File record */
               record.dataLength = 0;
               record.addressOffset = 0;
               record.type = HEX_RECORD_TYPE_EOF;
               IntelHex_CalcRecordChecksum(record);
               IntelHex_WriteRecordToFile(record, hexFileHandle);

               status = EXIT_CODE_ALL_SUCCEEDED;
            }
            else /* if opening the HEX file failed */
            {
               std::cerr << "ERROR: couldn't open the HEX file\n" << std::endl;

               status = EXIT_CODE_COULDNT_OPEN_HEX_FILE;
            }
         }
         else /* if ELF file header is NOT a valid ARM32 executable file */
         {
            std::cerr << "ERROR: invalid ELF file, supported type is a little-endian executable ARM32 ELF file only\n" << std::endl;

            status = EXIT_CODE_INVALID_ELF_FILE;
         }
      }
      else /* if opening the ELF file failed */
      {
         std::cerr << "ERROR: couldn't open the ELF file\n" << std::endl;

         status = EXIT_CODE_COULDNT_OPEN_ELF_FILE;
      }
   }
   else /* if invalid number of args */
   {
      std::cerr << "ERROR: invalid number of arguments\n" << std::endl;
      displayHelpPage();

      status = EXIT_CODE_INVALID_ARGS_COUNT;
   }

   if (elfFileHandle.is_open()) /* if opening the ELF file succeeded */
   {
      /* close the file */
      elfFileHandle.close();
   }
   else /* if opening the ELF file failed */
   {

   }

   if (hexFileHandle.is_open()) /* if opening the HEX file succeeded */
   {
      /* close the file */
      hexFileHandle.close();
   }
   else /* if opening the HEX file failed */
   {

   }

   return status;
}


void displayHelpPage(void)
{
   std::cout << "Usage: elhex-converter.exe <input ELF file> <output HEX file>\n"
             << "   input ELF file: executable ARM32 ELF file\n"
             << "   output HEX file: intel HEX file\n"
             << std::endl;
}


void ArmElf32_ExtractHeaderFromFile(Elf32_Ehdr& elfFileHeader, std::ifstream& elfFileHandle)
{
   /* point to the beginning of the elf file */
   elfFileHandle.seekg(0);

   /* read the identification part */
   elfFileHandle.read((char*)&elfFileHeader, sizeof(elfFileHeader));
}

void ArmElf32_ExtractProgramHeaderEntryFromFile(Elf32_Phdr& elfProgramHeader, u32 entryNum, const Elf32_Ehdr& elfFileHeader, std::ifstream& elfFileHandle)
{
   /* point to the beginning of the program header entry:
    * program header table offset + n * entry size*/
   elfFileHandle.seekg(elfFileHeader.e_phoff + entryNum * elfFileHeader.e_phentsize);

   /* read the entry */
   elfFileHandle.read((char*)&elfProgramHeader, sizeof(elfProgramHeader));

   //std::cout << "physical = " << std::hex << (int)elfProgramHeader.p_vaddr << std::endl;
}

u8 ArmElf32_CheckHeaderValidity(const Elf32_Ehdr& elfFileHeader)
{
   u8 status;

   if ( (elfFileHeader.e_ident[EI_MAG0] == ELFMAG0)               && /* 1st magic byte */
        (strncmp(&elfFileHeader.e_ident[EI_MAG1], "ELF", 3) == 0) && /* magic string */
        (elfFileHeader.e_ident[EI_CLASS] == ELFCLASS32)           && /* word size = 32-bit */
        (elfFileHeader.e_ident[EI_DATA] == ELFDATA2LSB)           && /* data order is little endian */
        (elfFileHeader.e_ident[EI_VERSION] == EV_CURRENT)         && /* version field is always set to EV_CURRENT */
        (elfFileHeader.e_type == ET_EXEC)                         && /* object file type = Executable file */
        (elfFileHeader.e_machine == EM_ARM)                       && /* machine/processor type is ARM */
        (elfFileHeader.e_version == EV_CURRENT)                   && /* version field is always set to EV_CURRENT */
        (elfFileHeader.e_phoff != 0)                              && /* program header table's offset NOT 0 */
        (elfFileHeader.e_ehsize != 0)                             && /* ELF file header size NOT 0 */
        (elfFileHeader.e_phentsize != 0)                          && /* program header table entry size NOT 0 */
        (elfFileHeader.e_phnum != 0) )                               /* program header table entries count NOT 0 */
   {
      status = 1;
   }
   else
   {
      status = 0;
   }

   return status;
}


void IntelHex_WriteElfProgramHeaderEntryToFile(const Elf32_Phdr& elfProgramHeader, std::ifstream& elfFileHandle, std::ofstream& hexFileHandle)
{
   u16 segmentMemAddr; /* offset in memory */
   IntelHexRecord_t record; /* represents each record */

   if (elfProgramHeader.p_filesz) /* if the segment has a representation in file (has physical bytes that'll be written to flash) */
   {
      /* creaate the extended address (start address) record */
      record.dataLength = 2;
      record.addressOffset = 0;
      record.type = HEX_RECORD_TYPE_EXTENDED_LINEAR_ADDR;
      record.data[0] = (u8)((elfProgramHeader.p_paddr & 0xFFFF0000) >> 24);
      record.data[1] = (u8)((elfProgramHeader.p_paddr & 0xFFFF0000) >> 16);

      IntelHex_CalcRecordChecksum(record);
      IntelHex_WriteRecordToFile(record, hexFileHandle);

      record.dataLength = HEX_MAX_RECORD_LENGTH;
      record.type = HEX_RECORD_TYPE_DATA;

      /* the memory offset of each record is the lower 2 bytes of the base memory address */
      segmentMemAddr = (u16)(elfProgramHeader.p_paddr & 0x0000FFFF);

      /* goto the file offset of the data bytes of this program header entry */
      elfFileHandle.seekg(elfProgramHeader.p_offset);

      /* foreach record that can have a size = HEX_MAX_RECORD_LENGTH */
      for (u32 i = 0; i < (elfProgramHeader.p_filesz / HEX_MAX_RECORD_LENGTH); i++)
      {
         record.addressOffset = segmentMemAddr;

         for (u8 j = 0; j < HEX_MAX_RECORD_LENGTH; j++)
         {
            record.data[j] = (u8)elfFileHandle.get();
         }

         IntelHex_CalcRecordChecksum(record);
         IntelHex_WriteRecordToFile(record, hexFileHandle);

         segmentMemAddr += HEX_MAX_RECORD_LENGTH;
      }

      if (elfProgramHeader.p_filesz % HEX_MAX_RECORD_LENGTH) /* if there're some bytes that form a record with size < HEX_MAX_RECORD_LENGTH */
      {
         record.dataLength = elfProgramHeader.p_filesz % HEX_MAX_RECORD_LENGTH;
         record.addressOffset = segmentMemAddr;

         for (u8 j = 0; j < record.dataLength; j++)
         {
            record.data[j] = elfFileHandle.get();
         }

         IntelHex_CalcRecordChecksum(record);
         IntelHex_WriteRecordToFile(record, hexFileHandle);
      }
      else /* if no bytes are remaining (all bytes form a record with size = HEX_MAX_RECORD_LENGTH) */
      {

      }
   }
   else /* if the segment doesn't have a representation in file (like .bss) */
   {

   }
}

void IntelHex_CalcRecordChecksum(IntelHexRecord_t& record)
{
   /* checksum = ((sum of all record bytes) % 256) * -1 */
   record.checksum = record.dataLength                          +
                     (u8)(record.addressOffset & 0x00FF)        +
                     (u8)((record.addressOffset & 0xFF00) >> 8) +
                     record.type;

   for (u8 i = 0; i < record.dataLength; i++)
   {
      record.checksum += record.data[i];
   }

   record.checksum *= -1;
}

void IntelHex_WriteRecordToFile(const IntelHexRecord_t& record, std::ofstream& hexFileHandle)
{
   u8 prevFill;

   /* write the colon first */
   hexFileHandle << ':';
   
   /* we pad the numbers by 0s */
   prevFill = hexFileHandle.fill('0');

   /* write all numeric digits in uppercase (looks cool!) */
   hexFileHandle << std::hex << std::uppercase;

   /* width of the next write operation = sizeof(numeric object) * 2 because 1 byte = 2 hex degits
    * write the data length */
   hexFileHandle.width(sizeof(record.dataLength) * 2);
   hexFileHandle << (int)record.dataLength;

   /* write the memory offset */
   hexFileHandle.width(sizeof(record.addressOffset) * 2);
   hexFileHandle << (int)record.addressOffset;
   
   /* write the record type */
   hexFileHandle.width(sizeof(record.type) * 2);
   hexFileHandle << (int)record.type;

   /* write all the data bytes */
   for (u8 i = 0; i < record.dataLength; i++)
   {
      hexFileHandle.width(sizeof(record.data[0]) * 2);
      hexFileHandle << (int)record.data[i];
   }

   /* finally write the checksum */
   hexFileHandle.width(sizeof(record.checksum) * 2);
   hexFileHandle << (int)record.checksum;

   /* restore everything realted to the manipulations of the hex file handle */
   hexFileHandle.width(1);
   hexFileHandle << std::dec << std::nouppercase;
   hexFileHandle.fill(prevFill);

   /* and terminate the line */
   hexFileHandle << std::endl;
}

