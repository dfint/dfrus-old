-- Модуль работы с форматом Executable and Linkable Format
-- Based on http://www.skyfree.org/linux/references/ELF_Format.pdf

-- Смещения полей структуры Elf32_Ehdr (заголовка файла)
public constant 
    E_IDENT     = #00, -- + 16
    E_TYPE      = #10, -- + 2
    E_MACHINE   = #12, -- + 2
    E_VERSION   = #14, -- + 4
    E_ENTRY     = #18, -- + 4
    E_PHOFF     = #1C, -- + 4
    E_SHOFF     = #20, -- + 4 -- Смещение таблицы секций
    E_FLAGS     = #24, -- + 4
    E_HSIZE     = #28, -- + 2
    E_PHENTSIZE = #2A, -- + 2
    E_PHNUM     = #2C, -- + 2
    E_SHENTSIZE = #2E, -- + 2 -- Размер структуры, описывающей каждую секцию
    E_SHNUM     = #30, -- + 2 -- Количество секций
    SIZEOF_EHDR = #32  -- 50

-- Values of the e_type field
public enum
    ET_NONE = 0,    -- No file type
    ET_REL,         -- Relocatable file
    ET_EXEC,        -- Executable file
    ET_DYN,         -- Shared object file
    ET_CORE,        -- Core file
    ET_LOPROC = #FF00, -- Processor specific
    ET_HIPROC = #FFFF, -- Processor specific
    $

-- Values of the e_machine field
public enum
    EM_NONE = 0, -- No machine
    EM_M32,      -- AT&T WE 32100
    EM_SPARC,    -- SPARC
    EM_386,      -- Intel 80386
    EM_68K,      -- Motorola 68000
    EM_88K,      -- Motorola 88000
    EM_860 = 7,  -- Intel 80860
    EM_MIPS,     -- MIPS RS3000
    $

public constant EV_NONE = 0, EV_CURRENT = 1

-- Индексы в массиве e_ident, с учетом того, что индексация в Euphoria начинается с 1
public enum
    EI_MAG = 0, EI_MAG0 = 0, EI_MAG1, EI_MAG2, EI_MAG3, -- "\x7fELF"
    EI_CLASS, EI_DATA, EI_VERSION, EI_PAD, EI_NIDENT = 16

public constant ELFMAG = #7F & "ELF"

public enum ELFCLASSNONE = 0, ELFCLASS32, ELFCLASS64

public enum ELFDATANONE = 0, ELFDATA2LSB, ELFDATA2MSB

public constant
    SHN_UNDEF       = 0,
    SHN_LORESERVE   = #FF00,
    SHN_LOPROC      = #FF00,
    SHN_HIPROC      = #FF1F,
    SHN_ABS         = #FFF1,
    SHN_COMMON      = #FFF2,
    SHN_HIRESERVE   = #FFFF

-- Смещения полей структуры Elf32_Shdr (заголовка секции)
public constant
    SH_NAME         = #00, -- +4
    SH_TYPE         = #04, -- +4
    SH_FLAGS        = #08, -- +4
    SH_ADDR         = #0C, -- +4
    SH_OFFSET       = #10, -- +4
    SH_SIZE         = #14, -- +4
    SH_LINK         = #18, -- +4
    SH_INFO         = #1C, -- +4
    SH_ADDRALIGN    = #20, -- +4
    SH_ENTSIZE      = #24, -- +4
    SIZEOF_SHDR     = #28  -- 40

public enum
    SHT_NULL = 0,
    SHT_PROGBITS,
    SHT_SYMTAB,
    SHT_STRTAB,
    SHT_RELA,
    SHT_HASH,
    SHT_DYNAMIC,
    SHT_NOTE,
    SHT_NOBITS,
    SHT_REL,
    SHT_SHLIB,
    SHT_DYNSYM,
    SHT_LOPROC = #70000000,
    SHT_HIPROC = #7FFFFFFF,
    SHT_LOUSER = #80000000,
    SHT_HIUSER = #FFFFFFFF

public constant
    SHF_WRITE       = #1,
    SHF_ALLOC       = #2,
    SHF_EXECINSTR   = #4,
    SHF_MASKPROC    = #F0000000

include patcher.e
public include std/io.e

public function check_header(atom fn)
    if equal(fpeek(fn, {E_IDENT+EI_MAG, 4}), ELFMAG) then -- check ELF signature
        return 0 -- return zero offset
    else
        return -1
    end if
end function
