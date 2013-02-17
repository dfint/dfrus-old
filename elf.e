-- ћодуль работы с форматом Executable and Linkable Format
-- Based on http://www.skyfree.org/linux/references/ELF_Format.pdf

-- Elf32_Ehdr
public constant 
    E_IDENT     = #00, -- + 16
    E_TYPE      = #10, -- + 2
    E_MACHINE   = #12, -- + 2
    E_VERSION   = #14, -- + 4
    E_ENTRY     = #18, -- + 4
    E_PHOFF     = #1C, -- + 4
    E_SHOFF     = #20, -- + 4
    E_FLAGS     = #24, -- + 4
    E_HSIZE     = #28, -- + 2
    E_PHENTSIZE = #2A, -- + 2
    E_PHNUM     = #2C, -- + 2
    E_SHENTSIZE = #2E, -- + 2
    E_SHNUM     = #30, -- + 2
    SIZEOF_EHDR = #32  -- 50

-- Values of the e_type field
public constant
    ET_NONE     = 0, -- No file type
    ET_REL      = 1, -- Relocatable file
    ET_EXEC     = 2, -- Executable file
    ET_DYN      = 3, -- Shared object file
    ET_CORE     = 4, -- Core file
    ET_LOPROC   = #FF00, -- Processor specific
    ET_HIPROC   = #FFFF, -- Processor specific

-- Values of the e_machine field
public constant
    EM_NONE     = 0, -- No machine
    EM_M32      = 1, -- AT&T WE 32100
    EM_SPARC    = 2, -- SPARC
    EM_386      = 3, -- Intel 80386
    EM_68K      = 4, -- Motorola 68000
    EM_88K      = 5, -- Motorola 88000
    EM_860      = 7, -- Intel 80860
    EM_MIPS     = 8, -- MIPS RS3000

public constant EV_NONE = 0, EV_CURRENT = 1

-- »ндексы в массиве e_ident, с учетом того, что индексаци€ в Eu начинаетс€ с 1
public enum
    EI_MAG = 1, EI_MAG0 = 1, EI_MAG1, EI_MAG2, EI_MAG3, -- "\x7fELF"
    EI_CLASS, EI_DATA, EI_VERSION, EI_PAD, EI_NIDENT = 16


