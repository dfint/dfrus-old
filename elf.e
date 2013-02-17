-- Модуль работы с форматом Executable and Linkable Format

constant EI_NIDENT = 16

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

