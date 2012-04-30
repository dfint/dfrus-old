include patcher.e
public include std/io.e
include std/convert.e

public constant
    -- IMAGE_DOS_HEADER
    MZ_SIGNATURE        = #00, -- "MZ"
    -- ...
    MZ_LFANEW           = #3C

-- Get pe-header offset, and check executable file validity as well
public
function check_pe(atom fn)
    atom pe
    if not equal(fpeek(fn,{MZ_SIGNATURE,2}),"MZ") then -- Check MZ signature
        return -1
    end if
    pe = fpeek4u(fn, MZ_LFANEW)
    if not equal(fpeek(fn,{pe,2}),"PE") then -- Check PE signature
        return -1
    end if
    return pe
end function

-- PE header offsets
public constant
    -- IMAGE_NT_HEADER
    PE_SIGNATURE                = #00, -- "PE\0\0"
    -- IMAGE_FILE_HEADER
    PE_MACHINE                  = #04,
    PE_NUMBER_OF_SECTIONS       = #06, -- !
    PE_TIMEDATE_STAMP           = #08,
    PE_POINTER_TO_SYMBOL_TABLE  = #0C,
    PE_NUMBER_OF_SYMBOLS        = #10,
    PE_SIZE_OF_OPTIONAL_HEADER  = #14,
    PE_CHARACTERISTICS          = #16,
    -- IMAGE_OPTIONAL_HEADER
    PE_MAGIC                    = #18,
    PE_MAJOR_LINKER_VER         = #1A,
    PE_MINOR_LINKER_VER         = #1B,
    PE_SIZE_OF_CODE             = #1C,
    PE_SIZE_OF_INIT_DATA        = #20,
    PE_SIZE_OF_UNINIT_DATA      = #24,
    PE_ENTRY_POINT_RVA          = #28, -- !
    PE_BASE_OF_CODE             = #2C,
    PE_BASE_OF_DATA             = #30,
    PE_IMAGE_BASE               = #34, -- !
    PE_SECTION_ALIGNMENT        = #38,
    PE_FILE_ALIGNMENT           = #3C,
    PE_MAJOR_OS_VER             = #40,
    PE_MINOR_OS_VER             = #42,
    PE_MAJOR_IMAGE_VER          = #44,
    PE_MINOR_IMAGE_VER          = #46,
    PE_MAJOR_SUBSYS_VER         = #48,
    PE_MINOR_SUBSYS_VER         = #4A,
    PE_WIN32_VER                = #4C,
    PE_SIZE_OF_IMAGE            = #50,
    PE_SIZE_OF_HEADER           = #54,
    PE_CHECKSUM                 = #58,
    PE_SUBSYSTEM                = #5C, -- !
    PE_DLL_CHARACTERISTICS      = #5E,
    PE_SIZE_OF_STACK_RESERVE    = #60,
    PE_SIZE_OF_STACK_COMMIT     = #64,
    PE_SIZE_OF_HEAP_RESERVE     = #68,
    PE_SIZE_OF_HEAP_COMMIT      = #6C,
    PE_LOADER_FLAGS             = #70,
    PE_NUMBER_OF_RVA_AND_SIZES  = #74, -- reserved
    PE_DATA_DIRECTORY           = #78,
    IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16,
    SIZEOF_DATA_DIRECTORY       = #08,
    SIZEOF_PE_HEADER            = #F8

public
constant data_dir_tags = {
    "EXPORT","IMPORT","RESOURCE","EXCEPTION",
    "SECURITY","BASRELOC","DEBUG","ARCHITECTURE",
    "GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT",
    "IAT","DELAY_IMPORT","COM_DESCRIPTOR","RESERVED"
}

public enum
    DD_EXPORT, DD_IMPORT, DD_RESOURCE, DD_EXCEPTION,
    DD_SECURITY, DD_BASERELOC, DD_DEBUG, DD_ARCHITECTURE,
    DD_GLOBALPTR, DD_TLS, DD_LOAD_CONFIG, DD_BOUND_IMPORT,
    DD_IAT, DD_DELAY_IMPORT, DD_COM_DESCRIPTOR

public
function get_data_directory(atom fn)
    atom pe = fpeek4u(fn, MZ_LFANEW)
    sequence dd = repeat(0, IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    seek(fn, pe + PE_DATA_DIRECTORY)
    for i = 1 to length(dd) do
        -- dd[i] = append(get_dwords(fn,2),data_dir_tags[i])
        dd[i] = get_dwords(fn,2)
    end for
    return dd
end function

public enum
    SECTION_NAME,       -- section name
    SECTION_VSIZE,      -- section virtual size
    SECTION_RVA,        -- section relative virtual address
    SECTION_PSIZE,      -- section phisical size
    SECTION_POFFSET,    -- section phisical offset
    SECTION_FLAGS = 10  -- section flags

public constant SIZEOF_IMAGE_SECTION_HEADER = #28

public
function get_section_table(atom fn, atom pe=0)
    atom n
    if pe=0 then
        pe = fpeek4u(fn, MZ_LFANEW)
    end if
    n = fpeek2u(fn, pe + PE_NUMBER_OF_SECTIONS)
    sequence sh = repeat(repeat(0,10),n)
    seek(fn, pe + SIZEOF_PE_HEADER)
    for i = 1 to n do
        sh[i][1] = get_bytes(fn,8) -- Name
        if sh[i][$] = 0 then -- Truncate trailing zeros
            sh[i][1] = sh[i][1][1..find(0,sh[i][1])-1]
        end if
        for j = 2 to 7 do
            sh[i][j] = get_integer32(fn)
        end for
        sh[i][8] = get_integer16(fn)
        sh[i][9] = get_integer16(fn)
        sh[i][10] = get_integer32(fn)
    end for
    return sh
end function

public
procedure put_section_info(atom fn, atom off, sequence section)
    sequence s
    seek(fn,off)
    section[1] &= repeat(0,8) -- Pad with zeros
    puts(fn,section[1][1..8])
    for i = 2 to 7 do
        puts(fn,int_to_bytes(section[i]))
    end for
    for i = 8 to 9 do
        s = int_to_bytes(section[i])
        puts(fn,s[1..2])
    end for
    puts(fn,int_to_bytes(section[$]))
end procedure

public constant
    IMAGE_SCN_CNT_CODE                  = #00000020,
    IMAGE_SCN_CNT_INITIALIZED_DATA      = #00000040,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA    = #00000080,
    IMAGE_SCN_MEM_DISCARDABLE           = #02000000,
    IMAGE_SCN_MEM_SHARED                = #10000000,
    IMAGE_SCN_MEM_EXECUTE               = #20000000,
    IMAGE_SCN_MEM_READ                  = #40000000,
    IMAGE_SCN_MEM_WRITE                 = #80000000,
    $

-- converts relative virtual address to offset
public
function rva_to_off(atom rva, sequence section_table)
    atom loc
    for i = 1 to length(section_table) do
        loc = rva - section_table[i][SECTION_RVA] -- local offset inside current section
        if loc < 0 then
            return -1
        elsif loc < section_table[i][SECTION_VSIZE] then
            return section_table[i][SECTION_POFFSET] + loc
        end if
    end for
    return -1
end function

-- converts offset to relative virtual address
public
function off_to_rva(atom off, sequence section_table)
    atom loc
    for i = 1 to length(section_table) do
        loc = off - section_table[i][SECTION_POFFSET]
        if loc < 0 then
            return -1
        elsif loc < section_table[i][SECTION_PSIZE] then
            return section_table[i][SECTION_RVA] + loc
        end if
    end for
    return -1
end function

public
function off_to_rva_ex(atom off, sequence section)
    return off - section[SECTION_POFFSET] + section[SECTION_RVA]
end function

public
function get_relocations(atom fn, object sections = 0)
    sequence dd = get_data_directory(fn)
    if atom(sections) then
        sections = get_section_table(fn)
    end if
    atom reloc_off = rva_to_off(dd[DD_BASERELOC][1],sections),
         reloc_size = dd[DD_BASERELOC][2]
    sequence relocs = {}
    atom page, block_size, cur_off = 0, rec
    seek(fn,reloc_off)
    while cur_off < reloc_size do
        page = get_integer32(fn)
        block_size = get_integer32(fn)
        for i = 1 to (block_size-8)/2 do
            rec = get_integer16(fn)
            if and_bits(rec,#3000) then
                relocs &= page+and_bits(rec,#0FFF)
            end if
        end for
        cur_off += block_size
    end while
    return relocs
end function