-- Модуль работы с форматом Portable Executable
include patcher.e
public include std/io.e
include std/convert.e
include std/math.e
include std/sequence.e
include std/search.e
include std/map.e

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
    sequence section_table = repeat(repeat(0,10),n)
    seek(fn, pe + SIZEOF_PE_HEADER)
    for i = 1 to n do
        section_table[i][1] = get_bytes(fn,8) -- Name
        if section_table[i][$] = 0 then -- Truncate trailing zeros
            section_table[i][1] = section_table[i][1][1..find(0,section_table[i][1])-1]
        end if
        for j = 2 to 7 do
            section_table[i][j] = get_integer32(fn)
        end for
        section_table[i][8] = get_integer16(fn)
        section_table[i][9] = get_integer16(fn)
        section_table[i][10] = get_integer32(fn)
    end for
    return section_table
end function

public
procedure put_section_info(atom fn, atom off, sequence section)
    sequence s
    seek(fn,off)
    section[1] = pad_tail(section[1], 8, 0) -- Pad with zeros
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
    integer left = 1, right = length(section_table), mid
    atom loc
    while left <= right do
        mid = floor((right+left)/2)
        loc = rva - section_table[mid][SECTION_RVA] -- local offset inside the current section
        if loc < 0 then
            right = mid-1
        elsif loc < section_table[mid][SECTION_VSIZE] then
            return section_table[mid][SECTION_POFFSET] + loc
        else
            left = mid+1
        end if
    end while
    return -1
end function

public
function rva_to_off_ex(atom rva, sequence section)
    return rva + section[SECTION_POFFSET] - section[SECTION_RVA]
end function

-- converts offset to relative virtual address
function off_to_rva(atom off, sequence section_table)
    integer left = 1, right = length(section_table), mid
    atom loc
    while left <= right do
        mid = floor((right+left)/2)
        loc = off - section_table[mid][SECTION_POFFSET] -- local offset inside the current section
        if loc < 0 then
            right = mid-1
        elsif loc < section_table[mid][SECTION_PSIZE] then
            return section_table[mid][SECTION_RVA] + loc
        else
            left = mid+1
        end if
    end while
    return -1
end function

public
function off_to_rva_ex(atom off, sequence section)
    return off - section[SECTION_POFFSET] + section[SECTION_RVA]
end function

public constant
    IMAGE_REL_BASED_ABSOLUTE    = 0,
    IMAGE_REL_BASED_HIGH        = 1,
    IMAGE_REL_BASED_LOW         = 2,
    IMAGE_REL_BASED_HIGHLOW     = 3

public
function get_reloc_table(atom fn, atom offset, atom reloc_size)
    sequence reloc_table = {}
    atom cur_page, block_size, cur_off = 0
    seek(fn, offset)
    while cur_off < reloc_size do
        cur_page = get_integer32(fn)
        block_size = get_integer32(fn)
        sequence relocs = get_words(fn, floor((block_size-8)/2))
        reloc_table = append(reloc_table, {cur_page, relocs})
        cur_off += block_size
    end while
    return reloc_table
end function

public
function get_reloc_table_map(atom fn, atom offset, atom reloc_size)
    map reloc_table = map:new()
    atom cur_page, block_size, cur_off = 0
    seek(fn, offset)
    while cur_off < reloc_size do
        cur_page = get_integer32(fn)
        block_size = get_integer32(fn)
        sequence relocs = get_words(fn, floor((block_size-8)/2))
        map:put(reloc_table, cur_page, relocs)
        cur_off += block_size
    end while
    return reloc_table
end function

public
function table_to_relocs(sequence reloc_table)
    sequence relocs = {}
    for i = 1 to length(reloc_table) do
        atom cur_page = reloc_table[i][1]
        for j = 1 to length(reloc_table[i][2]) do
            atom record = reloc_table[i][2][j]
            if and_bits(record, #3000) = #1000*IMAGE_REL_BASED_HIGHLOW then
                relocs &= cur_page + and_bits(record, #0FFF)
            end if
        end for
    end for
    return relocs
end function

public
function get_relocations(atom fn, object sections = 0)
    sequence dd = get_data_directory(fn)
    if atom(sections) then
        sections = get_section_table(fn)
    end if
    atom reloc_off = rva_to_off(dd[DD_BASERELOC][1], sections),
         reloc_size = dd[DD_BASERELOC][2]
    return table_to_relocs( get_reloc_table(fn, reloc_off, reloc_size ) )
end function

public
function relocs_to_table(sequence relocs)
    sequence reloc_table = {}
    atom cur_page = 0, page, off
    integer padding_words = 0
    for i = 1 to length(relocs) do
        page = and_bits(relocs[i], #FFFFF000)
        off = and_bits(relocs[i], #00000FFF)
        -- {page, off} = and_bits(relocs[i], {#FFFFF000, #00000FFF})
        if page > cur_page then
            if length(reloc_table)>0 and remainder(length(reloc_table[$][2]), 2) = 1 then
                reloc_table[$][2] &= #1000*IMAGE_REL_BASED_ABSOLUTE + 0
                padding_words += 1
            end if
            reloc_table = append(reloc_table, {page, {}})
            page = cur_page
        elsif page < cur_page then
            return -1
        end if
        reloc_table[$][2] &= #1000*IMAGE_REL_BASED_HIGHLOW + off
    end for
    integer reloc_table_size = length(reloc_table)*8 + (length(relocs)+padding_words)*2
    return {reloc_table_size, reloc_table}
end function

public
procedure write_relocation_table(atom fn, atom offset, sequence reloc_table)
    seek(fn, offset)
    for i = 1 to length(reloc_table) do
        if remainder(length(reloc_table[i][2]),2)=1 then
            reloc_table[i][2] &= #1000*IMAGE_REL_BASED_ABSOLUTE + 0
        end if
        write_dwords(fn, {reloc_table[i][1], length(reloc_table[i][2])*2 + 8})
        write_words(fn, reloc_table[i][2])
    end for
end procedure

-- mod = {+add, -remove}
public
function modify_relocations(atom fn, object sections = 0, sequence mod)
    sequence dd = get_data_directory(fn)
    if atom(sections) then
        sections = get_section_table(fn)
    end if
    atom reloc_off = rva_to_off(dd[DD_BASERELOC][1], sections),
         reloc_size = dd[DD_BASERELOC][2]
    sequence relocs = {}
    integer cur_page = 0, next_page = 0, cur_page_off, block_size, len, cur_off, rec, k, rva
    
    for i = 1 to length(mod) do
        rva = abs(mod[i])
        if rva < cur_page or rva >= next_page then
            if length(relocs)>0 then
                -- записать измененный блок релокаций:
                if length(relocs)>len then
                    return -1
                end if
                fpoke2(fn, reloc_off+cur_page_off+8,
                    pad_tail(relocs+#1000*IMAGE_REL_BASED_HIGHLOW, len, 0) )
            end if
            cur_off = 0
            cur_page_off = -1
            while cur_off < reloc_size do
                seek(fn, reloc_off+cur_off) -- перейти к началу следующего/текущего блока
                next_page = get_integer32(fn)
                if next_page > rva then
                    if cur_off = 0 then
                        return mod[i] -- страницы с модифицируемым элементом нет в таблице релокаций
                    end if
                    cur_page_off = cur_off - block_size
                    exit
                end if
                cur_page = next_page
                block_size = get_integer32(fn)
                len = floor( (block_size-8)/2 )
                cur_off += block_size
            end while
            if cur_page_off < 0 then
                return mod[i] -- страницы с модифицируемым элементом нет в таблице релокаций
            end if
            -- считать блок релокаций:
            seek(fn, reloc_off+cur_page_off+8)
            relocs = {}
            for j = 1 to len do
                rec = get_integer16(fn)
                if and_bits(rec, #1000*IMAGE_REL_BASED_HIGHLOW) then
                    relocs &= and_bits(rec, #0FFF)
                end if
            end for
        end if
        rec = rva - cur_page
        k = binary_search(rec, relocs)
        if mod[i]>0 then
            if k>0 then
                return -2
            end if
            relocs = insert(relocs, rec, -k)
        else
            if k<0 then
                return -3
            end if
            relocs = remove(relocs, k)
        end if
    end for
    -- записать измененный блок релокаций:
    if length(relocs)>len then
        return -1
    end if
    fpoke2(fn, reloc_off+cur_page_off+8,
        pad_tail(relocs+#1000*IMAGE_REL_BASED_HIGHLOW, len, 0) )
    return 0 -- OK
end function
