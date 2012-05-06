-- ������ ����������� ��� �������
include std/sequence.e
include std/get.e
include std/search.e
include std/convert.e

include patcher.e
include pe.e

public
procedure patch_unicode_table(atom fn, atom off)
    sequence cyr = repeat(0,64)
    for i = 0 to 31 do
        cyr[i+1] = #0410+i -- �-�
        cyr[i+33] = #0430+i -- �-�
    end for
    
    fpoke4(fn, off+'�'*4, #0401)
    fpoke4(fn, off+'�'*4, #0451)
    fpoke4(fn, off+'�'*4, cyr)
end procedure

public
function load_trans_file(sequence fname)
    object line
    sequence x, off, trans = {}
    atom fn = open(fname, "r")
    if fn < 0 then
        return -1
    end if
    while 1 do
        line = gets(fn)
        if atom(line) then
            exit
        end if
        x = split(line, '|')
        if length(x)>=3 then
            off = value('#' & x[1])
            if off[1] = GET_SUCCESS then
                x[1] = off[2]
                x[2] = match_replace("\\r", x[2], "\r")
                x[3] = match_replace("\\r", x[3], "\r")
                if length(trans)=0 or x[1]>trans[$][1] then
                    trans = append(trans,x)
                else
                    -- todo: ��������� � ������ �����
                end if
            end if
        end if
    end while
    close(fn)
    return trans
end function

constant code=1, rdata = 2
public
function get_cross_references(atom fn, sequence relocs, sequence sections, atom image_base)
    atom ref, obj
    sequence objs = {}, xrefs = {}
    integer k

    for i = 1 to length(relocs) do
        -- �������� �������� �������, �� ������� ��������� ������������ �������
        -- ���������� ����� � �������� � ������ ��� �� ����� �������� ���������:
        -- relocs[i] = rva_to_off(relocs[i], sections)
        relocs[i] -= sections[code][SECTION_RVA]
        -- ������ ������ ���������� � ������ ����:
        if relocs[i] < 0 or relocs[i]>=sections[code][SECTION_VSIZE] then
            continue
        end if
        relocs[i] += sections[code][SECTION_POFFSET]
        
        -- �������� �������� ������� �� ������ ������ rdata:
        obj = fpeek4u(fn, relocs[i]) - image_base - sections[rdata][SECTION_RVA]
        -- ���������, ��������� �� ����� � ������ .rdata:
        if obj >= 0 and obj < sections[rdata][SECTION_VSIZE] then
            -- ����������� ��������� ����� ������� � ��� �������� �� ������ �����:
            obj += sections[rdata][SECTION_POFFSET]
            
            -- ��������� �������� ������� � ������������� ������� ��������
            k = binary_search(obj, objs)
            if k < 0 then -- ���� �������� ������� �� �������, ��
                -- �������� ��� � ������� �������� ��������:
                objs = insert(objs, obj, -k)
                -- � �������� ������ �� ������ ��� ����������� ������ � ������� ������:
                xrefs = insert(xrefs, {relocs[i]}, -k)
            else -- ���� �������� ������� ��� ���� � �������, ��
                -- ���������� ������ �� ���� � ������� ������:
                xrefs[k] &= relocs[i]
            end if
        end if
    end for
    return {objs, xrefs}
end function

-- ������� ������� ������ ����, ����������� ������ ������
public
function get_start(sequence pre)
    -- sequence pre = fpeek(fn, {off-count,count})
    integer i = 0
    if and_bits(pre[$-i],#FE) = MOV_ACC_MEM then
        i += 1
    elsif and_bits(pre[$-i-1],#F8) = MOV_RM_REG and and_bits(pre[$-i],#C7) = #05 then
        i += 2
    else
        return #DEADBEEF
    end if
    
    if pre[$-i] = PREFIX_OPERAND_SIZE then
        i += 1
    end if
    return i
end function

-- ��������� n �� ���������� �����, �������� edge � �������� ��� n
public
function align(atom n, atom edge = 4)
    return and_bits(n+edge-1, -edge)
end function

include disasm.e

-- ������� ����������� �����, ����������� � ����
-- ����������: 0 ���� �� ������� ���������, 1 ���� �������, -1 ���� ���������� �� �����
constant count = #18, count_after = #50
public
function fix_len(atom fn, atom off, integer oldlen, integer len)
    atom operand, next = off+4
    sequence pre = fpeek(fn, {off-count,count}),
             aft = fpeek(fn, {next,count})
    integer r
    integer move_to_reg, move_to_mem, opcode
    
    if aft[1] = JMP_SHORT or
        aft[1] = JMP_NEAR or
            aft[1] = CALL_NEAR or
                and_bits(aft[1], #F0) = JCC_SHORT or
                    (aft[1] = JCC_NEAR[1] and and_bits(aft[2], #F0) = JCC_NEAR[2]) then
        aft = {}
    end if
    
    if pre[$] = PUSH_IMM32 then -- push offset str
        return -1 -- �������� ������ �� ������, ���������� �� �����
    elsif and_bits(pre[$], #F8) = MOV_REG_IMM + 8 then -- mov reg, offset str
        if pre[$-2] = PUSH_IMM8 and pre[$-1] = oldlen then -- push len
            fpoke(fn,off-2,len)
            return 1
        elsif pre[$] = MOV_REG_IMM + 8 + EAX and -- mov eax, offset str
                pre[$-5] = MOV_REG_IMM + 8 + EDI and
                bytes_to_int(pre[$-4..$-1]) = oldlen then -- mov edi,len
            fpoke4(fn,off-5,len)
            
            return 1
        elsif length(aft)>0 and aft[1] = PUSH_IMM8 and aft[2] = oldlen then -- push len
            fpoke(fn,next+1,len) -- ?
            return 1
        elsif pre[$] = MOV_REG_IMM + 8 + ESI and
                pre[$-5] = MOV_REG_IMM + 8 + ECX and
                    bytes_to_int(pre[$-4..$-1]) = floor(oldlen/4) then -- � ������ rep movsd
            -- fpoke4(fn, off-5, floor((len+1+3)/4))
            r = remainder(oldlen+1,4)
            fpoke4(fn, off-5, floor((len+1-r+3)/4)) -- � ������ ����������, ���������� ������� ������
            return 1
        else
            return -1 -- ? � ��������� ������� ���������� ����� �� ����� ?
        end if
    elsif pre[$] = MOV_ACC_MEM+1 or pre[$-1] = MOV_REG_RM+1 then -- mov eax, [] ��� mov reg, []
        if len > oldlen and len+1 <= align(oldlen+1) then
            r = remainder(oldlen+1,4)
            next = off - get_start(pre)
            aft = fpeek(fn, {next,count_after})
            if r = 1 then
                move_to_reg = find(MOV_REG_RM, aft)
                if and_bits(aft[move_to_reg+1], #C7) != #05 then -- �������� ����� MOD R/M
                    move_to_reg = find(MOV_ACC_MEM, aft)
                end if
                
                move_to_mem = find_from(MOV_RM_REG, aft, move_to_reg+1)
                if and_bits(aft[move_to_mem+1], #C0) != #40 then -- �������� ����� MOD R/M
                    move_to_mem = -move_to_mem
                end if
                
                if move_to_reg > 0 and move_to_mem > move_to_reg then
                    opcode = aft[move_to_reg]
                    fpoke(fn, next+move_to_reg-1, opcode+1) -- ���������� ������� �������� � byte �� dword (���������� ���� ������� ��������)
                    opcode = aft[move_to_mem]
                    fpoke(fn, next+move_to_mem-1, opcode+1) -- ���������� ������� �������� � byte �� dword
                    return 1
                end if
            else
                move_to_reg = find(PREFIX_OPERAND_SIZE, aft)
                move_to_mem = find_from(PREFIX_OPERAND_SIZE, aft, move_to_reg+1)
                
                if move_to_reg > 0 and move_to_mem > 0 then
                    fpoke(fn, next+move_to_reg-1, NOP) -- ���������� ������� �������� � word �� dword (������� �������� ��������� ������� �������� �� NOP)
                    fpoke(fn, next+move_to_mem-1, NOP) -- ���������� ������� �������� � word �� dword
                    return 1
                end if
            end if
        else
            -- stub
        end if
    end if
    
    return 0
end function

public
procedure fix_off(atom fn, atom ref, atom new_rva)
    atom next = ref+4
    sequence pre = fpeek(fn, {ref-count, count}),
            aft = fpeek(fn, {next, count})
    if pre[$] = PUSH_IMM32 or and_bits(pre[$], #F8) = MOV_REG_IMM + 8 then
        fpoke4(fn, ref, new_rva)
    else
        -- stub
    end if
end procedure

-- ������� ���� �� ������
function triads(integer x)
    return and_bits(floor(x/{#40,#08,#1}), #7)
end function

-- ���������� ���� sib � ���������������� �������
function process_operands(sequence s, integer i, sequence modrm)
    sequence sib
    integer basereg, disp -- ������� ������� ������� � ��������
    
    -- ������ ������� �������
    if modrm[3] != 4 then -- ��� ����� SIB (Scale/Index/Base)
        basereg = modrm[3]
    else -- ������������ ���� SIB
        sib = triads(s[i]) -- ������� ���� SIB �� ��������� ����
        if sib[1] != 0 or sib[2] != 4 then -- ������� != 2 pow 0 ��� ������ ��������� �������
            return -1
        end if
        basereg = sib[3]
        i += 1 -- SIB 1 ����
    end if
    
    -- ������ ��������
    if modrm[1] = 0 then -- ��� ��������
        disp = 0
    elsif modrm[1] = 1 then -- ������������ ��������
        disp = s[i]
        if and_bits(disp, #80) then -- �������� ���� �����
            disp -= #100
        end if
        i += 1 -- �������� 1 ����
    else -- ��������������� ��������
        disp = bytes_to_int(s[i..i+3])
        if and_bits(disp, #80000000) then -- �������� ���� �����
            disp -= #100000000
        end if
        i += 4 -- �������� 4 �����
    end if
    
    return {basereg, disp, i}
end function

-- ���������� ����� (� ������) ����������, ���������� ������, ����� ����� ���������� ���� ���������� ������
public
function get_length(sequence s, integer len)
    integer i = 1, cur_len = 0 -- ������� ���������� ������������ ����
    integer op
    integer size -- operand size
    sequence reg = {0,0,0} -- �������� eax/ax/al, ecx/cx/cl, edx/dx/dl
    sequence modrm, sib
    sequence deleted = {}
    object dest = -1 -- {�������, ��������} -- ����� ����������
    object x
    
    while cur_len < len do
        size = 4 -- ������ �������� ��-��������� 4 �����
        if s[i] = PREFIX_OPERAND_SIZE then
            size = 2
            i += 1
        end if
        
        op = s[i]
        i += 1 -- ���������� 1 ����
        
        if and_bits(op, #FE)=MOV_ACC_MEM then -- � ����������� �������� ������ � ��������� ������
            if reg[AX+1] > 0 then
                return -1 -- ���������� ������������ �� ���� ����������� �� ����� ����������
            end if
            
            if and_bits(op, 1)=0 then
                size = 1 -- ���� ������� �������, ������ ���������� 1 ����
            end if
            
            reg[AX+1] = size -- � ����������� �������� ������ �������� size
            deleted &= i -- �������� �������� ������ � ������ ��������� ���������
            i += 4 -- ���������������� ������� 4 �����
        elsif and_bits(op, #FC)=MOV_RM_REG then
            if not and_bits(op,1) then
                size = 1 -- ���� ������� �������, ������ ���������� 1 ����
            end if
            
            -- ��������� ���� MOD R/M �� ��������� ����:
            modrm = triads(s[i])
            
            -- ���������� ��������: eax/ax/al, ecx/cx/cl, edx/dx/dl
            if modrm[2] > DX then
                return -2
            end if
            
            i += 1 -- MOD R/M 1 ����
            
            if and_bits(op, 2) then -- ������ �������� � �������
                -- ������ ������� � ��������� ������ � �������� � ���� �� ��������
                if modrm[1] = 0 and modrm[3] = 5 then
                    if reg[modrm[2]+1] != 0 then
                        return -3 -- ���������� �������� ���� �� ����������� �� ����� ����������
                    end if
                    
                    reg[modrm[2]+1] = size
                    deleted &= i -- �������� �������� ������ � ������ ��������� ���������
                    i += 4 -- ���������������� ������� 4 �����
                else
                    return -4
                end if
            else -- ������ ������� �� ��������
                if reg[modrm[2]+1] != size or -- ������ ����������� �������� �� ����� ������� ����������� �����������
                        modrm[1] = 3 or -- ����������� �� �������� � �������
                        (modrm[1] = 0 and modrm[3] = 5) then -- ����������� �� ����������������� ������
                    return -5
                end if
                reg[modrm[2]+1] = 0
                
                x = process_operands(s, i, modrm)
                if atom(x) then
                    return -6
                end if
                i = x[3]
                
                -- ���������� ����� ���������� �� ������������ �������� disp
                if atom(dest) then
                    dest = x[1..2]
                elsif dest[1] = x[1] and dest[2] > x[2] then
                    dest[2] = x[2]
                end if
                
                cur_len += size
            end if
        elsif op = LEA then
            -- ��������� ���� MOD R/M �� ��������� ����:
            modrm = triads(s[i+1])
            if modrm[1] = 3 then
                return -7 -- ����������� ��������� � LEA �����������
            end if
            
            -- ���� ������������ ���� �� ��������� eax, ecx ��� edx, ��
            if modrm[2] <= DX then
                reg[modrm[2]+1] = -1 -- �������� ������� ��� �������
            end if
            
            i += 1 -- MOD R/M 1 ����
            
            x = process_operands(s, i, modrm)
            if atom(x) then
                return -8
            end if
            i = x[3]
            
            -- ���������� ����� ���������� �� ������������ �������� disp
            if atom(dest) then
                dest = x[1..2]
            elsif dest[1] = x[1] and dest[2] > x[2] then
                dest[2] = x[2]
            end if
        else
            return -9 -- ��� ������ ����������
        end if
    end while
    return {i-1, dest, deleted} -- {����� ����, ����� ����������, �������� ������ � ������}
end function

public integer new_ref_off -- �������� ������ �� �������� � ������������ �������� ����
-- ������� ���������� �������� ���, ���������� ��������� ���������� ���� � ������ �����
public
function mach_memcpy(integer src, sequence dest, integer count) -- (�����, {�������, ��������}, ���������� ����)
    sequence mach = {}
    integer md
    mach &= (XOR_RM_REG+1) & (#C0+#08*ECX+ECX) & -- XOR ECX, ECX
        (MOV_REG_IMM+CL) & (floor(count+3)/4) & -- MOV CL, IMM8
        (MOV_REG_IMM+8+ESI) -- MOV ESI, ...
    new_ref_off = length(mach)
    mach &= int_to_bytes(src) -- IMM32
    mach &= PUSH_REG + EDI
    -- LEA EDI, [reg+imm] :
    mach &= LEA
    if dest[2] = 0 and dest[1] != EBP then
        md = 0 -- ��� ��������
    elsif dest[2] >= -128 and dest[2] < 128 then
        md = 1 -- ������������ ��������
    else
        md = 2 -- ��������������� ��������
    end if
    
    if dest[1] = ESP then
        mach &= #40*md + #08*EDI + 4 -- ���� mod r/m
        mach &= 0 + #08*4 + dest[1] -- ���� sib
    else
        mach &= #40*md + #08*EDI + dest[1] -- ���� mod r/m
    end if
    
    if md = 1 then
        mach &= dest[2]
    elsif md = 2 then
        mach &= int_to_bytes(dest[2])
    end if
    
    mach &= REP & MOVSD -- nuff said
    
    mach &= POP_REG + EDI
    
    return mach
end function

constant blocksize = 1024

function forbidden(integer i)
    return find(i,"$;<>@^_`{|}")
end function

function allowed(integer i)
    return i='\r' or (i>=' ' and i<127 and not forbidden(i))
end function

function extract_strings(atom fn, sequence xref_table)
    sequence
        objs  = xref_table[1],
        xrefs = xref_table[2],
        strings = {}
    object buf
    integer len
    
    for i = 1 to length(objs) do
        -- ��������� ������ �� �������� �����:
        if length(strings)>0 and objs[i]<=strings[$][1]+len then
            continue
        end if
        -- ��������� ���� ������:
        seek(fn, objs[i])
        buf = get_bytes(fn, blocksize)
        if atom(buf) then
            return -1
        end if
        -- ���������, �������� �� ������ ������ �������:
        len = -1
        for j = 1 to length(buf) do
            if buf[j] = 0 then
                len = j-1
                exit
            elsif not allowed(buf[j]) then
                exit
            end if
        end for
        if len>0 then
            strings = append(strings,{objs[i],buf[1..len]})
        end if
    end for
    return strings
end function
