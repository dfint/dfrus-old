-- ������ ����������� ��� �������
include std/sequence.e
include std/get.e
include std/search.e
include std/convert.e
include std/map.e
include std/error.e
include std/os.e

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

ifdef DEBUG then
    -- pass
elsedef
    constant debug = 0
end ifdef

public
function load_trans_file_to_map(sequence fname)
    object line
    sequence x
    map trans = map:new()
    atom fn = open(fname, "r")
    if fn < 0 then
        return -1
    end if
    while 1 do
        line = gets(fn)
        if atom(line) then
            exit
        end if
        line = match_replace("\\r", line, "\r")
        line = match_replace("\\t", line, "\t")
        x = split(line, '|')
        if length(x)>3 then
            if map:has(trans,x[2]) and debug then
                printf(1,"Warning: there already is '%s' key in the map.\n",{x[2]})
            end if
            map:put(trans,x[2],x[3])
        end if
    end while
    return trans
end function

constant code=1, rdata = 2, data = 3
public
function get_cross_references_to_map(atom fn, sequence relocs, sequence sections, atom image_base)
    atom obj
    map xrefs = map:new()
    for i = 1 to length(relocs) do
        -- �������� �������� �������, �� ������� ��������� ������������ �������
        -- ���������� ����� � �������� � ������ ��� �� ����� �������� ���������:
        relocs[i] -= sections[code][SECTION_RVA]
        -- ������ ������ ���������� � ������ ����:
        if relocs[i] < 0 or relocs[i]>=sections[code][SECTION_VSIZE] then
            continue
        end if
        relocs[i] += sections[code][SECTION_POFFSET]
        -- ��������� ����� ������� � ����������� ��� � �������� �� ������ �����:
        obj = rva_to_off(fpeek4u(fn, relocs[i]) - image_base, sections)
        -- ���������, ��������� �� ����� � ������� .rdata ��� .data:
        if obj >= sections[rdata][SECTION_POFFSET] and obj < sections[data][SECTION_POFFSET]+sections[data][SECTION_PSIZE] then
            -- ��������� �������� ������� � ���-�������
            map:put(xrefs,obj,relocs[i],APPEND)
        end if
    end for
    return xrefs
end function

-- ������������ ��� ������ � �������� �����

-- ������� ������� ������ ����, ����������� ������ ������
public
function get_start(sequence pre)
    integer i = 0
    if and_bits(pre[$-i],#FE) = MOV_ACC_MEM then
        i += 1
    elsif and_bits(pre[$-i-1],#F8) = MOV_RM_REG and and_bits(pre[$-i],#C7) = #05 then
        i += 2
    else
        crash("Failed to find beginning of the instruction: %02x %02x %02x\n",pre)
    end if
    
    if pre[$-i] = PREFIX_OPERAND_SIZE then
        i += 1
    end if
    return i
end function

include disasm.e

-- ������� ����������� �����, ����������� � ����
-- ����������:
-- 1 ���� ������� ��������� �����,
-- 0 ���� ��������� ������������ ������ ����,
-- -1 ���� ���������� �� �����,
-- -2 ���� �� ������ ���, ����������� ����� ������
-- {jmp_from, {code}, jmp_to} - ������ ��� �������� "�����"
constant count = #20, count_after = #80
public
function fix_len(atom fn, atom off, integer oldlen, integer len,
                    object optionals = 0) -- optional debugging params
    atom next = off+4, oldnext
    sequence pre = fpeek(fn, {off-count,count}),
             aft = fpeek(fn, {next,count_after})
    integer r, reg
    integer jmp = 0
    object orig = 0, transl = 0, section = 0, image_base = 0
    if not atom(optionals) then
        orig = optionals[1]
        transl = optionals[2]
        section = optionals[3]
        image_base = optionals[4]
    end if
    
    if aft[1] = JMP_SHORT or aft[1] = JMP_NEAR then
        integer disp -- �������� jmp
        oldnext = next
        if aft[1] = JMP_SHORT then
            disp = check_sign_bit(aft[2],8)
            next += 1 + 1 + disp
        else
            disp = check_sign_bit(bytes_to_int(aft[2..5]),32) -- 1 ����� - near jump, 2-5 - ��������
            next += 1 + 4 + disp
        end if
        jmp = aft[1] -- ��������, ��� ����� �������� ����� �������� �� jmp
        -- ��������� �� jmp � ��������� �������� ���������� ���� ������
        aft = fpeek(fn, {next,count_after})
    elsif aft[1] = CALL_NEAR or and_bits(aft[1], #F0) = JCC_SHORT or
                    (aft[1] = JCC_NEAR[1] and and_bits(aft[2], #F0) = JCC_NEAR[2]) then
        -- �� �������� ��������� � ������� ���������� �� �� �����
        aft = {}
    end if

    if pre[$] = PUSH_IMM32 then -- push offset str
        return -1 -- �������� ������ �� ������, ���������� �� �����
    elsif and_bits(pre[$], #F8) = MOV_REG_IMM + 8 then -- mov reg, offset str
        reg = and_bits(pre[$], #7)
        if reg = EAX then -- mov eax, offset str
            if pre[$-2] = PUSH_IMM8 and pre[$-1] = oldlen then -- push len
                fpoke(fn,off-2,len)
                return 1
            elsif length(aft)>0 and aft[1] = PUSH_IMM8 and aft[2] = oldlen then -- push len
                if not jmp then
                    fpoke(fn, next+1, len)
                    return 1
                elsif jmp = JMP_NEAR then
                    -- ���������� ����� ������� ��������, ���. ��� �������� ����� ������ � ����� ����� ��������:
                    return {oldnext, {PUSH_IMM8, len}, next+2} -- push len8
                else -- jmp = JMP_SHORT
                    return -1 -- �������� �������, ���������� �������� "�����"
                    -- @TODO: ����� ��������� call, �������� �� ����� strlen � ����������� ��������� �� ������ ���������
                end if
            elsif pre[$-5] = MOV_REG_IMM + 8 + EDI and
                    bytes_to_int(pre[$-4..$-1]) = oldlen then -- mov edi,len ; ��
                fpoke4(fn, off-5, len)
                if oldlen = 15 and length(aft)>0 then
                    atom address
                    if debug then
                        address = off_to_rva_ex(next,section)+image_base
                    end if
                    integer i = 1
                    if debug and sequence(orig) and sequence(transl) then
                        printf(1,"Translating '%s' to '%s':\n", {orig,transl})
                    end if
                    while i<length(aft) do
                        object x = disasm(address,aft,i)
                        if atom(x) then
                            exit
                        end if
                        if debug then
                            printf(1,"%08x\t%s\n",x[1..$-1])
                        end if
                        if aft[i]=CALL_NEAR then
                            -- @TODO: �������� �������� �� ����������� ������� mov [esp+N], edi
                            -- exit
                            atom disp = check_sign_bit(bytes_to_int(aft[i+1..i+4]),32)
                            return {next+i-1,
                                (MOV_RM_IMM + 1) & glue_triads(1,0,ESI) & #14 & int_to_bytes(15), -- mov [esi+14h], 15
                                next+i+4+disp}
                        end if
                        i = x[$]
                    end while
                    
                    if debug then
                        puts(1,'\n')
                    end if
                end if
                return 1
            elsif length(aft)>0 and aft[1] = MOV_REG_IMM + 8 + EDI and
                    bytes_to_int(aft[2..5]) = oldlen then -- mov edi,len ; �����
                if not jmp then
                    fpoke4(fn, next+1, len)
                    return 1
                elsif jmp = JMP_NEAR then
                    -- ���������� ����� ������� ��������, ���. ��� �������� ����� ������ � ������ ����� ��������:
                    return {oldnext,
                        (MOV_REG_IMM + 8 + EDI) & int_to_bytes(len), -- mov edi, len32
                        next+5}
                else
                    -- return -1 -- �������� �������, ���������� �������� "�����" - ������� ��� ��� � ����
                    return {oldnext, next}
                end if
            elsif pre[$-3]=LEA and and_bits(pre[$-2],#F8) = glue_triads(1,EDI,0) then -- lea edi, [reg+len]
                integer disp = check_sign_bit(pre[$-1],8)
                if disp=oldlen then
                    fpoke(fn, off-2, len)
                    return 1
                elsif and_bits(pre[$-2],#07) != ESP then -- lea edi, [reg+(len-����������_��������)]
                    fpoke(fn, off-2, len-oldlen+disp)
                    return 1
                end if
            elsif length(aft)>0 and aft[1] = MOV_REG_RM+1 and and_bits(aft[2],#F8) = glue_triads(3,ECX,0) -- mov ecx, reg
                    and aft[3] = PUSH_IMM8 and aft[4] = oldlen then -- push len
                if not jmp then
                    fpoke(fn, next+3, len)
                    return 1
                else
                    -- mov ecx,reg ++ push len �� ������������
                    return -1
                end if
            elsif and_bits(pre[$-1],#F8) = PUSH_REG and jmp = JMP_NEAR then
                -- push reg; mov eax, offset str; jmp near somewhere
                reg = and_bits(pre[$-1],7)
                if reg != EAX and reg != EBP and -- pop eax ������ ����� ������, pop ebp - "������ ������"
                        not ((pre[$-5]=LEA and and_bits(pre[$-4],#F8)=glue_triads(1,reg,0)) or -- lea modrm disp8
                             (pre[$-7]=LEA and and_bits(pre[$-6],#F8)=glue_triads(2,reg,0)) or -- lea modrm disp32
                             (pre[$-8]=LEA and pre[$-7]=glue_triads(2,reg,4))) and -- lea modrm sib disp32
                        not  (pre[$-3]=MOV_REG_RM+1 and and_bits(pre[$-2],#F8)=glue_triads(3,reg,0)) then -- mov reg1, reg2
                    -- @TODO: ��������� ��� �������!!! �������� ����� ����� ���� ��������� ����� ����� push ��� jmp
                    -- ���������� ����� ������� ��������, ���. ��� �������� ����� ������ � ������ ����� ��������:
                    return {oldnext, {POP_REG+reg, PUSH_IMM8, len}, next} -- pop REG \\ push len
                end if
            -- elsif length(aft)>0 and and_bits(aft[1], #F8) = PUSH_REG and aft[2] = JMP_NEAR then
                -- mov eax, offset str; push reg; jmp near somewhere - �� ������� �� ������ ������
            end if
        elsif reg = ESI then -- mov esi, offset str
            if pre[$-5] = MOV_REG_IMM + 8 + ECX and -- mov ecx, (len+1)/4
                    bytes_to_int(pre[$-4..$-1]) = floor((oldlen+1)/4) then
                r = remainder(oldlen+1,4)
                fpoke4(fn, off-5, floor((len+1-r+3)/4)) -- � ������ ����������, ���������� ������� ������
                return 1
            elsif pre[$-3] = LEA and and_bits(pre[$-2],#F8) = glue_triads(1,ECX,0) and pre[$-1]=floor((oldlen+1)/4) then -- lea ecx, [reg+(len+1)/4]
                r = remainder(oldlen+1,4)
                fpoke(fn, off-2, floor((len+1-r+3)/4))
            elsif len > oldlen then
                return -2 -- �� ������� ���������, ���� ������ ����� �����
            end if
        end if
        return -1 -- ? � ��������� ������� ���������� ����� �� ����� ?
    elsif pre[$] = MOV_ACC_MEM+1 or pre[$-1] = MOV_REG_RM+1 then -- mov eax, [] ��� mov reg, []
        if len > oldlen and len+1 <= align(oldlen+1) then
            -- ������ �� ����� �������, ��������� ����������� ����������� ����
            integer move_to_reg, move_to_mem, opcode
            sequence modrm
            r = remainder(oldlen+1,4)
            next = off - get_start(pre)
            aft = fpeek(fn, {next,count_after})
            integer i = 1, flag = 0
            reg = -1
            while i < length(aft) and flag < 2 do
                object x = analyse_mach(aft,i)
                if atom(x) then
                    return 0
                end if
                if r=1 then
                    if flag = 0 then
                        if x[1][1] = MOV_REG_RM and sequence(x[2]) then -- ����������� �� ������ � �������
                            modrm = x[2]
                            if modrm[1]=0 and modrm[3]=5 then
                                reg = modrm[2]
                                move_to_reg = i
                                flag += 1
                            end if
                        elsif x[1][1] = MOV_ACC_MEM then
                            reg = EAX
                            move_to_reg = i
                            flag += 1
                        end if
                    else
                        if x[1][1] = MOV_RM_REG and sequence(x[2]) then -- ����������� �� �������� � ������
                            modrm = x[2]
                            if modrm[1]<3 and modrm[2] = reg then
                                move_to_mem = i
                                
                                opcode = aft[move_to_reg]
                                fpoke(fn, next+move_to_reg-1, opcode+1) -- ���������� ������� �������� � byte �� dword (���������� ���� ������� ��������)
                                opcode = aft[move_to_mem]
                                fpoke(fn, next+move_to_mem-1, opcode+1) -- ���������� ������� �������� � byte �� dword
                                return 1
                            end if
                        end if
                    end if
                else
                    if x[1][1] = PREFIX_OPERAND_SIZE then
                        if flag = 0 then
                            move_to_reg = i
                            flag += 1
                        else
                            move_to_mem = i
                            
                            fpoke(fn, next+move_to_reg-1, NOP) -- ���������� ������� �������� � word �� dword (������� �������� ��������� ������� �������� �� NOP)
                            fpoke(fn, next+move_to_mem-1, NOP) -- ���������� ������� �������� � word �� dword
                            return 1
                        end if
                    end if
                end if
                i = x[$]
            end while
        end if
        return 0 -- �� ������� ��������� �����, ���������� ������������ ����������� ����
    end if
    
    return -1 -- �������, ��� �� ���� ��������� ������� ����������� ����� �� ���������
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

-- ������������ ����. ���������� ����� (� ������) ����������, ���������� ������, ����� ����� ���������� ���� ���������� ������
-- �� �����: ����� ���� ��������� ����
-- �� ������: ��. ��������� return.
public
function get_length(sequence s, integer len)
    integer i = 1, cur_len = 0 -- ������� ���������� ������������ ����
    integer op
    integer size -- operand size
    sequence reg = {0,0,0} -- �������� eax/ax/al, ecx/cx/cl, edx/dx/dl
    sequence modrm
    sequence deleted = {}
    object dest = -1 -- {�������, ��������} -- ����� ����������
    object x
    object lea = 0
    
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
            i += 4
        elsif and_bits(op, #FC)=MOV_RM_REG then
            x = analyse_modrm(s,i)
            
            if not and_bits(op,1) then
                size = 1 -- ���� ������� �������, ������ ���������� 1 ����
            end if
            
            modrm = x[1]
            
            -- ���������� ��������: eax/ax/al, ecx/cx/cl, edx/dx/dl
            if modrm[2] > DX then
                return -2
            end if
            
            i += 1
            
            if and_bits(op, 2) then -- ������ �������� � �������
                -- ������ ������� � ��������� ������ � �������� � ���� �� ��������
                if modrm[1] = 0 and modrm[3] = 5 then
                    if reg[modrm[2]+1] != 0 then
                        return -3 -- ���������� �������� ���� �� ����������� �� ����� ����������
                    end if
                    
                    reg[modrm[2]+1] = size
                    deleted &= i -- �������� �������� ������ � ������ ��������� ���������
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
                
                x = process_operands(x)
                if atom(x) then
                    return -6
                end if
                
                -- ���������� ����� ���������� �� ������������ �������� disp
                if atom(dest) then
                    dest = x[1..2]
                elsif dest[1] = x[1] and dest[2] > x[2] then
                    dest[2] = x[2]
                end if
                
                cur_len += size
            end if
            i = x[$]
        elsif op = LEA then
            x = analyse_modrm(s,i)
            modrm = x[1]
            if modrm[1] = 3 then
                return -7 -- ����������� ��������� � LEA �����������
            end if
            
            -- ���� ������������ ���� �� ��������� eax, ecx ��� edx, ��
            if modrm[2] <= DX then
                reg[modrm[2]+1] = -1 -- �������� ������� ��� �������
            end if
            
            x = process_operands(x)
            if atom(x) then
                return -8
            end if
            
            -- ���������� ����� ���������� �� ������������ �������� disp
            if atom(dest) then
                dest = x[1..2]
            elsif dest[1] = x[1] and dest[2] > x[2] then
                dest[2] = x[2]
            end if
            
            lea = modrm[2] & x[1..2]
            i = x[$]
        else
            return -9 -- ��� ������ ����������
        end if
    end while
    return {i-1, dest, deleted, lea} -- {����� ����, ����� ����������, �������� ������ � ������, ���������� lea}
end function

-- ������� ���������� �������� ���, ���������� ��������� ���������� ���� � ������ �����
public
function mach_memcpy(integer src, sequence dest, integer count) -- (�����, {�������, ��������}, ���������� ����)
    integer new_ref_off -- �������� ������ �� �������� � ������������ �������� ����
    sequence mach = {}
    
    -- ���������� ��������� ������ ���������� � �����
    mach &= PUSHAD
    
    mach &= (XOR_RM_REG+1) & glue_triads(3,ECX,ECX) & -- XOR ECX, ECX
        (MOV_REG_IMM+CL) & (floor(count+3)/4) -- MOV CL, IMM8
    
    -- ���� ����� ����� ���������� ��� �� ��������� � �������� edi, ������ ��� ����:
    if not equal(dest,{EDI,0}) then
        if dest[2] != 0 then
            -- LEA EDI, [reg+imm] :
            mach &= lea(EDI, dest)
        else
            -- MOV EDI, reg
            mach &= (MOV_RM_REG+1) & glue_triads(3,dest[1],EDI)
        end if
    end if
    
    mach &= (MOV_REG_IMM+8+ESI) -- MOV ESI, ...
    new_ref_off = length(mach)
    mach &= int_to_bytes(src) -- IMM32
    
    mach &= REP & MOVSD -- REP MOVSD
    
    -- �������������� ��������� ������ ���������� �� �����
    mach &= POPAD
    
    return mach & new_ref_off
end function

-- ���������� ����� �� ������������ �����

constant blocksize = 1024

function forbidden(integer i)
    return find(i,"$;@^`{|}")
end function

function allowed(integer i)
    return i='\r' or (i>=' ' and i<127 and not forbidden(i))
end function

function letter(integer i)
    return (i>='A' and i<='Z') or (i>='a' and i<='z')
end function

-- �������� ������ ����� � ���� ������ ��� {��������, ������}
sequence strings
function check_string(object key, object val, object fn, integer progress_code)
    object buf
    integer len
    if progress_code <= 0 then
        -- map is empty or the last call
        return strings
    end if
    -- integer fn = user_data[1]
    -- ��������� ������ �� �������� �����:
    if length(strings)>0 and key <= strings[$][1]+length(strings[$][2]) then
        return 0
    end if
    -- ��������� ���� ������:
    seek(fn, key)
    buf = get_bytes(fn, blocksize)
    if atom(buf) then
        return -1
    end if
    -- ���������, �������� �� ������ ������ �������
    len = -1
    integer letters = 0
    for i = 1 to length(buf) do
        if buf[i] = 0 then
            len = i-1
            exit
        elsif not allowed(buf[i]) then
            exit
        elsif letter(buf[i]) then
            letters += 1
        end if
    end for
    if len>0 and letters>0 then
        strings = append(strings, {key, buf[1..len]})
    end if
    return 0
end function

public
function extract_strings_map(atom fn, map xrefs)
    strings = {}
    return for_each(xrefs,routine_id("check_string"),fn,1,1)
end function

-- ��������� ���������� ����-���� � ����� ������ � ������������� � ���������� ������
public
function add_to_new_section(integer fn, atom dest, sequence s, integer alignment = 4)
    integer aligned = align(length(s),alignment)
    s = pad_tail(s,aligned,0)
    fpoke(fn,dest,s)
    return dest + aligned
end function
