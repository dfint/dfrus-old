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
        if length(x)>3 and length(x[2])>0 then
            if map:has(trans,x[2]) and debug then
                printf(1,"Warning: there already is '%s' key in the map. Previously stored value is replaced.\n",{x[2]})
            end if
            map:put(trans,x[2],x[3])
        end if
    end while
    return trans
end function

public constant code=1, rdata = 2, data = 3
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

constant MAX_LEN = 80 -- ����������� ��� ���������� ������ �� strlen()
function mach_strlen(sequence ins)
    return {
        PUSH_REG + ECX, -- push ecx
        XOR_RM_REG+1, glue_triads(3, ECX, ECX), -- xor ecx, ecx
        -- @@:
        #80, #3c, #08, #00, -- cmp byte [eax+ecx], 0
        #74, #0B, -- jz success
        #81, #F9, MAX_LEN, #00, #00, #00, -- cmp ecx, MAX_LEN
        JCC_SHORT+COND_G, #03+length(ins), -- jg skip
        INC_REG + ECX, -- inc ecx
        JMP_SHORT, #EF -- jmp @b
        -- success:
    } &
    ins & -- ; some code
    -- skip:
    POP_REG+ECX -- pop ecx
end function

function find_instruction(sequence aft, integer instruct)
    integer i = 1
    while i<length(aft) do
        object x = disasm(0,aft,i)
        if atom(x) then
            exit
        end if
        if aft[i]=instruct then
            return i
        end if
        i = x[$]
    end while
    return 0
end function

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
    elsif aft[1] = CALL_NEAR then
        aft = aft[1..5]  -- leave enough to work with near calls
    elsif and_bits(aft[1], #F0) = JCC_SHORT or
                    (aft[1] = JCC_NEAR[1] and and_bits(aft[2], #F0) = JCC_NEAR[2]) then
        aft = {}
    end if

    if pre[$] = PUSH_IMM32 then -- push offset str
        return -1 -- �������� ������ �� ������, ���������� �� �����
    elsif and_bits(pre[$], #F8) = MOV_REG_IMM + 8 then -- mov reg, offset str
        reg = and_bits(pre[$], #7)
        if reg = EAX then -- mov eax, offset str
            if bytes_to_int(pre[$-4..$-1]) = oldlen then
                fpoke4(fn, off-5, len)
                if pre[$-5] = MOV_REG_IMM + 8 + EDI then  -- mov edi, len before
                    -- fpoke4(fn, off-5, len)
                    if oldlen = 15 and length(aft)>0 then
                        -- Sample code for this case:
                        -- mov edi, 0fh
                        -- mov eax, strz_You_last_spoke__db24d8
                        -- lea esi, [esp+40h]
                        -- mov [esp+54h], edi  ; Equivalent to mov [esi+14h], edi
                        -- mov dword ptr [esp+50h], 0
                        -- mov byte ptr [esp+40h], 0
                        -- call sub_40f650
                        
                        atom address = 0
                        if debug then
                            address = off_to_rva_ex(next,section) + image_base
                        end if
                        
                        integer mov_esp = 0
                        integer i = 1
                        while i<=length(aft) do
                            object x = disasm(address,aft,i)
                            if atom(x) then
                                exit
                            end if
                            if aft[i]=MOV_RM_REG+1 and and_bits(aft[i+1],#3F)=glue_triads(0,EDI,4) and  -- mov [esp+N], edi
                                    aft[i+2]=glue_triads(0,ESP,4) then
                                mov_esp = 1
                            elsif aft[i]=CALL_NEAR then
                                if mov_esp then
                                    atom disp = check_sign_bit(bytes_to_int(aft[i+1..i+4]),32)
                                    return {next+i-1,
                                        (MOV_RM_IMM + 1) & glue_triads(1,0,ESI) & #14 & int_to_bytes(15), -- mov [esi+14h], 15
                                        next+i+4+disp} & aft[i]
                                else
                                    exit
                                end if
                            end if
                            i = x[$]
                        end while
                    end if
                    return 1
                end if
                return 1
            elsif pre[$-2] = PUSH_IMM8 and pre[$-1] = oldlen then -- push short len before
                fpoke(fn, off-2, len)
                return 1
            elsif length(aft)>0 and aft[1] = PUSH_IMM8 and aft[2] = oldlen then -- push len after
                if jmp = JMP_NEAR then
                    return {oldnext,
                        {PUSH_IMM8, len},
                        next+2, jmp} -- instuction after mov edi, len
                elsif jmp = JMP_SHORT then
                    integer i = find_instruction(aft,CALL_NEAR)
                    if i>0 then
                        atom disp = check_sign_bit(bytes_to_int(aft[i+1..i+4]),32)
                        return {next+(i-1),
                            mach_strlen({MOV_RM_REG+1, glue_triads(1,ECX,4), glue_triads(0,4,ESP), 8}), -- mov [ESP+8], ECX
                            next+i+4+disp} & aft[i]
                    end if
                else
                    fpoke(fn, next+1, len)
                    return 1
                end if
                return -1
            elsif pre[$-1]=MOV_REG_RM+1 and and_bits(pre[$],#F8)=glue_triads(3,EDI,0) then
                -- mov edi,reg; mov eax, offset str
                -- �� ���� �� �����������
                integer i = find_instruction(aft, CALL_NEAR)
                if i>0 then
                    atom disp = check_sign_bit(bytes_to_int(aft[i+1..i+4]),32)
                    return {next+(i-1),
                        mach_strlen({MOV_REG_RM+1, glue_triads(3,EDI,ECX)}), -- mov edi, ecx
                        next+i+4+disp} & CALL_NEAR
                end if
            elsif length(aft)>0 and aft[1] = MOV_REG_IMM + 8 + EDI and
                    bytes_to_int(aft[2..5]) = oldlen then -- mov edi,len ; �����
                if jmp = JMP_NEAR then
                    return {oldnext,
                        MOV_REG_IMM + 8 + EDI & int_to_bytes(len),
                        next+5, jmp} -- instuction after mov edi, len
                elsif jmp = JMP_SHORT then
                    integer i = find_instruction(aft, CALL_NEAR)
                    if i>0 then
                        atom disp = check_sign_bit(bytes_to_int(aft[i+1..i+4]),32)
                        return {next+(i-1),
                            mach_strlen({MOV_REG_RM+1, glue_triads(3,EDI,ECX)}), -- mov edi, ecx
                            next+i+4+disp} & CALL_NEAR
                    end if
                else
                    fpoke4(fn, next+1, len)
                    return 1
                end if
                return -1
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

-- ��������� ���������� � ���� ������������������ ���� � ������������� 
public
function add_to_new_section(integer fn, atom dest, sequence s, integer alignment = 4)
    integer aligned = align(length(s),alignment)
    s = pad_tail(s,aligned,0)
    fpoke(fn,dest,s)
    return dest + aligned
end function
