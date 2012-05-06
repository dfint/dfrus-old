-- Модуль подпрограмм для патчера
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
        cyr[i+1] = #0410+i -- А-Я
        cyr[i+33] = #0430+i -- а-я
    end for
    
    fpoke4(fn, off+'Ё'*4, #0401)
    fpoke4(fn, off+'ё'*4, #0451)
    fpoke4(fn, off+'А'*4, cyr)
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
                    -- todo: вставлять в нужное место
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
        -- Получаем смещение объекта, на который указывает перемещаемый элемент
        -- превращаем адрес в смещение и читаем что по этому смещению находится:
        -- relocs[i] = rva_to_off(relocs[i], sections)
        relocs[i] -= sections[code][SECTION_RVA]
        -- Ссылка должна находиться в секции кода:
        if relocs[i] < 0 or relocs[i]>=sections[code][SECTION_VSIZE] then
            continue
        end if
        relocs[i] += sections[code][SECTION_POFFSET]
        
        -- Получаем смещение объекта от начала секции rdata:
        obj = fpeek4u(fn, relocs[i]) - image_base - sections[rdata][SECTION_RVA]
        -- Проверяем, находится ли адрес в секции .rdata:
        if obj >= 0 and obj < sections[rdata][SECTION_VSIZE] then
            -- Преобразуем считанный адрес объекта в его смещение от начала файла:
            obj += sections[rdata][SECTION_POFFSET]
            
            -- Добавляем смещение объекта в сортированную таблицу смещений
            k = binary_search(obj, objs)
            if k < 0 then -- Если смещение объекта не найдено, то
                -- добавить его в таблицу смещений объектов:
                objs = insert(objs, obj, -k)
                -- и добавить ссылку на только что добавленный объект в таблицу ссылок:
                xrefs = insert(xrefs, {relocs[i]}, -k)
            else -- Если смещение объекта уже есть в таблице, то
                -- дописываем ссылку на него в таблицу ссылок:
                xrefs[k] &= relocs[i]
            end if
        end if
    end for
    return {objs, xrefs}
end function

-- Функция находит начало кода, копирующего данную строку
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

-- Округлить n до ближайшего числа, кратного edge и большего чем n
public
function align(atom n, atom edge = 4)
    return and_bits(n+edge-1, -edge)
end function

include disasm.e

-- Функция исправления длины, прописанной в коде
-- Возвращает: 0 если не удалось исправить, 1 если удалось, -1 если исправлять не нужно
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
        return -1 -- передача строки по ссылке, исправлять не нужно
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
                    bytes_to_int(pre[$-4..$-1]) = floor(oldlen/4) then -- а дальше rep movsd
            -- fpoke4(fn, off-5, floor((len+1+3)/4))
            r = remainder(oldlen+1,4)
            fpoke4(fn, off-5, floor((len+1-r+3)/4)) -- с учетом инструкций, копирующих остаток строки
            return 1
        else
            return -1 -- ? в остальных случаях исправлять длину не нужно ?
        end if
    elsif pre[$] = MOV_ACC_MEM+1 or pre[$-1] = MOV_REG_RM+1 then -- mov eax, [] или mov reg, []
        if len > oldlen and len+1 <= align(oldlen+1) then
            r = remainder(oldlen+1,4)
            next = off - get_start(pre)
            aft = fpeek(fn, {next,count_after})
            if r = 1 then
                move_to_reg = find(MOV_REG_RM, aft)
                if and_bits(aft[move_to_reg+1], #C7) != #05 then -- проверка байта MOD R/M
                    move_to_reg = find(MOV_ACC_MEM, aft)
                end if
                
                move_to_mem = find_from(MOV_RM_REG, aft, move_to_reg+1)
                if and_bits(aft[move_to_mem+1], #C0) != #40 then -- проверка байта MOD R/M
                    move_to_mem = -move_to_mem
                end if
                
                if move_to_reg > 0 and move_to_mem > move_to_reg then
                    opcode = aft[move_to_reg]
                    fpoke(fn, next+move_to_reg-1, opcode+1) -- Увеличение размера операнда с byte до dword (установкой бита размера операнда)
                    opcode = aft[move_to_mem]
                    fpoke(fn, next+move_to_mem-1, opcode+1) -- Увеличение размера операнда с byte до dword
                    return 1
                end if
            else
                move_to_reg = find(PREFIX_OPERAND_SIZE, aft)
                move_to_mem = find_from(PREFIX_OPERAND_SIZE, aft, move_to_reg+1)
                
                if move_to_reg > 0 and move_to_mem > 0 then
                    fpoke(fn, next+move_to_reg-1, NOP) -- Увеличение размера операнда с word до dword (заменой префикса изменения размера операнда на NOP)
                    fpoke(fn, next+move_to_mem-1, NOP) -- Увеличение размера операнда с word до dword
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

-- Разбить байт на триады
function triads(integer x)
    return and_bits(floor(x/{#40,#08,#1}), #7)
end function

-- Обработать байт sib и непосредственный операнд
function process_operands(sequence s, integer i, sequence modrm)
    sequence sib
    integer basereg, disp -- текущие базовый регистр и смещение
    
    -- Узнаем базовый регистр
    if modrm[3] != 4 then -- без байта SIB (Scale/Index/Base)
        basereg = modrm[3]
    else -- используется байт SIB
        sib = triads(s[i]) -- разбить байт SIB на отдельные поля
        if sib[1] != 0 or sib[2] != 4 then -- масштаб != 2 pow 0 или указан индексный регистр
            return -1
        end if
        basereg = sib[3]
        i += 1 -- SIB 1 байт
    end if
    
    -- Узнаем смещение
    if modrm[1] = 0 then -- без смещения
        disp = 0
    elsif modrm[1] = 1 then -- однобайтовое смещение
        disp = s[i]
        if and_bits(disp, #80) then -- проверка бита знака
            disp -= #100
        end if
        i += 1 -- смещение 1 байт
    else -- четырехбайтовое смещение
        disp = bytes_to_int(s[i..i+3])
        if and_bits(disp, #80000000) then -- проверка бита знака
            disp -= #100000000
        end if
        i += 4 -- смещение 4 байта
    end if
    
    return {basereg, disp, i}
end function

-- Определить длину (в байтах) инструкций, копирующих строку, также нужно определить куда копируется строка
public
function get_length(sequence s, integer len)
    integer i = 1, cur_len = 0 -- текущее количество скопированых байт
    integer op
    integer size -- operand size
    sequence reg = {0,0,0} -- регистры eax/ax/al, ecx/cx/cl, edx/dx/dl
    sequence modrm, sib
    sequence deleted = {}
    object dest = -1 -- {регистр, смещение} -- место назначения
    object x
    
    while cur_len < len do
        size = 4 -- размер операнда по-умолчанию 4 байта
        if s[i] = PREFIX_OPERAND_SIZE then
            size = 2
            i += 1
        end if
        
        op = s[i]
        i += 1 -- инструкция 1 байт
        
        if and_bits(op, #FE)=MOV_ACC_MEM then -- в аккумулятор кладутся данные с указаного адреса
            if reg[AX+1] > 0 then
                return -1 -- содержимое аккумулятора не было скопировано по месту назначения
            end if
            
            if and_bits(op, 1)=0 then
                size = 1 -- флаг размера сброшен, значит копируется 1 байт
            end if
            
            reg[AX+1] = size -- в аккумулятор положили данные размером size
            deleted &= i -- добавить смещение ссылки в список удаляемых релокаций
            i += 4 -- непосредственный операнд 4 байта
        elsif and_bits(op, #FC)=MOV_RM_REG then
            if not and_bits(op,1) then
                size = 1 -- флаг размера сброшен, значит копируется 1 байт
            end if
            
            -- Разбиваем байт MOD R/M на отдельные поля:
            modrm = triads(s[i])
            
            -- Допустимые регистры: eax/ax/al, ecx/cx/cl, edx/dx/dl
            if modrm[2] > DX then
                return -2
            end if
            
            i += 1 -- MOD R/M 1 байт
            
            if and_bits(op, 2) then -- данные кладутся в регистр
                -- данные берутся с указаного адреса и кладутся в один из регистов
                if modrm[1] = 0 and modrm[3] = 5 then
                    if reg[modrm[2]+1] != 0 then
                        return -3 -- содержимое регистра было не скопировано по месту назначения
                    end if
                    
                    reg[modrm[2]+1] = size
                    deleted &= i -- добавить смещение ссылки в список удаляемых релокаций
                    i += 4 -- непосредственный операнд 4 байта
                else
                    return -4
                end if
            else -- данные берутся из регистра
                if reg[modrm[2]+1] != size or -- размер содержимого регистра не равен размеру копируемого содержимого
                        modrm[1] = 3 or -- копирование из регистра в регистр
                        (modrm[1] = 0 and modrm[3] = 5) then -- копирование по непосредственному адресу
                    return -5
                end if
                reg[modrm[2]+1] = 0
                
                x = process_operands(s, i, modrm)
                if atom(x) then
                    return -6
                end if
                i = x[3]
                
                -- Определяем место назначения по минимальному значению disp
                if atom(dest) then
                    dest = x[1..2]
                elsif dest[1] = x[1] and dest[2] > x[2] then
                    dest[2] = x[2]
                end if
                
                cur_len += size
            end if
        elsif op = LEA then
            -- Разбиваем байт MOD R/M на отдельные поля:
            modrm = triads(s[i+1])
            if modrm[1] = 3 then
                return -7 -- регистровая адресация в LEA недопустима
            end if
            
            -- Если используется один из регистров eax, ecx или edx, то
            if modrm[2] <= DX then
                reg[modrm[2]+1] = -1 -- пометить регистр как занятый
            end if
            
            i += 1 -- MOD R/M 1 байт
            
            x = process_operands(s, i, modrm)
            if atom(x) then
                return -8
            end if
            i = x[3]
            
            -- Определяем место назначения по минимальному значению disp
            if atom(dest) then
                dest = x[1..2]
            elsif dest[1] = x[1] and dest[2] > x[2] then
                dest[2] = x[2]
            end if
        else
            return -9 -- все прочие инструкции
        end if
    end while
    return {i-1, dest, deleted} -- {длина кода, место назначения, смещения ссылок в память}
end function

public integer new_ref_off -- смещение ссылки на источник в генерируемом машинном коде
-- Функция возвращает машинный код, копирующий требуемое количество байт в нужное место
public
function mach_memcpy(integer src, sequence dest, integer count) -- (адрес, {регистр, смещение}, количество байт)
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
        md = 0 -- без смещения
    elsif dest[2] >= -128 and dest[2] < 128 then
        md = 1 -- однобайтовое смещение
    else
        md = 2 -- четырехбайтовое смещение
    end if
    
    if dest[1] = ESP then
        mach &= #40*md + #08*EDI + 4 -- байт mod r/m
        mach &= 0 + #08*4 + dest[1] -- байт sib
    else
        mach &= #40*md + #08*EDI + dest[1] -- байт mod r/m
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
        -- исключить ссылки на середины строк:
        if length(strings)>0 and objs[i]<=strings[$][1]+len then
            continue
        end if
        -- считываем блок данных:
        seek(fn, objs[i])
        buf = get_bytes(fn, blocksize)
        if atom(buf) then
            return -1
        end if
        -- проверяем, является ли данный объект строкой:
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
