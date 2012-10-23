-- Модуль подпрограмм для патчера
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
        cyr[i+1] = #0410+i -- А-Я
        cyr[i+33] = #0430+i -- а-я
    end for
    
    fpoke4(fn, off+'Ё'*4, #0401)
    fpoke4(fn, off+'ё'*4, #0451)
    fpoke4(fn, off+'А'*4, cyr)
end procedure

-- DEPRECATED: не используется в текущей версии, требует явного указания смещения.
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
        if length(x)>3 then
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

public
function load_trans_file_to_map(sequence fname)
    object line
    sequence x
    map trans = new()
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
        if length(x)>3 then
            x[2] = match_replace("\\r", x[2], "\r")
            x[3] = match_replace("\\r", x[3], "\r")
            if has(trans,x[2]) and debug then
                printf(1,"Warning: there already is <%s> key in the map.\n",{x[2]})
            end if
            put(trans,x[2],x[3])
        end if
    end while
    return trans
end function

-- Утечка памяти при при запуске в скомпилированном виде
constant code=1, rdata = 2, data = 3
public
function get_cross_references(atom fn, sequence relocs, sequence sections, atom image_base)
    atom obj
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
        -- Считываем адрес объекта и преобразуем его в смещение от начала файла:
        obj = rva_to_off(fpeek4u(fn, relocs[i]) - image_base, sections)
        -- Проверяем, находится ли адрес в секциях .rdata или .data:
        if obj >= sections[rdata][SECTION_POFFSET] and obj < sections[data][SECTION_POFFSET]+sections[data][SECTION_PSIZE] then
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

-- Пока не используется
public
function get_cross_references_to_map(atom fn, sequence relocs, sequence sections, atom image_base)
    atom obj
    map xrefs = new()
    for i = 1 to length(relocs) do
        -- Получаем смещение объекта, на который указывает перемещаемый элемент
        -- превращаем адрес в смещение и читаем что по этому смещению находится:
        relocs[i] -= sections[code][SECTION_RVA]
        -- Ссылка должна находиться в секции кода:
        if relocs[i] < 0 or relocs[i]>=sections[code][SECTION_VSIZE] then
            continue
        end if
        relocs[i] += sections[code][SECTION_POFFSET]
        -- Считываем адрес объекта и преобразуем его в смещение от начала файла:
        obj = rva_to_off(fpeek4u(fn, relocs[i]) - image_base, sections)
        -- Проверяем, находится ли адрес в секциях .rdata или .data:
        if obj >= sections[rdata][SECTION_POFFSET] and obj < sections[data][SECTION_POFFSET]+sections[data][SECTION_PSIZE] then
            -- Добавляем смещение объекта в хэш-таблицу
            put(xrefs,obj,relocs[i],APPEND)
        end if
    end for
    return xrefs
end function

-- Подпрограммы для работы с машинным кодом

-- Функция находит начало кода, копирующего данную строку
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

-- Функция исправления длины, прописанной в коде
-- Возвращает:
-- 1 если удалось исправить длину,
-- 0 если требуется кардинальная правка кода,
-- -1 если исправлять не нужно,
-- -2 если не найден код, указыающий длину строки
constant count = #20, count_after = #80
public
function fix_len(atom fn, atom off, integer oldlen, integer len)
    atom next = off+4
    sequence pre = fpeek(fn, {off-count,count}),
             aft = fpeek(fn, {next,count})
    integer r, reg
    integer move_to_reg, move_to_mem, opcode
    sequence modrm
    
    -- По поводу нижеследующего ифа: можно проверять, не идет ли по безусловному переходу инструкция,
    -- указывающая длину строки, и если да, то переход на код, прописывающий нужную длину, а потом переход
    -- на код идущий после кода указывающего старую длину
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
        reg = and_bits(pre[$], #7)
        if reg = EAX then -- mov eax, offset str
            if pre[$-2] = PUSH_IMM8 and pre[$-1] = oldlen then -- push len
                fpoke(fn,off-2,len)
                return 1
            elsif length(aft)>0 and aft[1] = PUSH_IMM8 and aft[2] = oldlen then -- push len
                fpoke(fn,next+1,len)
                return 1
            elsif pre[$-5] = MOV_REG_IMM + 8 + EDI and
                    bytes_to_int(pre[$-4..$-1]) = oldlen then -- mov edi,len ; до
                fpoke4(fn,off-5,len)
                return 1
            elsif length(aft) > 0 and aft[1] = MOV_REG_IMM + 8 + EDI and
                    bytes_to_int(aft[2..5]) = oldlen then -- mov edi,len ; после
                fpoke4(fn,next+1,len)
                return 1
            elsif pre[$-3]=LEA and and_bits(pre[$-2],#F8) = glue_triads(1,EDI,0) then -- lea edi, [reg+len]
                integer disp = check_sign_bit(pre[$-1],8)
                if disp=oldlen then
                    fpoke(fn, off-2, len)
                    return 1
                elsif and_bits(pre[$-2],#07) != ESP then -- lea edi, [reg+(len-содержимое_регистра)]
                    fpoke(fn, off-2, len-oldlen+disp)
                    return 1
                end if
            elsif length(aft)>0 and aft[1] = MOV_REG_RM+1 and and_bits(aft[2],#F8) = glue_triads(3,ECX,0) -- mov ecx, reg
                    and aft[3] = PUSH_IMM8 and aft[4] = oldlen then -- push len
                fpoke(fn,next+3,len)
                return 1
            end if
        elsif reg = ESI then -- mov esi, offset str
            if pre[$-5] = MOV_REG_IMM + 8 + ECX and
                    bytes_to_int(pre[$-4..$-1]) = floor((oldlen+1)/4) then
                r = remainder(oldlen+1,4)
                fpoke4(fn, off-5, floor((len+1-r+3)/4)) -- с учетом инструкций, копирующих остаток строки
                return 1
            elsif pre[$-3] = LEA and and_bits(pre[$-2],#F8) = glue_triads(1,ECX,0) and pre[$-1]=floor((oldlen+1)/4) then
                r = remainder(oldlen+1,4)
                fpoke(fn, off-2, floor((len+1-r+3)/4))
            elsif len > oldlen then
                return -2 -- Не удалось исправить, хотя скорее всего нужно
            end if
        end if
        return -1 -- ? в остальных случаях исправлять длину не нужно ?
    elsif pre[$] = MOV_ACC_MEM+1 or pre[$-1] = MOV_REG_RM+1 then -- mov eax, [] или mov reg, []
        if len > oldlen and len+1 <= align(oldlen+1) then
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
                        if x[1][1] = MOV_REG_RM and sequence(x[2]) then -- Копирование из памяти в регистр
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
                        if x[1][1] = MOV_RM_REG and sequence(x[2]) then -- Копирование из регистра в память
                            modrm = x[2]
                            if modrm[1]<3 and modrm[2] = reg then
                                move_to_mem = i
                                
                                opcode = aft[move_to_reg]
                                fpoke(fn, next+move_to_reg-1, opcode+1) -- Увеличение размера операнда с byte до dword (установкой бита размера операнда)
                                opcode = aft[move_to_mem]
                                fpoke(fn, next+move_to_mem-1, opcode+1) -- Увеличение размера операнда с byte до dword
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
                            
                            fpoke(fn, next+move_to_reg-1, NOP) -- Увеличение размера операнда с word до dword (заменой префикса изменения размера операнда на NOP)
                            fpoke(fn, next+move_to_mem-1, NOP) -- Увеличение размера операнда с word до dword
                            return 1
                        end if
                    end if
                end if
                i = x[$]
            end while
        end if
        return 0 -- Не удалось исправить длину, необходимо править код
    end if
    
    return -1 -- Считаем, что во всех остальных случаях исправление длины не требуется
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

-- В соответствии с битом знака изменить знак числа
function check_sign_bit(atom x, integer w)
    if and_bits(x, power(2, w-1)) then
        x -= power(2, w)
    end if
    return x
end function

-- Функция по данным, полученным из analyse_modrm(), определяет место назначения
function process_operands(sequence x)
    sequence modrm = x[1], sib
    integer basereg, disp -- текущие базовый регистр и смещение
    
    -- Узнаем базовый регистр
    if modrm[3] != 4 then -- без байта SIB (Scale/Index/Base)
        basereg = modrm[3]
    else  -- используется байт SIB
        sib = x[2]
        if sib[1] != 0 or sib[2] != 4 then -- масштаб != 2 pow 0 или указан индексный регистр
            return -1
        end if
        basereg = sib[3]
    end if
    
    if modrm[1] = 0 then -- без смещения
        disp = 0
    else
        disp = x[$-1]
    end if
    
    return {basereg, disp, x[$]} -- x[$] возвращается для совместимости
end function

-- Анализ байта mod r/m и выбор соответствующего типа адресации
-- На входе: набор байт машинного кода. Первый байт - mod r/m
function analyse_modrm(sequence s, integer i)
    sequence modrm, sib
    sequence result
    atom disp = 0
    modrm = triads(s[i])
    i += 1
    result = {modrm}
    if modrm[1] != 3 then -- Не регистровая адресация
        if modrm[1] = 0 and modrm[3] = 5 then
            -- Прямая адресация [imm32]
            result &= bytes_to_int(s[i..i+3])
            i += 4
        else
            if modrm[3] = 4 then
                -- Косвенная адресация по базе с масштабированием
                sib = triads(s[i])
                i += 1
                result = append(result, sib)
            end if
            
            if modrm[1] = 1 then
                disp = check_sign_bit(s[i], 8)
                i += 1
                result &= disp
            elsif modrm[1] = 2 then
                disp = check_sign_bit(bytes_to_int(s[i..i+3]), 32)
                i += 4
                result &= disp
            end if
        end if
    end if
    return result & i -- {{триады байта modrm}, [{триады байта sib},] смещение, i}
end function

-- Попытка вынести анализирующий код в отдельную функцию
-- На входе: набор байт машинного кода
-- На выходе: см. последний return.
function analyse_mach(sequence s, integer i=1)
    integer op, j = i
    sequence modrm, sib
    sequence result
    if s[i] = PREFIX_OPERAND_SIZE then
        i += 1
    end if
    -- Префикс смены режима адресации пока не поддерживается
    op = s[i]
    result = {s[j..i]}
    i += 1
    if and_bits(op, #FE) = MOV_ACC_MEM then
        result &= {bytes_to_int(s[i..i+3]), i+4}
    elsif and_bits(op, #FC) = MOV_RM_REG or op = LEA then
        result &= analyse_modrm(s, i)
    else
        return -1
    end if
    return result -- {{операция}, {modrm}, {sib}, непосредственный операнд, индекс следующей инструкции}
end function

-- Определить длину (в байтах) инструкций, копирующих строку, также нужно определить куда копируется строка
-- На входе: набор байт машинного кода
-- На выходе: см. последний return.
public
function get_length(sequence s, integer len)
    integer i = 1, cur_len = 0 -- текущее количество скопированых байт
    integer op
    integer size -- operand size
    sequence reg = {0,0,0} -- регистры eax/ax/al, ecx/cx/cl, edx/dx/dl
    sequence modrm
    sequence deleted = {}
    object dest = -1 -- {регистр, смещение} -- место назначения
    object x
    object lea = 0
    
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
            i += 4
        elsif and_bits(op, #FC)=MOV_RM_REG then
            x = analyse_modrm(s,i)
            
            if not and_bits(op,1) then
                size = 1 -- флаг размера сброшен, значит копируется 1 байт
            end if
            
            modrm = x[1]
            
            -- Допустимые регистры: eax/ax/al, ecx/cx/cl, edx/dx/dl
            if modrm[2] > DX then
                return -2
            end if
            
            i += 1
            
            if and_bits(op, 2) then -- данные кладутся в регистр
                -- данные берутся с указаного адреса и кладутся в один из регистов
                if modrm[1] = 0 and modrm[3] = 5 then
                    if reg[modrm[2]+1] != 0 then
                        return -3 -- содержимое регистра было не скопировано по месту назначения
                    end if
                    
                    reg[modrm[2]+1] = size
                    deleted &= i -- добавить смещение ссылки в список удаляемых релокаций
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
                
                x = process_operands(x)
                if atom(x) then
                    return -6
                end if
                
                -- Определяем место назначения по минимальному значению disp
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
                return -7 -- регистровая адресация в LEA недопустима
            end if
            
            -- Если используется один из регистров eax, ecx или edx, то
            if modrm[2] <= DX then
                reg[modrm[2]+1] = -1 -- пометить регистр как занятый
            end if
            
            x = process_operands(x)
            if atom(x) then
                return -8
            end if
            
            -- Определяем место назначения по минимальному значению disp
            if atom(dest) then
                dest = x[1..2]
            elsif dest[1] = x[1] and dest[2] > x[2] then
                dest[2] = x[2]
            end if
            
            lea = modrm[2] & x[1..2]
            i = x[$]
        else
            return -9 -- все прочие инструкции
        end if
    end while
    return {i-1, dest, deleted, lea} -- {длина кода, место назначения, смещения ссылок в память, инструкция lea}
end function

-- Функция возвращает машинный код, копирующий требуемое количество байт в нужное место
public
function mach_memcpy(integer src, sequence dest, integer count) -- (адрес, {регистр, смещение}, количество байт)
    integer new_ref_off -- смещение ссылки на источник в генерируемом машинном коде
    sequence mach = {}
    
    -- Сохранение регистров общего назначения в стеке
    mach &= PUSHAD
    
    mach &= (XOR_RM_REG+1) & glue_triads(3,ECX,ECX) & -- XOR ECX, ECX
        (MOV_REG_IMM+CL) & (floor(count+3)/4) -- MOV CL, IMM8
    
    -- Если адрес места назначения еще не находится в регистре edi, кладем его туда:
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
    
    -- Восстановление регистров общего назначения из стека
    mach &= POPAD
    
    return mach & new_ref_off
end function

-- Извлечение строк из исполняемого файла

constant blocksize = 1024

function forbidden(integer i)
    return find(i,"$;<>@^`{|}")
end function

function allowed(integer i)
    return i='\r' or (i>=' ' and i<127 and not forbidden(i))
end function

function letter(integer i)
    return (i>='A' and i<='Z') or (i>='a' and i<='z')
end function

public
function extract_strings(atom fn, sequence objs)
    sequence strings = {}
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
        integer letters = 0
        for j = 1 to length(buf) do
            if buf[j] = 0 then
                len = j-1
                exit
            elsif not allowed(buf[j]) then
                exit
            elsif letter(buf[j]) then
                letters += 1
            end if
        end for
        if len>0 and letters>0 then
            strings = append(strings,{objs[i],buf[1..len]})
        end if
    end for
    return strings
end function

public
function extract_strings_map(atom fn, map xrefs)
    sequence
        objs = keys(xrefs,1),
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
        len = -1
        integer letters = 0
        for j = 1 to length(buf) do
            if buf[j] = 0 then
                len = j-1
                exit
            elsif not allowed(buf[j]) then
                exit
            elsif letter(buf[j]) then
                letters += 1
            end if
        end for
        if len>0 and letters>0 then
            strings = append(strings,{objs[i],buf[1..len]})
        end if
    end for
    return strings
end function
