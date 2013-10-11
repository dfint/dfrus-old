-- Коды машинных операций x86

-- Префиксы команд:
public constant
    REP = #F3, REPE = REP, REPZ  = REPE,
    REPNE = #F2, REPNZ = REPNE,
    LOCK  = #F0 -- Префикс блокировки шины

public constant
    PREFIX_ADDR = #67, -- Префикс замены размера адреса
    PREFIX_OPERAND_SIZE = #66 -- Префикс замены размера операнда

-- Префиксы замены сегментов:
public constant
    SEG_CS = #2E,
    SEG_DS = #3E,
    SEG_ES = #26,
    SEG_SS = #36,
    SEG_FS = #64,
    SEG_GS = #65

public constant
    JMP_NEAR  = #E9,
    JMP_SHORT = JMP_NEAR+2,
    JMP_INDIR = {#0F,#25},
    JCC_SHORT = #70, -- + cond
    JCC_NEAR  = {#0F,#80} -- + {0,cond}

public constant
    CMP_RM_IMM = #80

public constant
    CALL_NEAR   = #E8,
    CALL_INDIR  = {#FF, #10}

public constant
    RET_NEAR    = #C3,
    RET_FAR     = #CB,
    RET_NEAR_N  = #C2,
    RET_FAR_D   = #CA,
    LEAVE       = #C9,
    INT3        = #CC

-- Коды условий
public constant
    COND_O   = #0, -- Overflow
    COND_NO  = COND_O+1, -- Not Overflow
    COND_B   = #2, COND_NAE = COND_B, COND_C = COND_B, -- Below, Not Above or Equal, Carry
    COND_NB  = COND_B+1, COND_AE = COND_NB, COND_NC = COND_NB, -- Not Below, Above or Equal, Not Carry
    COND_E   = #4, COND_Z = COND_E, -- Equal, Zero
    COND_NE  = COND_E+1, COND_NZ = COND_NE, -- Not Equal, Not Zero
    COND_BE  = #6, COND_NA = COND_BE, -- Below or equal, Not Above
    COND_NBE = COND_BE+1, COND_A = COND_NBE, -- Not Below or Equal, Above
    COND_S   = #8, -- Sign
    COND_NS  = COND_S+1, -- Not Sign
    COND_P   = #A, COND_PE = COND_P, -- Parity, Parity Even
    COND_NP  = COND_P+1, COND_PO = COND_NP, -- Not Parity, Parity Odd
    COND_L   = #C, COND_NGE = COND_L, -- Less, Not Greater or Equal
    COND_NL  = COND_L+1, COND_GE = COND_NL, -- Not Less, Greater or Equal
    COND_LE  = #E, COND_NG = COND_LE, -- Less or Equal, Not Greater
    COND_NLE = COND_LE+1, COND_G = COND_NLE, -- Not Less or Equal, Greater
    $

constant conds = {"o","no","b","nb","z","nz","na","a","s","ns","p","np","l","nl","ng","g"}

-- Коды регистров:
public constant
    AL = 0, AX = 0, EAX = 0, ES = 0,
    CL = 1, CX = 1, ECX = 1, CS = 1,
    DL = 2, DX = 2, EDX = 2, SS = 2,
    BL = 3, BX = 3, EBX = 3, DS = 3,
    AH = 4, SP = 4, ESP = 4, FS = 4,
    CH = 5, BP = 5, EBP = 5, GS = 5,
    DH = 6, SI = 6, ESI = 6,
    BH = 7, DI = 7, EDI = 7

constant regs = {
    {"al","ax","eax"},
    {"cl","cx","ecx"},
    {"dl","dx","edx"},
    {"bl","bx","ebx"},
    {"ah","sp","esp"},
    {"ch","bp","ebp"},
    {"dh","si","esi"},
    {"bh","di","edi"}
}

constant seg_regs = {"es","cs","ss","ds","fs","gs"}

-- push
public constant
    PUSH_REG    = #50, -- + REG
    PUSH_IMM32  = #68,
    PUSH_IMM8   = PUSH_IMM32 + 2,
    PUSH_INDIR  = {#FF,#30}, -- + размер смещение * 40h + базовый регистр [& SIB]
    PUSHFD      = #9C, POPFD = #9D,
    $

public constant
    POP_REG     = #58, -- + REG
    POP_RM      = #8F

public constant PUSHAD = #60, POPAD = #61

public constant
    MOV_REG_IMM = #B0, -- + 8*width + REG
    MOV_ACC_MEM = #A0, -- + 2*dir + width
    MOV_RM_REG  = #88, -- + 2*dir + width
    MOV_REG_RM  = MOV_RM_REG+2, -- + width
    MOV_MEM_IMM8 = #C6,
    MOV_MEM_IMM = MOV_MEM_IMM8+1,
    MOV_RM_SEG  = #8C, -- + 2*dir
    $

public constant
    XOR_RM_REG  = #30, -- + 2*dir + width
    SUB_RM_REG  = #28, -- + 2*dir + width
    SUB_REG_RM  = SUB_RM_REG+2, -- + width
    OP_RM_IMM   = #80,
    OP_RM_IMM32 = #80, -- + width
    OP_RM_IMM8  = #83,
    $

public constant
    CMP_ACC_IMM = #3C, -- + width
    $

public constant LEA = #8D

public constant NOP = #90

public constant MOVZX = {#0F,#B6}, MOVSX = {#0F,#BE}

public constant MOVSB = #A4, MOVSD = #A5, MOVSW = PREFIX_OPERAND_SIZE & MOVSD

-- Разбить байт на триады
public
function triads(integer x)
    return and_bits(floor(x/{#40,#08,#1}), #7)
end function

-- Склеить 3 триады
public
function glue_triads(integer a, integer b, integer c)
    return a*#40 + b*#08 + c
end function

include std/convert.e

public
function lea(integer dest, sequence src)
    integer md
    sequence mach = {}
    mach &= LEA
    if src[2] = 0 and src[1] != EBP then
        md = 0 -- без смещения
    elsif src[2] >= -128 and src[2] < 128 then
        md = 1 -- однобайтовое смещение
    else
        md = 2 -- четырехбайтовое смещение
    end if
    
    if src[1] = ESP then
        mach &= glue_triads(md,dest,4) -- байт mod r/m
        mach &= glue_triads(0,4,src[1]) -- байт sib
    else
        mach &= glue_triads(md,dest,src[1]) -- байт mod r/m
    end if
    
    if md = 1 then
        mach &= src[2]
    elsif md = 2 then
        mach &= int_to_bytes(src[2])
    end if
    return mach
end function

-- Округлить n до ближайшего числа, кратного edge, большего или равного n
public
function align(atom n, atom edge = 4)
    return and_bits(n+edge-1, -edge)
end function

-- В соответствии с битом знака изменить знак числа
public
function check_sign_bit(atom x, integer w = 8) -- x - значение, w - ширина в битах (номер бита знака + 1)
    atom pow2w = power(2, w)
    if x >= pow2w then
        w = 32
        pow2w = power(2, w)
    end if
    if and_bits(x, pow2w/2) then
        x -= pow2w
    end if
    return x
end function

-- Функция по данным, полученным из analyse_modrm(), определяет место назначения
public
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
public
function analyse_modrm(sequence s, integer i)
    sequence modrm, sib
    sequence result
    atom disp = 0
    integer j = i
    if length(s)<i then
        return length(s)-i
    end if
    modrm = triads(s[i])
    i += 1
    result = {modrm}
    if modrm[1] != 3 then -- Не регистровая адресация
        if length(s)<i then
            return length(s)-i
        end if
        if modrm[1] = 0 and modrm[3] = 5 then
            -- Прямая адресация [imm32]
            if length(s)<i+3 then
                return length(s)-i-3
            end if
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
                if length(s)<i then
                    return length(s)-i
                end if
                disp = check_sign_bit(s[i], 8)
                i += 1
                result &= disp
            elsif modrm[1] = 2 then
                if length(s)<i+3 then
                    return length(s)-i-3
                end if
                disp = check_sign_bit(bytes_to_int(s[i..i+3]), 32)
                i += 4
                result &= disp
            end if
        end if
    end if
    -- @todo: привести к однозначому виду: если sib нет, вместо него писать -1, если смещения нет - 0
    return result & i -- {{триады байта modrm}, [{триады байта sib},] [смещение,] i}
end function

-- Попытка вынести анализирующий код в отдельную функцию
-- На входе: набор байт машинного кода
-- На выходе: см. последний return.
public
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

include std/math.e

-- Преобразование числа в 16-ричное представление, принятое в ассемблере (вида 0ABCDh)
function asmhex(atom x, integer width=1)
    sequence s = ""
    if x<0 then
        s &= '-'
        x = -x
    end if
    s &= sprintf(sprintf("%%0%dx",width),x)
    -- Если по модулю больше или равно 0Ah, то добавляем h в конце
    if x >= #A then
        s &= 'h'
    end if
    -- Если начинается с буквы, то добавлять 0 в начало:
    if s[1]>='A' and s[1]<='F' then
        s = '0' & s
    end if
    return s
end function

-- Приведение вывода функции analyse_modrm к унифицированному виду
-- Вид возвращаемого значения:
-- { регистр, {масштаб (-1 если нет), индексный регистр (-1 если нет), базовый регистр (-1 если нет), смещение (0 если нет)} }
function unify_operands(sequence x)
    -- ? x
    integer op1 = x[1][2]
    object op2
    if x[1][1] = 3 then -- Регистровая адресация
        op2 = x[1][3]
    else
        if x[1][1] = 0 and x[1][3] = 5 then -- Непосредственная адресация
            op2 = {-1, -1, -1, x[$-1]} -- {масштаб, индекс, база, смещение}
        else
            if x[1][3] != 4 then -- Указание способа адресации при помощи MOD R/M
                op2 = {0, x[1][3], -1, 0}
            else -- Указание способа адресации при помощи SIB
                op2 = x[2] & 0
                if x[2][2] = 4 then
                    op2[2] = -1
                end if
            end if
            
            if x[1][1] > 0 then
                op2[$] = x[$-1]
            end if
        end if
    end if
    return {op1, op2}
end function

function op_to_text(object op)
    -- ? op
    sequence text
    if atom(op) then
        text = regs[op+1][3]
    else
        text = "["
        if op[1]>0 then
            text &= sprintf("%d*",power(2,op[1]))
        end if
        if op[2]>=0 then
            text &= regs[op[2]+1][3]
        end if
        if op[3]>=0 then
            if op[2]>= 0 then
                text &= '+'
            end if
            text &= regs[op[3]+1][3]
        end if
        if op[4]!=0 then
            if op[2]>=0 or op[3]>=0 then
                if op[4]>=0 then
                    text &= '+'
                else
                    text &= '-'
                    op[4]=-op[4]
                end if
            end if
            text &= asmhex(op[4])
        elsif op[2]=-1 and op[3]=-1 then
            text &= '0'
        end if
        text &= ']'
    end if
    return text
end function

-- Если flag установлен, поменять местами первый и второй элемент
function swap(sequence x, integer flag=1)
    if flag then
        return {x[2],x[1]}
    else
        return x
    end if
end function

constant seg_tags = {"cs:","ds:","es:","ss:","fs:","gs:"}
constant op_sizes = {"byte","word","dword"}

constant mnemo = {"add","or","adc","sbb","add","sub","xor","cmp"}

-- Опкоды однобайтовых операций без аргумнтов:
sequence op_1byte_nomask_noargs = repeat(-1,256)
op_1byte_nomask_noargs[NOP+1]           = "nop"
op_1byte_nomask_noargs[RET_NEAR+1]      = "retn"
op_1byte_nomask_noargs[PUSHFD+1]        = "pushfd"
op_1byte_nomask_noargs[PUSHAD+1]        = "pushad"
op_1byte_nomask_noargs[POPFD+1]         = "popfd"
op_1byte_nomask_noargs[POPAD+1]         = "popad"
op_1byte_nomask_noargs[LEAVE+1]         = "leave"
op_1byte_nomask_noargs[INT3+1]          = "int3"

-- Опкоды операций без маски
sequence op_nomask = repeat(-1,256)
op_nomask[CALL_NEAR+1] = "call near"
op_nomask[JMP_NEAR+1]  = "jmp near"
op_nomask[JMP_SHORT+1] = "jmp short"

-- Опкоды с неизменяемой частью по маске #FC, флагами направления и размера операнда
sequence op_FC_dir_width = repeat(-1,256)
op_FC_dir_width[MOV_RM_REG+1] = "mov"
op_FC_dir_width[SUB_RM_REG+1] = "sub"
op_FC_dir_width[XOR_RM_REG+1] = "xor"

-- Набросок функции, по введенному машинному коду возвращающей его ассемблерное представление
public
function disasm(integer start_addr, sequence s, integer i=1)
    sequence text, op_prefix={}
    integer j = i
    integer addr = start_addr+i-1
    integer seg
    integer op_size = 0
    -- sequence prefixes = {}
    -- Прежде всего, нужно разобрать префиксы. Некоторые префиксы (REP, например) можно отображать как отдельные инструкции
    seg = find(s[i],{SEG_CS,SEG_DS,SEG_ES,SEG_SS,SEG_FS,SEG_GS})
    if seg then
        op_prefix = seg_tags[seg]
        -- prefixes = prepend(prefixes, s[i])
        i += 1
    end if
    
    if s[i]=PREFIX_OPERAND_SIZE then
        -- prefixes = prepend(prefixes, s[i])
        op_size = 1
        i += 1
    end if
    
    if sequence(op_1byte_nomask_noargs[s[i]+1]) then
        text = op_1byte_nomask_noargs[s[i]+1]
        i += 1
    elsif s[i] = RET_NEAR_N then
        integer immediate = bytes_to_int(s[i+1..i+2])
        text = sprintf("retn %s",{asmhex(immediate)})
        i += 3
    elsif s[i] = CALL_NEAR or s[i] = JMP_NEAR then
        sequence mnemonix = op_nomask[s[i]+1]
        if length(s)<i+4 then
            return length(s)-(i+4)
        end if
        atom immediate = addr+5+check_sign_bit(bytes_to_int(s[i+1..i+4]),32)
        text = sprintf("%s %s",{mnemonix, asmhex(immediate)})
        i += 5
    elsif s[i] = JMP_SHORT then
        if length(s)<i+1 then
            return length(s)-(i+1)
        end if
        integer immediate = addr+2+check_sign_bit(s[i+1])
        text = sprintf("jmp short %s",{asmhex(immediate)})
        i += 2
    elsif and_bits(s[i],#F8) = JCC_SHORT then
        if length(s)<i+1 then
            return length(s)-(i+1)
        end if
        integer immediate = addr+2+check_sign_bit(s[i+1])
        integer condition = and_bits(s[i],7)
        text = sprintf("j%s short %s",{conds[condition+1], asmhex(immediate)})
        i += 2
    elsif s[i] = LEA then
        object x = analyse_modrm(s,i+1)
        if atom(x) then
            return x
        end if
        i = x[$]
        x = unify_operands(x)
        text = sprintf("lea %s, %s", {op_to_text(x[1]), op_to_text(x[2])})
    elsif and_bits(s[i],#FC) = OP_RM_IMM then
        integer flags = and_bits(s[i],3)
        if flags != 2 then
            object x = analyse_modrm(s,i+1)
            sequence mnemonix = mnemo[x[1][2]+1]
            if atom(x) then
                return x
            end if
            
            i = x[$]
            x = unify_operands(x)
            text = mnemonix & ' '
            if not atom(x[2]) then
                if flags = 0 then
                    text &= "byte "
                elsif op_size = 1 then
                    text &= "word "
                else
                    text &= "dword "
                end if
            end if
            text &= op_to_text(x[2]) & ", "
            atom immediate
            if flags = 1 then
                if length(s)<i+3 then
                    return s-(i+3)
                end if
                immediate = bytes_to_int(s[i..i+3])
                i += 4
            else -- flags = 0 or flags = 3
                if length(s)<i then
                    return length(s)-i
                end if
                immediate = s[i]
                i += 1
            end if
            text &= asmhex(immediate)
        end if
    elsif sequence(op_FC_dir_width[and_bits(s[i],#FC)+1]) then
        -- Операция между регистром и регистром/памятью с флагом направления
        sequence mnemonix = op_FC_dir_width[and_bits(s[i],#FC)+1]
        integer d = and_bits(s[i],2)
        integer size = and_bits(s[i],1)
        object x = analyse_modrm(s,i+1)
        if atom(x) then
            return x
        end if
        i = x[$]
        x = unify_operands(x)
        sequence reg = regs[x[1]+1][1+size*2-op_size]
        text = sprintf("%s %s, %s", {mnemonix} & swap({reg, op_prefix & op_to_text(x[2])}, not d))
    elsif and_bits(s[i],#FE) = MOV_MEM_IMM8 then
        object x = analyse_modrm(s,i+1)
        integer size = and_bits(s[i],1)
        if atom(x) then
            return x
        end if
        if x[1][2] = 0 then
            i = x[$]
            x = unify_operands(x)
            if length(s)<i+3 then
                return length(s)-(i+3)
            end if
            atom immediate
            sequence size_spec
            if size=0 then
                immediate = s[i]
                size_spec = "byte"
                i += 1
            elsif op_size = 1 then
                immediate = bytes_to_int(s[i..i+1])
                size_spec = "word"
                i += 2
            else
                immediate = bytes_to_int(s[i..i+3])
                size_spec = "dword"
                i += 4
            end if
            text = sprintf("mov %s %s, %s", {size_spec, op_to_text(x[2]), asmhex(immediate)})
        end if
    elsif and_bits(s[i],#FD) = MOV_RM_SEG then
        integer d = and_bits(s[i],2)
        object x = analyse_modrm(s,i+1)
        if atom(x) then
            return x
        end if
        i = x[$]
        x = unify_operands(x)
        text = sprintf("mov %s, %s", swap({seg_regs[x[1]+1], op_prefix & op_to_text(x[2])}, not d))
    elsif and_bits(s[i],#FC) = MOV_ACC_MEM then
        integer d = and_bits(s[i],2)
        if length(s)<i+4 then
            return length(s)-(i+4)
        end if
        atom immediate = bytes_to_int(s[i+1..i+4])
        text = sprintf("mov %s, %s", swap({regs[EAX+1][3],op_prefix&'['&asmhex(immediate)&']'},d))
        i += 5
    elsif and_bits(s[i],#FE) = CMP_ACC_IMM then
        integer size = and_bits(s[i],1)
        i += 1
        atom immediate
        sequence acc
        if size then
            immediate = bytes_to_int(s[i..i+3])
            acc = "eax"
            i += 4
        else
            immediate = s[i]
            acc = "al"
            i += 1
        end if
        text = sprintf("cmp %s, %s", {acc, asmhex(immediate)})
    elsif and_bits(s[i],#F0) = MOV_REG_IMM then
        integer size = and_bits(s[i],8)/8
        integer reg = and_bits(s[i],7)
        i += 1
        atom immediate
        if size then
            immediate = bytes_to_int(s[i..i+3])
            i += 4
        else
            immediate = s[i]
            i += 1
        end if
        text = sprintf("mov %s, %s", {regs[reg+1][1+size*2], asmhex(immediate)})
    elsif and_bits(s[i],#F8) = PUSH_REG then
        integer reg = and_bits(s[i],7)
        text = sprintf("push %s",{regs[reg+1][3]})
        i += 1
    elsif and_bits(s[i],#FD) = PUSH_IMM32 then
        integer size = and_bits(s[i],2)
        atom immediate
        if size then
            if length(s)<i+1 then
                return length(s)-(i+4)
            end if
            immediate = s[i+1]
            i += 2
        else
            if length(s)<i+4 then
                return length(s)-(i+4)
            end if
            immediate = bytes_to_int(s[i+1..i+4])
            i += 5
        end if
        text = sprintf("push %s",{asmhex(immediate)})
    elsif and_bits(s[i],#F8) = POP_REG then
        integer reg = and_bits(s[i],7)
        text = sprintf("pop %s",{regs[reg+1][3]})
        i += 1
    elsif s[i] = POP_RM then
        object x = analyse_modrm(s,i+1)
        if atom(x) then
            return x
        end if
        i = x[$]
        x = unify_operands(x)
        text = sprintf("pop dword %s", {op_to_text(x[2])})
    elsif s[i] = #FF then
        i += 1
        if s[i] = JMP_INDIR[2] then
            atom immediate = bytes_to_int(s[i+1..i+4])
            text = sprintf("jmp dword %s[%s]",{op_prefix,asmhex(immediate)})
            i += 5
        elsif and_bits(s[i],#38) = PUSH_INDIR[2] then
            object x = analyse_modrm(s,i) -- байт mod r/m накладывается на опкод
            if atom(x) then
                return x
            end if
            i = x[$]
            x = unify_operands(x)
            text = sprintf("push dword %s%s", {op_prefix, op_to_text(x[2])})
        elsif and_bits(s[i],#38) = CALL_INDIR[2] then
            object x = analyse_modrm(s,i) -- байт mod r/m накладывается на опкод
            if atom(x) then
                return x
            end if
            i = x[$]
            x = unify_operands(x)
            text = sprintf("call dword %s%s", {op_prefix, op_to_text(x[2])})
        end if
    end if
    
    if not object(text) then
        i = j
        text = sprintf("db %s", {asmhex(s[i])})
        i += 1
    end if
    
    return {addr,text,i}
end function
