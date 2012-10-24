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
    SEG_SS = #36,
    SEG_DS = #3E,
    SEG_ES = #26,
    SEG_FS = #64,
    SEG_GS = #65

public constant
    JMP_SHORT = #EB,
    JMP_NEAR  = #E9,
    JCC_SHORT = #70, -- + cond
    JCC_NEAR  = {#0F,#80} -- + {0,cond}

public constant
    CALL_NEAR = #E8

public constant
    RET_NEAR = #C3

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

-- Коды регистров:
public constant
    AL = 0, AX = 0, EAX = 0,
    CL = 1, CX = 1, ECX = 1,
    DL = 2, DX = 2, EDX = 2,
    BL = 3, BX = 3, EBX = 3,
    AH = 4, SP = 4, ESP = 4,
    CH = 5, BP = 5, EBP = 5,
    DH = 6, SI = 6, ESI = 6,
    BH = 7, DI = 7, EDI = 7

-- push
public constant
    PUSH_REG    = #50, -- + REG
    PUSH_IMM8   = #6A,
    PUSH_IMM32  = #68

public constant
    POP_REG     = #58 -- + REG

public constant PUSHAD = #60, POPAD = #61

public constant
    MOV_REG_IMM = #B0, -- + 8*width + REG
    MOV_ACC_MEM = #A0, -- + 2*dir + width
    MOV_RM_REG  = #88, -- + 2*dir + width
    MOV_REG_RM  = MOV_RM_REG+2, -- + width
    $

public constant
    XOR_RM_REG = #30 -- + 2*dir + width

public constant LEA = #8D

public constant NOP = #90

public constant MOVZX = {#0F,#B6}, MOVSX = {#0F,#BE}

public constant MOVSB = #A4, MOVSD = #A5, MOVSW = PREFIX_OPERAND_SIZE & MOVSD

-- public constant MOD_MASK = #C0

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
function check_sign_bit(atom x, integer w) -- x - значение, w - ширина в битах (номер бита знака + 1)
    if and_bits(x, power(2, w-1)) then
        x -= power(2, w)
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
