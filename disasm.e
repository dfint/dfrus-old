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
    PUSH_REG   = #50, -- + REG
    PUSH_IMM8  = #6A,
    PUSH_IMM32 = #68

public constant
    MOV_REG_IMM   = #B0, -- + 8*width + REG
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

-- function mod_reg_rm(integer mod, integer reg, integer rm)
    -- return mod*#40 + reg*#08 + rm
-- end function

-- function scale_index_base(integer scale, integer ireg, integer breg)
    -- return scale*#40 + ireg*#08 + breg
-- end function
