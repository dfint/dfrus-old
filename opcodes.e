-- Коды машинных операций x86

-- Коды условий
public enum
    COND_O   = #0, -- Overflow
    COND_NO, -- Not Overflow
    COND_B,  COND_NAE = COND_B,  COND_C  = COND_B, -- Below, Not Above or Equal, Carry
    COND_NB, COND_AE  = COND_NB, COND_NC = COND_NB, -- Not Below, Above or Equal, Not Carry
    COND_E,  COND_Z   = COND_E, -- Equal, Zero
    COND_NE, COND_NZ  = COND_NE, -- Not Equal, Not Zero
    COND_BE, COND_NA  = COND_BE, -- Below or equal, Not Above
    COND_A,  COND_NBE = COND_A, -- Above, Not Below or Equal
    COND_S,  -- Sign
    COND_NS, -- Not Sign
    COND_P,  COND_PE  = COND_P, -- Parity, Parity Even
    COND_NP, COND_PO  = COND_NP, -- Not Parity, Parity Odd
    COND_L,  COND_NGE = COND_L, -- Less, Not Greater or Equal
    COND_NL, COND_GE  = COND_NL, -- Not Less, Greater or Equal
    COND_LE, COND_NG  = COND_LE, -- Less or Equal, Not Greater
    COND_G,  COND_NLE = COND_G, -- Not Less or Equal, Greater
    $

-- Коды регистров:
public enum
    AL = 0, CL, DL, BL, AH, CH, DH, BH,
    AX = 0, CX, DX, BX, SP, BP, SI, DI,
    EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    ES = 0, CS, SS, DS, FS, GS

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
    SEG_ES = #26,
    SEG_CS = #2E,
    SEG_SS = #36,
    SEG_DS = #3E,
    SEG_FS = #64,
    SEG_GS = #65

public constant
    JMP_NEAR  = #E9,
    JMP_SHORT = JMP_NEAR+2,
    JMP_INDIR = {#FF,#20},
    JCC_SHORT = #70, -- + cond
    JCC_NEAR  = {#0F,#80} -- + {0,cond}

public constant
    SETCC = {#0F,#90} -- + {0,cond}, modrm

public constant
    CMP_RM_IMM = #80,
    CMP_RM_REG = #38, -- + 2*dir + width
    CMP_ACC_IMM = #3C, -- + width
    TEST_RM_REG = #84, -- + width
    TEST_ACC_IMM = #A8, -- + width
    $

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
    MOV_RM_IMM  = #C6, -- + width
    MOV_RM_SEG  = #8C, -- + 2*dir
    $

public constant
    ADD_RM_REG  = #00, -- + 2*dir + width
    ADD_ACC_IMM = #04, -- + width
    SUB_RM_REG  = #28, -- + 2*dir + width
    SUB_REG_RM  = SUB_RM_REG+2, -- + width
    SUB_ACC_IMM = #2C, -- + width
    XOR_RM_REG  = #30, -- + 2*dir + width
    XOR_ACC_IMM = #34, -- + width
    OR_RM_REG   = #08, -- + 2*dir + width
    OR_ACC_IMM  = #0C, -- + width
    AND_RM_REG  = #20, -- + 2*dir + width
    AND_ACC_IMM = #24, -- + width
    OP_RM_IMM   = #80,
    OP_RM_IMM8  = #83,
    $

public constant
    XCHG_RM_REG = #86, -- + width
    XCHG_ACC_REG = #90, -- + reg -- no width bit, so only eax and ax are acceptable
    $

public constant LEA = #8D

public constant NOP = #90

public constant MOVZX = {#0F,#B6}, MOVSX = {#0F,#BE}

public constant MOVSB = #A4, MOVSD = #A5, MOVSW = PREFIX_OPERAND_SIZE & MOVSD

public constant SCASB = #AE, SCASD = #AF

public constant LODSB = #AC, LODSD = #AD

public constant INC_REG = #40, -- + reg
                DEC_REG = #48, -- + reg
                $

public constant
    SHIFT_OP_RM_1    = #D0, -- + width
    SHIFT_OP_RM_CL   = #D2, -- + width
    SHIFT_OP_RM_IMM8 = #C0, -- + width
    $

public constant
    TEST_or_unary_RM = #F6 -- + width & MODRM (reg==0 - test; reg==1 - n/a; reg==2 through 7 - unary ops)
