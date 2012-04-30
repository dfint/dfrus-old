-- Universal patcher
-- ~ 2012-02-28

-- include std/get.e
include std/io.e
include std/convert.e

type file_number(integer f) -- copied from the file.e
    return f >= 0
end type

public
function patch(file_number fn, sequence patch)
    for n = 1 to length(patch) do
        if seek(fn,patch[n][1]) then
            return n -- unable to seek
        else
            puts(fn,patch[n][2])
        end if
    end for
    return 0 -- it's ok
end function

public
function not_patched(file_number fn, sequence patch)
    sequence npatch
    npatch = {}
    for n = 1 to length(patch) do
        if seek(fn,patch[n][1]) then
            return n -- unable to seek
        elsif atom(patch[n][1]) then
            if getc(fn) != patch[n][2] then
                npatch = append(npatch,patch[n])
            end if
        else
            if compare(get_bytes(fn,length(patch[n][2])),patch[n][2]) != 0 then
                npatch = append(npatch,patch[n])
            end if
        end if
    end for
    
    return npatch
end function

public
function open_pe(sequence filename)
    return open(filename,"ub")
end function

public
function fpeek(atom fn, object off)
    if atom(off) then
        seek(fn,off)
        return getc(fn)
    else
        seek(fn,off[1])
        return get_bytes(fn,off[2])
    end if
end function

public
function get_words(atom fn, integer n)
    sequence words = repeat(0,n)
    for i = 1 to n do
        words[i] = get_integer16(fn)
    end for
    return words
end function

public
function get_dwords(atom fn, integer n)
    sequence dwords = repeat(0,n)
    for i = 1 to n do
        dwords[i] = get_integer32(fn)
    end for
    return dwords
end function

public
function fpeek2u(atom fn, object off)
    if atom(off) then
        seek(fn,off)
        return get_integer16(fn)
    else
        seek(fn,off[1])
        return get_words(fn,off[2])
    end if
end function

public
function fpeek4u(atom fn, object off)
    if atom(off) then
        seek(fn,off)
        return get_integer32(fn)
    else
        seek(fn,off[1])
        return get_dwords(fn,off[2])
    end if
end function

public
function fpeek4s(atom fn, object off)
    object x = fpeek4u(fn,off)
    if atom(x) then
        if and_bits(x,#80000000) then
            x -= #100000000
        end if
    else
        for i = 1 to length(x) do
            if and_bits(x[i],#80000000) then
                x[i] -= #100000000
            end if
        end for
    end if
    return x
end function

public
procedure fpoke(atom fn, atom off, object x)
    seek(fn,off)
    puts(fn,x)
end procedure

public
procedure fpoke2(atom fn, atom off, object x)
    seek(fn,off)
    if atom(x) then
        puts(fn,and_bits(x,#00FF))
        puts(fn,floor(x/#100))
    else
        for i = 1 to length(x) do
            puts(fn,and_bits(x[i],#00FF))
            puts(fn,floor(x[i]/#100))
        end for
    end if
end procedure

public
procedure fpoke4(atom fn, atom off, object x)
    sequence s
    seek(fn,off)
    if atom(x) then
        puts(fn,int_to_bytes(x))
    else
        s = {}
        for i = 1 to length(x) do
            s &= int_to_bytes(x[i])
        end for
        puts(fn,s)
    end if
end procedure
