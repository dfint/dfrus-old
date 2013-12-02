-- Извлечение строк из исполняемого файла

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

-- Получить список строк в виде списка пар {смещение, строка}
sequence strings
function check_string(object key, object val, object fn, integer progress_code)
    object buf
    integer len
    if progress_code <= 0 then
        -- map is empty or the last call
        return strings
    end if
    -- integer fn = user_data[1]
    -- исключить ссылки на середины строк:
    if length(strings)>0 and key <= strings[$][1]+length(strings[$][2]) then
        return 0
    end if
    -- считываем блок данных:
    seek(fn, key)
    buf = get_bytes(fn, blocksize)
    if atom(buf) then
        return -1
    end if
    -- проверяем, является ли данный объект строкой
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
