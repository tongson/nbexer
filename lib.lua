local l = {}

function l.printf(...)
    io.write(string.format(...))
end

function l.fopen(file)
    local f, err = io.open(file,'r')
    if not f then error(err) end
    local str, err = f:read('*a')
    f:close()
    if not str then error(err) end
    return str
end

function l.tblResults(str)
    local p = 1
    local tbl = {}
    for a, z in function() return str:find('|', p) end do
        tbl[#tbl + 1] = str:sub(p, a - 1)
        p = z + 1
    end
    tbl[#tbl + 1] = str:sub(p)
    return tbl
end

function l.tblIgnore(str)
    local tbl = {}
    for _, i in ipairs(str) do tbl[i] = true end
    return tbl
end

return l
