#!/usr/bin/env lua
local printf = function (...) io.write(string.format(...)) end

function fOpen(file)
    local f, err = io.open(file,'r')
    if not f then error(err) end
    local str, err = f:read('*a')
    f:close()
    if not str then error(err) end
    return str
end

function tblResults(str)
    local p = 1
    local tbl = {}
    for a, z in function() return str:find('|', p) end do
        tbl[#tbl + 1] = str:sub(p, a - 1)
        p = z + 1
    end
    tbl[#tbl + 1] = str:sub(p)
    return tbl
end

function tblIgnore(ids)
    local tbl = {}
    for _, i in ipairs(ids) do tbl[i] = true end
    return tbl
end

assert(arg[1], ".nbe file not specified")
local results = fOpen(arg[1])
local set = {}
local plugins = {}
local ignored = tblIgnore{"19506", "39520", "54615", "56468",
                          "10287", "25220", "34277"}

printf("%c[31;1m===%c[0m Opening Nessus NBE file %s\n", 0x1B, 0x1B, arg[1])

--[[
    Populate 'set' and 'plugins'.
    'set' has the plugin ID and synopsis as key=value.
    'plugins' is an array of plugin IDs.

    This approach seems cleaner than using a multi-dimensional array.
]]
for line in results:gmatch('[^\f\r\n]+') do
   local result = tblResults(line)
   local plugin = result[5]
   local body = result[7]
   if not set[plugin] then
       if ignored[plugin] then
           -- Skip ignored plugins. IMO they are of little use.
       elseif plugin:find('%d%d%d%d%d') then
           -- test the body
           local pattern = '[%a%s]+:[\\n%s]+([^\\]-)\\n\\n'
           local testField = body:find(pattern)
           local message = "NBE format may have changed. Check the 7th field."
           assert(testField, message)

           set[plugin] = body
           plugins[#plugins + 1] = plugin
       end
   end
end


for _, id in ipairs(plugins) do
   local synopsis = set[id]:match('[%a%s]+:[\\n%s]+([^\\]-)\\n\\n')
   printf("\n >>> %c[32;1m %s %c[0m %s\n", 0x1B, id, 0x1B, synopsis)
   for line in results:gmatch('[^\f\r\n]+') do
      local result = tblResults(line)
      local plugin = result[5]
      if plugin == id then
         local host = result[3]
         local port = result[4]:gsub('general/%a+', '')
         printf("%s %s\n", host, port)
      end
   end
end

for line in results:gmatch('[^\f\r\n]+') do
end
