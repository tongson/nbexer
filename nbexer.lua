#!/usr/bin/env lua
local l = require 'lib'
local printf, fopen = l.printf, l.fopen
local tblResults, tblIgnore = l.tblResults, l.tblIgnore

local results = fopen(assert(arg[1], ".nbe file not specified"))
printf("=== Opening Nessus .nbe file \n")
local set = {}
local plugins = {}

--[[
    Table of ignored Nessus Plugin ids. IMO they are of limited use for regular reports.
    Quoted string is from their respective Synopses.

    19506 = "Information about the Nessus scan"
    39520 = "Security patches are backported"
    54615 = "It is possible to guess the remote device type"
    56468 = "The system has been started"
    10287 = "It was possible to obtain traceroute information."
    25220 = "The remote service implements TCP timestamps."
    34277 = "The UDP port scan could not complete"
    20094 = "The remote host seems to be a VMware virtual machine."
    35351 = "Information about the remote system's hardware can be read."
    47761 = "The remote host seems to be a VMware virtual machine."
    58651 = "Active connections are enumerated via the 'netstat' command."
]]
local ignored = tblIgnore{ "19506", "39520", "54615", "56468",
                           "10287", "25220", "34277", "20094",
                           "35351", "47761", "58651" }

--[[
    Populate 'set' and 'plugins'.
    'set' has the plugin ID and synopsis as key=value.
    'plugins' is an array of plugin IDs.

    This approach seems cleaner than using a multi-dimensional array.
]]
for line in results:gmatch('[^\f\r\n]+') do
    local result = tblResults(line)
    local plugin = assert(result[5], "Empty result field! Invalid .nbe file?")
    local body = result[7]
    if not set[plugin] then
        if ignored[plugin] then
            -- Nil statement. Skip ignored plugins.
        elseif plugin:find('%d%d%d%d%d') then

            -- Test the body, bail on possible format changes.
            local pattern = '[%a%s]+:[\\n%s]+([^\\]-)\\n\\n'
            local message = "Test pattern failed! .nbe format may have changed."
            assert(body:find(pattern), message)

            -- Finally add entry to 'set' and 'plugins'.
            set[plugin] = body
            plugins[#plugins + 1] = plugin
        end
    end
end

--[[
    Output by plugin ID for shorter reports. SLOWER!!!
]]
if arg[2] == "-p" then
    for _, id in ipairs(plugins) do
        local pattern = '^Synopsis[\n%s]?:\\n\\n([^\\]-)\\n\\n'
        local Synopsis = assert(set[id]:match(pattern), "Synopsis did not match!")
        printf("\n=== %s %s\n", id, Synopsis)
        for line in results:gmatch('[^\f\r\n]+') do
            local result = tblResults(line)
            local plugin = result[5]
            if plugin == id then
                local host = result[3] -- Host being scanned.
                local port = result[4]:gsub('general/%a+', '') -- general/tcp is confusing, remove.
                printf("    %s %s\n", host, port)
            end
        end
    end
else
--[[
    Output per host. This is how the .nbe is organized per line.
]]
    for line in results:gmatch('[^\f\r\n]+') do
        local result = tblResults(line)
        local output = nil
        local host = result[3]
        local port = result[4]
        local plugin = result[5]
        local body = result[7]
        local Synopsis = '^Synopsis[\\n%s]?:\\n\\n([^\\]-)\\n\\n'
        local Pluginoutput = 'Plugin output :[\\n]+(.*)[%s]?[\\n%s]?[\\n%s]?[\\n%s]?$'
        if set[plugin] then
            -- Use the Synopsis field if there's no Plugin output from this id.
            if body:match(Pluginoutput) then
                output = assert(body:match(Pluginoutput), "Plugin output did not match!")
            else
                output = assert(body:match(Synopsis), "Synopsis did not match!")
            end
            output = output:gsub([[\n]], '\n') -- encode literal '\n's
            printf("%s    Plugin: %s\n", host, plugin)
            printf("Port: %s\n", port)
            printf("%s\n", output)
        end
    end
end
