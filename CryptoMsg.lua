-- CryptoMsg - in-game AES encryption
-- Copyright (C) 2019  Ranx

-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

script_name('CryptoMsg')
script_author('Ranx')
script_description('In-game AES encryption')
script_version('0.1.0-alpha')

require 'lib.moonloader'
require 'lib.aeslua'

local sampev = require 'lib.samp.events'
local LIP = require 'lib.LIP'
local inspect = require 'lib.inspect'

local aesParams = {aeslua.AES256, aeslua.CBCMODE}
local b64Charsets = {
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz*&|:;,!?@#+/'
}
local matchInlinePattern = '%$CS(.-)%$CE'
local formatInlinePattern = '$CS%s$CE'
local cfgPath = 'moonloader/config/cryptomsg.ini'

-- Default config
local cfg = {
    general = {
        inlineEncrypt = true,
        autoEncrypt = false,
        autoDecrypt = false,
        showInlineInfoMessages = false,
        showErrorMessages = true,
        b64Charset = 1,
        password = ''
    }
}

function main()
    if not isSampLoaded() or not isSampfuncsLoaded() then return end
    while not isSampAvailable() do wait(100) end

    loadConfig()
    setHooks()
    
    sampRegisterChatCommand('encrypt', cmdEncrypt)
    sampRegisterChatCommand('decrypt', cmdDecrypt)
    sampRegisterChatCommand('reloadcmsg', function()
        loadConfig()
        printStringNow('Config reloaded', 1500)
    end
    )
end

function loadConfig()
    if not doesFileExist(cfgPath) then
        LIP.save(cfgPath, cfg)
    end
    
    cfg = LIP.load(cfgPath)
end

function setHooks()
    hooks = {
        {'onSendChat', {1}, true, true, false},
        {'onSendCommand', {1}, true, false, false},
        {'onSendDialogResponse', {4}, true, true, false},
        {'onServerMessage', {2}, false, false, true},
        {'onChatMessage', {2}, false, false, true}
    }
    for _, hook in ipairs(hooks) do
        setHook(unpack(hook))
    end
end

function cmdEncrypt(params)
    if string.len(params) <= 0 then
        sampAddChatMessage('Usage: /encrypt {BABABA}<message>', 0xAAAAAA)
        return
    end
    result, returned = encrypt(params)
    if result and returned then
        sampAddChatMessage(string.format('Encrypted: {AAAAAA}%s', returned), 0x66FF66)
    else
        sendCryptoErrorMessage(false, returned)
    end
end

function cmdDecrypt(params)
    if string.len(params) <= 0 then
        sampAddChatMessage('Usage: /decrypt {BABABA}<message>', 0xAAAAAA)
        return
    end
    local result, returned = decrypt(params)
    if result and returned then
        sampAddChatMessage(string.format('Decrypted: {AAAAAA}%s', returned), 0x66FF66)
    else
        sendCryptoErrorMessage(true, returned)
    end
end

function setHook(event, argsPos, inline, autoEncryptionAvailable, decryption)
    sampev[event] = function(...)
        if decryption and not cfg.general.autoDecrypt then return true end
        local hookArgs = {...}
        print(string.format('\n// %s //', decryption and 'Decryption' or 'Encryption'))
        print('Before: ' .. inspect(hookArgs, {newline = '', indent = ''}))
        for _, i in ipairs(argsPos) do
            if autoEncryptionAvailable and cfg.general.autoEncrypt then
                hookArgs[i] = string.format(formatInlinePattern, encrypt(hookArgs[i]))
                print('Auto-encrypted:' .. hookArgs[i])
            else
                hookArgs[i] = string.gsub(hookArgs[i], matchInlinePattern, function(exp)
                    print('Exp: '.. exp)
                    if inline or (autoEncryptionAvailable and cfg.general.autoEncrypt) then
                        return string.format(formatInlinePattern, encrypt(exp))
                    elseif decryption then
                        return decrypt(exp)
                    else
                        return exp
                    end
                end)
            end
        end
        print('After: ' .. inspect(hookArgs, {newline = '', indent = ''}))
        return hookArgs
    end
end

function encrypt(plainText)
    local result, returned = pcall(function()
            return b64encode(
                aeslua.encrypt(
                    tostring(cfg.general.password),
                    plainText,
                    unpack(aesParams)),
                b64Charsets[cfg.general.b64Charset])
        end)
    if result and returned then
        return returned
    else
        sendCryptoErrorMessage(false, returned)
        return ''
    end
end

function decrypt(cipherText)
    local result, returned = pcall(function()
            return aeslua.decrypt(
                tostring(cfg.general.password),
                b64decode(
                    cipherText,
                    b64Charsets[cfg.general.b64Charset]),
                unpack(aesParams))
        end)
    if result and returned then
        return returned
    else
        sendCryptoErrorMessage(true, returned)
        return ciphertext
    end
end

function sendInlineCryptoMessage(decryption)
    if not cfg.general.showInlineInfoMessages then return end
    sampAddChatMessage(string.format('Inline %s.', decryption and 'decrypted' or 'encrypted'), 0xAAAAAA)
end

function sendCryptoErrorMessage(decryption, errorMsg)
    if not cfg.general.showErrorMessages then return end
    sampAddChatMessage(string.format('%s error%s.', decryption and 'Decryption' or 'Encryption', errorMsg ~= nil and ' (look in console for details)' or ''), 0xF75A3D)
    if errorMsg ~= nil then print('An error has occurred:\n' .. errorMsg) end
end

-- Utility functions
-- =================


function b64encode(data, chars)
    return ((data:gsub('.', function(x)
        local r, b = '', x:byte()
        for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c = 0
        for i = 1, 6 do c = c + (x:sub(i, i) == '1' and 2 ^ (6 - i) or 0) end
        return chars:sub(c + 1,c + 1)
    end) .. ({'', '==', '=' })[#data % 3 + 1])
end

function b64decode(data, chars)
    data = string.gsub(data, '[^' .. chars .. '=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r, f = '', (chars:find(x) - 1)
        for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0') end
        return r
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c = 0
        for i = 1, 8 do c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0) end
        return string.char(c)
    end))
end
