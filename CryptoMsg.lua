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
local matchInlinePattern = '%$CS(.+)%$CE'
local extendedMatchInlinePattern = '(%$CS.+%$CE)'
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
    
    if not doesFileExist(cfgPath) then
        LIP.save(cfgPath, cfg)
    end
    
    cfg = LIP.load(cfgPath)
    
    sampRegisterChatCommand('encrypt', cmdEncrypt)
    sampRegisterChatCommand('decrypt', cmdDecrypt)
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

-- Encryption
-- ==========

function sampev.onSendChat(message)
    local plainText = cfg.general.autoEncrypt and message or getInlineString(message)
    if plainText ~= nil then
        local result, returned = encrypt(plainText)
        if result and returned then
            if cfg.general.autoEncrypt then
                return {string.format(formatInlinePattern, returned)}
            else
                sendInlineCryptoMessage(false)
                return {replaceInlineString(message, string.format(formatInlinePattern, returned))}
            end
        else
            sendCryptoErrorMessage(false, returned)
            return false
        end
    end
end

function sampev.onSendCommand(command)
    local plainText = getInlineString(command)
    if plainText ~= nil then
        local result, returned = encrypt(plainText)
        if result and returned then
            sendInlineCryptoMessage(false)
            return {replaceInlineString(command, string.format(formatInlinePattern, returned))}
        else
            sendCryptoErrorMessage(false, returned)
            return false
        end
    end
end

function sampev.onSendDialogResponse(dialogId, button, listboxId, input)
    local plainText = cfg.general.autoEncrypt and input or getInlineString(input)
    if plainText ~= nil then
        local result, returned = encrypt(plainText)
        if result and returned then
            if cfg.general.autoEncrypt then
                return {dialogId, button, listboxId, string.format(formatInlinePattern, returned)}
            else
                sendInlineCryptoMessage(false)
                return {dialogId, button, listboxId, replaceInlineString(input, string.format(formatInlinePattern, returned))}
            end
        else
            sendCryptoErrorMessage(false, returned)
            return false
        end
    end
end

-- Decryption
-- ==========

function sampev.onServerMessage(color, text)
    if not cfg.general.autoDecrypt then return true end
    local cipherText = getInlineString(text)
    if cipherText ~= nil then
        local result, returned = decrypt(cipherText)
        if result and returned then
            sendInlineCryptoMessage(true)
            return {color, replaceInlineString(text, returned)}
        else
            sendCryptoErrorMessage(true)
            return true
        end
    end
end

function sampev.onChatMessage(playerId, text)
    if not cfg.general.autoDecrypt then return true end
    local cipherText = getInlineString(text)
    if cipherText ~= nil then
        local result, returned = decrypt(cipherText)
        if result and returned then
            sendInlineCryptoMessage(true)
            return {playerId, replaceInlineString(text, returned)}
        else
            sendCryptoErrorMessage(true)
            return true
        end
    end
end

function encrypt(plainText)
    return pcall(function()
            return b64encode(
                aeslua.encrypt(
                    tostring(cfg.general.password),
                    plainText,
                    unpack(aesParams)),
                b64Charsets[cfg.general.b64Charset])
        end)
end

function decrypt(cipherText)
    return pcall(function()
            return aeslua.decrypt(
                tostring(cfg.general.password),
                b64decode(
                    cipherText,
                    b64Charsets[cfg.general.b64Charset]),
                unpack(aesParams))
        end)
end

function sendInlineCryptoMessage(decryption)
    if not cfg.general.showInlineInfoMessages then return end
    sampAddChatMessage(string.format('Inline %s.', 'decrypted' and decryption or 'encrypted'), 0xAAAAAA)
end

function sendCryptoErrorMessage(decryption, errorMsg)
    if not cfg.general.showErrorMessages then return end
    sampAddChatMessage(string.format('%s error%s.', 'Decryption' and decryption or 'Encryption', errorMsg ~= nil and ' (look in console for details)'  or ''), 0xF75A3D)
    if errorMsg ~= nil then print('An error has occurred:\n' .. errorMsg) end
end
function getInlineString(text)
    return string.match(text, matchInlinePattern)
end

function replaceInlineString(text, replaceWith)
    return (string.gsub(text, matchInlinePattern, replaceWith))
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
