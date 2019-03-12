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
script_version('0.3.0')

require 'lib.moonloader'
require 'lib.aeslua'

local sf = require 'lib.sampfuncs'
local inicfg = require 'inicfg'
local sampev = require 'lib.samp.events'
local inspect = require 'lib.inspect'

local aesParams = {aeslua.AES256, aeslua.CBCMODE}
local b64Charsets = {
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz*&|:;,!?@#+/'
}
local b64CharsetsNamings = {
    'Digits',
    'Special chars'
}
local matchInlinePattern = '%$CS(.-)%$CE'
-- This should be exactly opposite to the pattern above
local formatInlinePattern = '$CS%s$CE'
local cfgPath = 'cryptomsg.ini'

local settignsDialog = {}

-- Default config
local cfg = {
    general = {
        inlineEncrypt = true,
        autoEncrypt = false,
        autoDecrypt = false,
        showInlineInfoMessages = false,
        showErrorMessages = true,
        b64Charset = 1,
        password = 'changeme'
    }
}

local colors = {
    default = 'AAAAAA',
    success = '66FF66',
    error = 'F75A3D',
    green = '43A047',
    red = 'E53935',
    grey = 'BABABA',
    menuTitle = '4E79AA',
    menuRow = 'E0E0E0',
    menuDelimiter = '546E7A'
}

function main()
    if not isSampLoaded() or not isSampfuncsLoaded() then return end
    while not isSampAvailable() do wait(100) end

    initialEncrypt()
    loadConfig()
    setHooks()
    loadSettingsDialog()
    
    sampRegisterChatCommand('cmsg', function()
        lua_thread.create(function()
            submenus_show(
                settingsDialog,
                string.format('%sCryptoMsg %sv%s', getBrackets(colors.menuTitle), getBrackets(colors.green), thisScript().version),
                'Select', 'Close', 'Back'
            )
        end)
    end)
    sampRegisterChatCommand('encrypt', cmdEncrypt)
    sampRegisterChatCommand('decrypt', cmdDecrypt)
    sampRegisterChatCommand('reloadcmsg', function()
        loadConfig()
        loadSettingsDialog()
        printStringNow('Config reloaded', 1500)
    end
    )
end

function loadConfig()
    cfg = inicfg.load(cfg, cfgPath)
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

function loadSettingsDialog()
    settingsDialog = {
        getTogglableMenuRow('Inline Encryption', cfg.general, 'inlineEncrypt'),
        getTogglableMenuRow('Auto Encryption', cfg.general, 'autoEncrypt'),
        getTogglableMenuRow('Auto Decryption', cfg.general, 'autoDecrypt'),
        getTogglableMenuRow('Show info messages', cfg.general, 'showInlineInfoMessages'),
        getTogglableMenuRow('Show error messages', cfg.general, 'showErrorMessages'),
        {
            title = string.format('%sBase64 charset  %s/%s  %s',
                getBrackets(colors.menuRow),
                getBrackets(colors.menuDelimiter),
                getBrackets(colors.menuRow),
                b64CharsetsNamings[cfg.general.b64Charset]
            ),
            onclick = function(menu, row)
                if cfg.general.b64Charset < #b64Charsets then
                    cfg.general.b64Charset = cfg.general.b64Charset + 1
                else
                    cfg.general.b64Charset = 1
                end
                inicfg.save(cfg, cfgPath)
                menu[row].title = string.format('%sBase64 charset  %s/%s  %s',
                    getBrackets(colors.menuRow),
                    getBrackets(colors.menuDelimiter),
                    getBrackets(colors.menuRow),
                    b64CharsetsNamings[cfg.general.b64Charset]
                )
                return true
            end
        },
        {
            title = getBrackets(colors.menuRow) .. 'Password',
            onclick = function()
                sampShowDialog(
                    36826,
                    getBrackets(colors.menuTitle) .. 'Password',
                    string.format('%sCurrent password: %s%s%s\n\nEnter new password:',
                        getBrackets(colors.default),
                        getBrackets(colors.green),
                        cfg.general.password,
                        getBrackets(colors.default)
                    ),
                    'Done',
                    'Close',
                    sf.DIALOG_STYLE_INPUT
                )
                lua_thread.create(function()
                    print('Run password dialog thread')
                    repeat
                        wait(0)
                        local result, button, _, input = sampHasDialogRespond(36826)
                        if result and button == 1 then
                            if string.len(input) > 0 then
                                cfg.general.password = input
                                inicfg.save(cfg, cfgPath)
                                sampAddChatMessage('Password was changed.', get0x(colors.success))
                            else
                                sampAddChatMessage('Password cannot be empty.', get0x(colors.error))
                            end
                        end
                    until result
                    print('Exited password dialog thread')
                end)
            end
        }
    }
end

function get0x(s)
    return '0x' .. s
end

function getBrackets(s)
    return string.format('{%s}', s)
end

function statusLabel(status)
    return string.format('  {%s}/  %s',
        colors.menuDelimiter,
        status and getBrackets(colors.green) .. '[On]' or getBrackets(colors.red) .. '[Off]'
    )
end

-- Unfortunately, Lua passes booleans by value , so we can't just
-- pass setting variable to function
function getTogglableMenuRow(name, settings, settingName)
    return {
        title = getBrackets(colors.menuRow) .. name .. statusLabel(settings[settingName]),
        onclick = function(menu, row)
            settings[settingName] = not settings[settingName]
            menu[row].title = getBrackets(colors.menuRow) .. name .. statusLabel(settings[settingName])
            inicfg.save(cfg, cfgPath)
            return true
        end
    }
end

function cmdEncrypt(params)
    if string.len(params) <= 0 then
        sampAddChatMessage(string.format('Usage: /encrypt {%s}<message>', colors.grey), get0x(colors.default))
        return
    end
    local ciphertext = encrypt(params)
    if ciphertext then
        sampAddChatMessage(string.format('Encrypted: {%s}%s', colors.default, ciphertext), get0x(colors.success))
    end
end

function cmdDecrypt(params)
    if string.len(params) <= 0 then
        sampAddChatMessage(string.format('Usage: /decrypt {%s}<message>', colors.grey), get0x(colors.default))
        return
    end
    local plaintext = decrypt(params)
    if plaintext then
        sampAddChatMessage(string.format('Decrypted: {%s}%s', colors.default, plaintext), get0x(colors.success))
    end
end

function setHook(event, argsPos, inlineEncryptionAvailable, autoEncryptionAvailable, decryption)
    sampev[event] = function(...)
        if decryption and not cfg.general.autoDecrypt then return true end
        -- Get all arguments passed to setHook function ..
        local hookArgs = {...}
        print(string.format('\n// %s //', decryption and 'Decryption' or 'Encryption'))
        print('Before: ' .. inspect(hookArgs, {newline = '', indent = ''}))
        -- .. and perform encryption/decryption for each of them
        for _, i in ipairs(argsPos) do
            if autoEncryptionAvailable and cfg.general.autoEncrypt then
                hookArgs[i] = string.format(formatInlinePattern, encrypt(hookArgs[i]) or '')
                print('Auto-encrypted:' .. hookArgs[i])
            else
                hookArgs[i] = string.gsub(hookArgs[i], matchInlinePattern, function(exp)
                    print('Exp: '.. exp)
                    if inlineEncryptionAvailable and cfg.general.inlineEncrypt then
                        return string.format(formatInlinePattern, encrypt(exp) or '')
                    elseif decryption then
                        return decrypt(exp)
                    else
                        return string.format(formatInlinePattern, exp)
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
        return nil
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
    sampAddChatMessage(string.format('Inline %s.', decryption and 'decrypted' or 'encrypted'), get0x(colors.default))
end

function sendCryptoErrorMessage(decryption, errorMsg)
    if not cfg.general.showErrorMessages then return end
    sampAddChatMessage(string.format('%s error%s.', decryption and 'Decryption' or 'Encryption', errorMsg ~= nil and ' (look in console for details)' or ''), get0x(colors.error))
    if errorMsg ~= nil then print('An error has occurred:\n' .. errorMsg) end
end

-- This trick is needed because aeslua does not
-- generate IV, it's based on previous encryption/decryption,
-- so we need to generate random plaintext (same plaintexts will give
-- you same IV, same IV will give you same ciphertexts)
function initialEncrypt()
    local result, returned = pcall(function()
        return aeslua.encrypt('password', string.random(8), unpack(aesParams))
    end)
    if not (result and returned) then
        print('Initial encryption failed:\n' .. returned)
    end
end

-- Utility functions
-- =================

-- https://gist.github.com/THE-FYP/e89a10df29698219b56bb37bc194cb31
function submenus_show(menu, caption, select_button, close_button, back_button)
    select_button, close_button, back_button = select_button or 'Select', close_button or 'Close', back_button or 'Back'
    prev_menus = {}
    function display(menu, id, caption)
        local string_list = {}
        for i, v in ipairs(menu) do
            table.insert(string_list, type(v.submenu) == 'table' and v.title .. '  >>' or v.title)
        end
        sampShowDialog(id, caption, table.concat(string_list, '\n'), select_button, (#prev_menus > 0) and back_button or close_button, sf.DIALOG_STYLE_LIST)
        repeat
            wait(0)
            local result, button, list = sampHasDialogRespond(id)
            if result then
                if button == 1 and list ~= -1 then
                    local item = menu[list + 1]
                    if type(item.submenu) == 'table' then -- submenu
                        table.insert(prev_menus, {menu = menu, caption = caption})
                        if type(item.onclick) == 'function' then
                            item.onclick(menu, list + 1, item.submenu)
                        end
                        return display(item.submenu, id + 1, item.submenu.title and item.submenu.title or item.title)
                    elseif type(item.onclick) == 'function' then
                        local result = item.onclick(menu, list + 1)
                        if not result then return result end
                        return display(menu, id, caption)
                    end
                else -- if button == 0
                    if #prev_menus > 0 then
                        local prev_menu = prev_menus[#prev_menus]
                        prev_menus[#prev_menus] = nil
                        return display(prev_menu.menu, id - 1, prev_menu.caption)
                    end
                    return false
                end
            end
        until result
    end
    return display(menu, 36825, caption or menu.title)
end

-- http://lua-users.org/wiki/BaseSixtyFour
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

function string.random(length)
    local charset = {}
    string.gsub('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', '.',
        function(c) table.insert(charset, c) end)

    if not length or length <= 0 then return '' end
    math.randomseed(os.clock() ^ 5)
    return string.random(length - 1) .. charset[math.random(1, #charset)]
end
