-- tark binary management
-- Handles finding and downloading the tark binary

local M = {}

M.config = {
    auto_download = true,
}

-- ============================================================================
-- Platform detection
-- ============================================================================

local function detect_platform()
    local os_name = vim.loop.os_uname().sysname:lower()
    local arch = vim.loop.os_uname().machine:lower()
    
    local os_key
    if os_name:match('darwin') then
        os_key = 'darwin'
    elseif os_name:match('linux') then
        os_key = 'linux'
    elseif os_name:match('windows') then
        os_key = 'windows'
    else
        return nil, nil, nil
    end
    
    local arch_key
    if arch:match('arm64') or arch:match('aarch64') then
        arch_key = 'arm64'
    elseif arch:match('x86_64') or arch:match('amd64') then
        arch_key = 'x86_64'
    else
        return nil, nil, nil
    end
    
    local ext = os_key == 'windows' and '.exe' or ''
    local binary_name = string.format('tark-%s-%s%s', os_key, arch_key, ext)
    
    return os_key, arch_key, binary_name
end

-- ============================================================================
-- Binary management
-- ============================================================================

local function get_data_dir()
    local dir = vim.fn.stdpath('data') .. '/tark'
    -- Only create if nothing exists at the path
    if vim.fn.isdirectory(dir) == 0 then
        -- Check if something else exists (file)
        if vim.fn.filereadable(dir) == 1 then
            -- A file exists where we want a directory - remove it
            vim.fn.delete(dir)
        end
        -- Create directory (pcall to handle race conditions)
        pcall(vim.fn.mkdir, dir, 'p')
    end
    return dir
end

local function get_binary_path()
    return get_data_dir() .. '/tark'
end

-- Find tark binary
function M.find()
    -- Check configured path
    if M.config.binary and vim.fn.executable(M.config.binary) == 1 then
        return M.config.binary
    end
    
    -- Check data directory
    local data_bin = get_binary_path()
    if vim.fn.filereadable(data_bin) == 1 and vim.fn.executable(data_bin) == 1 then
        return data_bin
    end
    
    -- Check PATH
    if vim.fn.executable('tark') == 1 then
        return 'tark'
    end
    
    return nil
end

-- Download tark binary
function M.download(callback)
    local _, _, binary_name = detect_platform()
    if not binary_name then
        vim.notify('tark: Unsupported platform', vim.log.levels.ERROR)
        if callback then callback(false) end
        return
    end
    
    -- Use latest stable release
    local tark = require('tark')
    local version = 'v' .. tark.version
    local base_url = 'https://github.com/thoughtoinnovate/tark/releases/download/' .. version .. '/'
    local binary_url = base_url .. binary_name
    local checksum_url = binary_url .. '.sha256'
    
    local dest = get_binary_path()
    local checksum_file = dest .. '.sha256'
    
    vim.notify('tark: Downloading ' .. version .. '...', vim.log.levels.INFO)
    
    -- Download binary and checksum
    local download_cmd = string.format(
        'curl -fsSL "%s" -o "%s" && curl -fsSL "%s" -o "%s"',
        binary_url, dest, checksum_url, checksum_file
    )
    
    vim.fn.jobstart(download_cmd, {
        on_exit = function(_, code)
            vim.schedule(function()
                if code ~= 0 then
                    vim.notify('tark: Download failed', vim.log.levels.ERROR)
                    if callback then callback(false) end
                    return
                end
                
                -- Verify checksum
                local checksum_handle = io.open(checksum_file, 'r')
                if checksum_handle then
                    local expected = checksum_handle:read('*a'):match('^(%S+)')
                    checksum_handle:close()
                    os.remove(checksum_file)
                    
                    if expected then
                        local sha_cmd = vim.fn.executable('sha256sum') == 1 
                            and 'sha256sum' or 'shasum -a 256'
                        local sha_handle = io.popen(sha_cmd .. ' "' .. dest .. '"')
                        if sha_handle then
                            local actual = sha_handle:read('*a'):match('^(%S+)')
                            sha_handle:close()
                            
                            if actual ~= expected then
                                vim.notify('tark: Checksum verification failed!', vim.log.levels.ERROR)
                                os.remove(dest)
                                if callback then callback(false) end
                                return
                            end
                        end
                    end
                end
                
                -- Make executable
                vim.fn.system('chmod +x "' .. dest .. '"')
                
                -- Verify it works
                local handle = io.popen(dest .. ' --version 2>&1')
                if handle then
                    local result = handle:read('*a')
                    handle:close()
                    if result:match('tark') then
                        local ver = result:match('tark%s+([%d%.]+)') or 'unknown'
                        vim.notify('tark: Downloaded v' .. ver, vim.log.levels.INFO)
                        if callback then callback(true) end
                        return
                    end
                end
                
                vim.notify('tark: Downloaded file is invalid', vim.log.levels.ERROR)
                os.remove(dest)
                if callback then callback(false) end
            end)
        end,
    })
end

-- Get version of installed binary
function M.version()
    local bin = M.find()
    if not bin then return nil end
    
    local handle = io.popen(bin .. ' --version 2>&1')
    if handle then
        local result = handle:read('*a')
        handle:close()
        return result:match('tark%s+([%d%.]+)')
    end
    return nil
end

-- ============================================================================
-- Setup
-- ============================================================================

function M.setup(config)
    M.config = vim.tbl_deep_extend('force', M.config, config or {})
end

return M

