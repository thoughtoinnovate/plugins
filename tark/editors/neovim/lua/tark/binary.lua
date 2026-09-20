--- Binary resolution, version compatibility, and secure download (R10/R12, S25).
---
--- Resolution order: explicit config path -> vim.fn.exepath('tark') ->
--- previously downloaded release in install_dir.
--- Downloads come from GitHub releases with a SHA256 sidecar check that
--- must pass before the binary is ever executed (NFR1 fail-closed).
local M = {}

--- Parse `tark --version` output into a bare "x.y.z" string.
---@param output string raw stdout of `tark --version`
---@return string|nil version or nil when unparseable
function M.parse_version(output)
  if type(output) ~= 'string' then
    return nil
  end
  return output:match('(%d+%.%d+%.%d+)')
end

--- Split "x.y.z" into numeric components.
---@param v string
---@return table|nil {major,minor,patch} or nil
function M.split_version(v)
  if type(v) ~= 'string' then
    return nil
  end
  local major, minor, patch = v:match('^(%d+)%.(%d+)%.(%d+)$')
  if not major then
    return nil
  end
  return { major = tonumber(major), minor = tonumber(minor), patch = tonumber(patch) }
end

--- Compatibility policy (R12, K5): same major AND minor is compatible;
--- patch skew is tolerated. Anything else fails closed with remediation.
---@param plugin_version string version the plugin expects
---@param binary_version string|nil version the binary reported
---@return boolean ok, string message_or_remediation
function M.is_compatible(plugin_version, binary_version)
  if not binary_version then
    return false,
      'Could not determine tark binary version.\n'
        .. 'Remediation: reinstall a matching binary with :TarkHealth, or set '
        .. "require('tark').setup({ binary = '<path-to-tark>' })."
  end
  local want = M.split_version(plugin_version)
  local got = M.split_version(binary_version)
  if not want or not got then
    return false,
      string.format(
        'Unparseable version (plugin %s, binary %s).\nRemediation: install tark %s from '
          .. 'https://github.com/thoughtoinnovate/tark/releases and retry.',
        tostring(plugin_version),
        tostring(binary_version),
        tostring(plugin_version)
      )
  end
  if want.major == got.major and want.minor == got.minor then
    return true, string.format('tark %s compatible with plugin %s', binary_version, plugin_version)
  end
  return false,
    string.format(
      'Version mismatch: plugin expects tark %s (same major.minor), found %s.\n'
        .. 'Remediation: install the matching release from '
        .. 'https://github.com/thoughtoinnovate/tark/releases/tag/v%s, or downgrade the plugin '
        .. 'to the version matching your binary. Then restart Neovim.',
      tostring(plugin_version),
      tostring(binary_version),
      tostring(plugin_version)
    )
end

--- Map (uname -s, uname -m) to a release asset name.
--- Mirrors install.sh detect_platform/get_asset_name.
---@param sysname string e.g. 'Linux'
---@param machine string e.g. 'x86_64'
---@return string|nil asset, string|nil err
function M.platform_asset(sysname, machine)
  local os
  if sysname == 'Linux' then
    os = 'linux'
  elseif sysname == 'Darwin' then
    os = 'darwin'
  else
    return nil, 'Unsupported operating system: ' .. tostring(sysname) .. ' (supported: Linux, macOS)'
  end
  local arch
  if machine == 'x86_64' or machine == 'amd64' then
    arch = 'x86_64'
  elseif machine == 'aarch64' or machine == 'arm64' then
    arch = 'arm64'
  else
    return nil, 'Unsupported architecture: ' .. tostring(machine) .. ' (supported: x86_64, arm64)'
  end
  return 'tark-' .. os .. '-' .. arch, nil
end

--- Build release download URLs for a versioned asset (R12).
---@param repo string 'owner/name'
---@param version string bare 'x.y.z'
---@param asset string asset file name
---@return table {binary_url, checksum_url}
function M.download_urls(repo, version, asset)
  local base = string.format('https://github.com/%s/releases/download/v%s/%s', repo, version, asset)
  return { binary_url = base, checksum_url = base .. '.sha256' }
end

--- Extract the expected hash from a `<hash>  <name>` checksum sidecar.
---@param text string sidecar content
---@return string|nil hash or nil
function M.parse_checksum_file(text)
  if type(text) ~= 'string' then
    return nil
  end
  local hash = text:match('^%s*(%x+)')
  if hash and #hash == 64 then
    return hash:lower()
  end
  return nil
end

--- Detect the current platform via Neovim's libuv bindings.
---@return string|nil asset, string|nil err
function M.current_platform_asset()
  local uname = vim.loop.os_uname()
  return M.platform_asset(uname.sysname, uname.machine)
end

--- Resolve the tark binary without network access.
--- Order: config.binary -> exepath('tark') -> install_dir/tark.
---@param config table plugin config (see init.lua)
---@return string|nil path, string|nil remediation
function M.resolve(config)
  if config.binary and config.binary ~= '' then
    if vim.fn.executable(config.binary) == 1 then
      return config.binary, nil
    end
    return nil,
      string.format(
        "Configured binary '%s' is not executable.\nRemediation: fix the path in setup({ binary = ... }) or unset it to use PATH/download.",
        config.binary
      )
  end
  local on_path = vim.fn.exepath('tark')
  if on_path and on_path ~= '' and vim.fn.executable(on_path) == 1 then
    return on_path, nil
  end
  local downloaded = (config.install_dir or '') .. '/tark'
  if downloaded ~= '/tark' and vim.fn.executable(downloaded) == 1 then
    return downloaded, nil
  end
  return nil,
    'No tark binary found in config, PATH, or the plugin install dir.\n'
      .. 'Remediation: install tark (https://github.com/thoughtoinnovate/tark/releases), '
      .. 'put it on PATH, or run :TarkHealth and accept the download.'
end

--- Query `binary --version` asynchronously (never blocks Neovim).
---@param binary string path
---@param cb function called as cb(version_or_nil, raw_output)
function M.query_version(binary, cb)
  local out = {}
  local job = vim.fn.jobstart({ binary, '--version' }, {
    stdout_buffered = true,
    stderr_buffered = true,
    on_stdout = function(_, data)
      out = data or {}
    end,
    on_exit = function(_, _)
      local raw = table.concat(out, '\n')
      vim.schedule(function()
        cb(M.parse_version(raw), raw)
      end)
    end,
  })
  if job <= 0 then
    vim.schedule(function()
      cb(nil, '')
    end)
  end
end

--- Download + SHA256-verify the pinned release into install_dir (R12).
--- Fail-closed: a checksum mismatch deletes the file and reports an error.
---@param config table plugin config
---@param cb function called as cb(path_or_nil, err_or_nil)
function M.download(config, cb)
  local asset, asset_err = M.current_platform_asset()
  if not asset then
    vim.schedule(function()
      cb(nil, asset_err)
    end)
    return
  end
  local urls = M.download_urls(config.repo, config.expected_version, asset)
  vim.fn.mkdir(config.install_dir, 'p')
  local tmp = config.install_dir .. '/tark.download'
  local checksum_tmp = config.install_dir .. '/tark.download.sha256'
  local dest = config.install_dir .. '/tark'

  local function finish(path, err)
    vim.fn.delete(tmp)
    vim.fn.delete(checksum_tmp)
    cb(path, err)
  end

  local function fetch(url, outfile, next)
    local job = vim.fn.jobstart({ 'curl', '-fsSL', '--max-time', '120', url, '-o', outfile }, {
      on_exit = function(_, code)
        vim.schedule(function()
          if code ~= 0 then
            finish(
              nil,
              'Download failed for ' .. url .. '.\nRemediation: check network access, or manually install from '
                .. 'https://github.com/' .. config.repo .. '/releases and put tark on PATH.'
            )
          else
            next()
          end
        end)
      end,
    })
    if job <= 0 then
      vim.schedule(function()
        finish(nil, 'Could not spawn curl.\nRemediation: install curl, or manually place a tark binary on PATH.')
      end)
    end
  end

  fetch(urls.checksum_url, checksum_tmp, function()
    fetch(urls.binary_url, tmp, function()
      local lines = vim.fn.readfile(checksum_tmp)
      local expected = M.parse_checksum_file(table.concat(lines, '\n'))
      if not expected then
        finish(nil, 'Checksum sidecar was unreadable; refusing to install.\nRemediation: retry, or install manually from the release page.')
        return
      end
      local bytes = table.concat(vim.fn.readfile(tmp, 'b'), '\n')
      local actual = vim.fn.sha256(bytes)
      if actual:lower() ~= expected then
        finish(nil, 'SECURITY: SHA256 mismatch for downloaded tark binary; file deleted, nothing executed.\nRemediation: retry the download or install manually from the release page.')
        return
      end
      vim.fn.delete(dest)
      vim.fn.rename(tmp, dest)
      vim.fn.setfperm(dest, 'rwxr-xr-x')
      if vim.fn.executable(dest) ~= 1 then
        finish(nil, 'Downloaded binary is not executable after install.\nRemediation: chmod +x ' .. dest .. ' or install manually.')
        return
      end
      finish(dest, nil)
    end)
  end)
end

--- Resolve a compatible binary, downloading the pinned release if allowed.
---@param config table plugin config
---@param cb function called as cb(path_or_nil, err_or_nil)
function M.ensure(config, cb)
  local path, resolve_err = M.resolve(config)
  if not path then
    if config.auto_download then
      M.download(config, function(dl_path, dl_err)
        if not dl_path then
          cb(nil, (resolve_err or '') .. '\n\nDownload also failed: ' .. (dl_err or 'unknown error'))
          return
        end
        M.query_version(dl_path, function(ver)
          local ok, msg = M.is_compatible(config.expected_version, ver)
          if ok then
            cb(dl_path, nil)
          else
            cb(nil, msg)
          end
        end)
      end)
    else
      cb(nil, resolve_err)
    end
    return
  end
  M.query_version(path, function(ver)
    local ok, msg = M.is_compatible(config.expected_version, ver)
    if ok then
      cb(path, nil)
    else
      cb(nil, msg)
    end
  end)
end

return M
