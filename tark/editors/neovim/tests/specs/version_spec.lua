-- Binary version parsing/compatibility + release URL specs (R12, S25).
-- Plenary-busted style; runs under PlenaryBustedFile or headless nvim
-- without plenary via the built-in fallback harness below.
if not (type(describe) == 'function' and type(it) == 'function') then
  local harness = { total = 0, failures = 0 }
  _G.describe = function(name, fn)
    print('describe: ' .. name)
    fn()
  end
  _G.it = function(name, fn)
    harness.total = harness.total + 1
    local ok, err = pcall(fn)
    if ok then
      print(string.format('  ok %d - %s', harness.total, name))
    else
      harness.failures = harness.failures + 1
      print(string.format('  FAIL %d - %s: %s', harness.total, name, tostring(err)))
    end
  end
  vim.api.nvim_create_autocmd('VimLeavePre', {
    once = true,
    callback = function()
      print(string.format('%d tests, %d failures', harness.total, harness.failures))
      if harness.failures > 0 then
        vim.cmd('cquit! 1')
      end
    end,
  })
end

local binary = require('tark.binary')

describe('version parsing', function()
  it('parses `tark --version` output', function()
    assert(binary.parse_version('tark 0.12.6\n') == '0.12.6', 'parse failed')
    assert(binary.parse_version('tark-cli 0.12.6') == '0.12.6', 'parse failed')
  end)

  it('returns nil for garbage', function()
    assert(binary.parse_version('no version here') == nil, 'garbage must not parse')
    assert(binary.parse_version(nil) == nil, 'nil must not parse')
  end)

  it('splits x.y.z into numeric parts', function()
    local v = binary.split_version('0.12.6')
    assert(v.major == 0 and v.minor == 12 and v.patch == 6, 'split mismatch: ' .. vim.inspect(v))
    assert(binary.split_version('0.12') == nil, 'partial versions must not split')
  end)
end)

describe('compatibility policy (same major.minor)', function()
  it('accepts exact matches', function()
    local ok, _ = binary.is_compatible('0.12.6', '0.12.6')
    assert(ok == true, 'exact match must be compatible')
  end)

  it('tolerates patch skew', function()
    local ok, _ = binary.is_compatible('0.12.6', '0.12.5')
    assert(ok == true, 'patch skew must be tolerated')
  end)

  it('rejects minor skew with a remediation path', function()
    local ok, msg = binary.is_compatible('0.12.6', '0.11.0')
    assert(ok == false, 'minor skew must be rejected')
    assert(msg:find('0.12.6', 1, true) ~= nil, 'remediation must name the expected version')
    assert(msg:find('github.com', 1, true) ~= nil, 'remediation must point at releases')
  end)

  it('rejects major skew with a remediation path', function()
    local ok, msg = binary.is_compatible('0.12.6', '1.0.0')
    assert(ok == false, 'major skew must be rejected')
    assert(msg:find('Remediation', 1, true) ~= nil, 'remediation required')
  end)

  it('fails closed on unknown binary versions', function()
    local ok, msg = binary.is_compatible('0.12.6', nil)
    assert(ok == false, 'unknown version must fail closed')
    assert(msg:find('Remediation', 1, true) ~= nil, 'remediation required')
  end)
end)

describe('release distribution', function()
  it('maps supported platforms to install.sh asset names', function()
    local asset = binary.platform_asset('Linux', 'x86_64')
    assert(asset == 'tark-linux-x86_64', 'linux asset mismatch: ' .. tostring(asset))
    asset = binary.platform_asset('Darwin', 'arm64')
    assert(asset == 'tark-darwin-arm64', 'macos asset mismatch: ' .. tostring(asset))
  end)

  it('rejects unsupported platforms with an explanation', function()
    local asset, err = binary.platform_asset('Windows', 'x86_64')
    assert(asset == nil and err ~= nil, 'windows must be rejected with a reason')
    asset, err = binary.platform_asset('Linux', 'riscv64')
    assert(asset == nil and err ~= nil, 'riscv64 must be rejected with a reason')
  end)

  it('builds versioned release + checksum URLs', function()
    local urls = binary.download_urls('thoughtoinnovate/tark', '0.12.6', 'tark-linux-x86_64')
    assert(
      urls.binary_url == 'https://github.com/thoughtoinnovate/tark/releases/download/v0.12.6/tark-linux-x86_64',
      'binary url mismatch: ' .. urls.binary_url
    )
    assert(urls.checksum_url == urls.binary_url .. '.sha256', 'checksum sidecar url mismatch')
  end)

  it('parses sha256 sidecar files', function()
    local hash = string.rep('a', 64)
    assert(binary.parse_checksum_file(hash .. '  tark-linux-x86_64\n') == hash, 'sidecar parse failed')
    assert(binary.parse_checksum_file('not-a-hash') == nil, 'garbage checksum must not parse')
  end)
end)
