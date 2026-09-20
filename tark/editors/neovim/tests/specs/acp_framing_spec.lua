-- ACP NDJSON framing + request-builder specs (R8 S20/S22).
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

local function eq(a, b)
  assert(vim.deep_equal(a, b), 'expected equal:\n' .. vim.inspect(a) .. '\nvs\n' .. vim.inspect(b))
end

local acp = require('tark.acp_client')

describe('NDJSON framing', function()
  it('encodes a single-line frame with trailing newline', function()
    local frame, err = acp.encode_frame('{"jsonrpc":"2.0","id":1}')
    eq(frame, '{"jsonrpc":"2.0","id":1}\n')
    assert(err == nil, 'no error expected')
  end)

  it('rejects multi-line payloads (no split frames)', function()
    local frame, err = acp.encode_frame('{"a":1}\n{"b":2}')
    assert(frame == nil, 'multi-line frame must be rejected')
    assert(err ~= nil, 'rejection needs a reason')
  end)

  it('rejects empty payloads', function()
    local frame, _ = acp.encode_frame('')
    assert(frame == nil, 'empty frame must be rejected')
  end)

  it('never emits Content-Length framing', function()
    local frame, err = acp.encode_frame('Content-Length: 42\r\n\r\n{"jsonrpc":"2.0"}')
    assert(frame == nil, 'Content-Length envelope must never be sent, got: ' .. tostring(err))
  end)

  it('detects Content-Length prefixed lines', function()
    assert(acp.is_content_length_framed('Content-Length: 120') == true)
    assert(acp.is_content_length_framed('content-length: 5') == true)
    assert(acp.is_content_length_framed('{"jsonrpc":"2.0"}') == false)
  end)

  it('splits complete lines and keeps the remainder', function()
    local rem, lines = acp.feed_buffer('', '{"a":1}\n{"b":2}\n{"part')
    eq(lines, { '{"a":1}', '{"b":2}' })
    eq(rem, '{"part')
    local rem2, lines2 = acp.feed_buffer(rem, 'ial"}\n')
    eq(lines2, { '{"partial"}' })
    eq(rem2, '')
  end)

  it('skips blank keep-alive lines and tolerates CRLF', function()
    local _, lines = acp.feed_buffer('', '\n\r\n{}\r\n')
    eq(lines, { '{}' })
  end)
end)

describe('ACP request builders (backend surface only)', function()
  it('initialize advertises protocolVersion 1 and completion opt-in', function()
    local params = acp.build_initialize('0.12.6', true)
    assert(params.protocolVersion == 1, 'protocolVersion must be 1')
    eq(params.clientInfo.name, 'tark-nvim')
    eq(params.clientInfo.version, '0.12.6')
    assert(params._meta.tark.completion.supported == true, 'completion opt-in missing')
  end)

  it('initialize can decline the completion extension', function()
    local params = acp.build_initialize('0.12.6', false)
    assert(params._meta.tark.completion.supported == false, 'opt-out must be explicit')
  end)

  it('session/new always sends an empty mcpServers list', function()
    local params = acp.build_session_new('/tmp/work')
    eq(params.cwd, '/tmp/work')
    eq(params.mcpServers, {})
  end)

  it('prompt uses text content blocks', function()
    local params = acp.build_prompt('acp-1', 'hello')
    eq(params.sessionId, 'acp-1')
    eq(params.prompt, { { type = 'text', text = 'hello' } })
  end)

  it('permission answers use outcome/optionId only', function()
    eq(acp.build_permission_result('allow_once'), { outcome = 'selected', optionId = 'allow_once' })
    eq(acp.build_permission_result(nil), { outcome = 'cancelled' })
  end)

  it('accepts the exact backend initialize surface', function()
    local ok, _ = acp.validate_initialize_result({
      protocolVersion = 1,
      agentCapabilities = {
        loadSession = false,
        promptCapabilities = { image = false, audio = false, embeddedContext = true },
        mcpCapabilities = { http = false, sse = false },
        sessionCapabilities = {},
      },
    })
    assert(ok == true, 'exact backend surface must validate')
  end)

  it('rejects wrong protocol versions', function()
    local ok, msg = acp.validate_initialize_result({ protocolVersion = 2, agentCapabilities = { loadSession = false } })
    assert(ok == false, 'protocolVersion 2 must be rejected')
    assert(msg ~= nil, 'rejection needs a message')
  end)

  it('rejects loadSession offers (only session/new is used)', function()
    local ok, _ = acp.validate_initialize_result({ protocolVersion = 1, agentCapabilities = { loadSession = true } })
    assert(ok == false, 'loadSession=true must be rejected')
  end)

  it('extension method name keeps its leading underscore', function()
    assert(acp.COMPLETION_METHOD == '_tark/inlineCompletion', 'extension method renamed?')
    assert(acp.COMPLETION_METHOD:sub(1, 1) == '_', 'extension methods must start with _')
  end)
end)
