-- Permission request parsing/rendering specs (R8 S21, NFR1 fail-closed).
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

local permission = require('tark.permission')

local function approval_params()
  return {
    sessionId = 'acp-1',
    toolCall = { toolCallId = 'toolcall-1', title = 'shell cargo test (in /work)', status = 'pending', kind = 'execute', rawInput = 'cargo test' },
    options = {
      { optionId = 'allow_once', name = 'Allow once', kind = 'allow_once' },
      { optionId = 'reject_once', name = 'Reject once', kind = 'reject_once' },
    },
    _meta = { tark = { requestId = 'req-1', tool = 'shell', workingDir = '/work' } },
  }
end

describe('permission request parsing', function()
  it('extracts title, input, working dir, and options', function()
    local view = permission.parse_request(approval_params())
    assert(view.title == 'shell cargo test (in /work)', 'title mismatch: ' .. view.title)
    assert(view.input == 'cargo test', 'input mismatch')
    assert(view.working_dir == '/work', 'working dir mismatch')
    assert(#view.options == 2, 'expected 2 options')
    assert(view.options[1].option_id == 'allow_once', 'first option id mismatch')
    assert(view.is_elicitation == false, 'approval is not elicitation')
  end)

  it('flags elicitation requests from _meta', function()
    local view = permission.parse_request({
      toolCall = { title = 'Pick a model', status = 'pending', kind = 'elicit', rawInput = 'Which?' },
      options = { { optionId = 'gpt', name = 'GPT', kind = 'elicit_option' } },
      _meta = { tark = { elicitation = true } },
    })
    assert(view.is_elicitation == true, 'elicitation flag missing')
    assert(view.working_dir == nil, 'elicitation has no working dir')
  end)

  it('tolerates missing fields', function()
    local view = permission.parse_request({})
    assert(view.title ~= nil and view.title ~= '', 'title needs a fallback')
    assert(#view.options == 0, 'options default to empty')
  end)
end)

describe('permission outcomes (fail-closed)', function()
  it('maps a chosen option to selected/optionId', function()
    local known = { { option_id = 'allow_once' }, { option_id = 'reject_once' } }
    local res = permission.outcome_for('allow_once', known)
    assert(res.outcome == 'selected' and res.optionId == 'allow_once', 'outcome mismatch: ' .. vim.inspect(res))
  end)

  it('denies on nil (window dismissed)', function()
    local res = permission.outcome_for(nil, { { option_id = 'allow_once' } })
    assert(res.outcome == 'cancelled', 'nil choice must deny')
  end)

  it('denies unknown option ids even when offered list exists', function()
    local res = permission.outcome_for('allow_always:rm -rf /', { { option_id = 'allow_once' } })
    assert(res.outcome == 'cancelled', 'unknown option must deny, got: ' .. vim.inspect(res))
  end)
end)

describe('permission rendering', function()
  it('shows title, command, cwd, options, and deny hint', function()
    local lines = permission.render_lines(permission.parse_request(approval_params()))
    local text = table.concat(lines, '\n')
    assert(text:find('shell cargo test', 1, true) ~= nil, 'title missing')
    assert(text:find('cargo test', 1, true) ~= nil, 'command missing')
    assert(text:find('/work', 1, true) ~= nil, 'cwd missing')
    assert(text:find('Allow once', 1, true) ~= nil, 'option missing')
    assert(text:find('deny', 1, true) ~= nil, 'deny hint missing')
  end)
end)
