--- ACP v1 NDJSON stdio client for `tark acp` (R8, S20/S21/S22).
---
--- Wire contract (mirrors src/transport/acp/protocol.rs + server.rs;
--- advertise/use ONLY what the backend implements):
---   client -> server : initialize, session/new, session/prompt,
---                      session/cancel, session/close, session/set_mode,
---                      session/set_config_option (configId 'mode' only),
---                      context/update, _tark/inlineCompletion (opt-in)
---   server -> client : session/update notifications
---                      (agent_message_start/chunk/end, tool_call,
---                      tool_call_update; stopReason end_turn/cancelled/refusal)
---                      session/request_permission requests, answered with
---                      {outcome='cancelled'} or
---                      {outcome='selected', optionId='...'}
---   agentCapabilities: loadSession=false,
---     promptCapabilities={image=false,audio=false,embeddedContext=true},
---     mcpCapabilities={http=false,sse=false}, sessionCapabilities={},
---     authMethods=[].
--- Framing is newline-delimited JSON. Content-Length framing is NEVER
--- sent and inbound Content-Length-prefixed lines are rejected (R8 S20).
local M = {}

--- Backend protocol version we speak.
M.PROTOCOL_VERSION = 1

--- Optional completion extension method (leading underscore, R8 S22).
M.COMPLETION_METHOD = '_tark/inlineCompletion'

--- Client identity reported in initialize.
M.CLIENT_NAME = 'tark-nvim'

--- Encode one NDJSON frame. Pure string handling: rejects embedded
--- newlines and legacy Content-Length envelopes fail-closed.
---@param payload string single JSON object text (no trailing newline)
---@return string|nil frame_or_nil, string|nil err
function M.encode_frame(payload)
  if type(payload) ~= 'string' or payload == '' then
    return nil, 'refusing to emit empty NDJSON frame'
  end
  if payload:find('\n') then
    return nil, 'refusing to emit multi-line NDJSON frame'
  end
  if M.is_content_length_framed(payload) then
    return nil, 'Content-Length framing is not supported; use newline-delimited JSON'
  end
  return payload .. '\n', nil
end

--- True when a line uses the removed Content-Length envelope.
---@param line string
---@return boolean
function M.is_content_length_framed(line)
  if type(line) ~= 'string' then
    return false
  end
  return line:lower():match('^%s*content%-length%s*:') ~= nil
end

--- Split freshly arrived stdio bytes into complete lines.
--- Returns new_remainder plus the list of complete (non-empty) lines;
--- blank lines are tolerated keep-alives and skipped (matches backend).
---@param remainder string unprocessed bytes from the previous chunk
---@param chunk string newly arrived bytes
---@return string new_remainder, table lines
function M.feed_buffer(remainder, chunk)
  local data = (remainder or '') .. (chunk or '')
  local lines = {}
  local start = 1
  while true do
    local nl = data:find('\n', start, true)
    if not nl then
      break
    end
    local line = data:sub(start, nl - 1):gsub('\r$', '')
    if line ~= '' then
      lines[#lines + 1] = line
    end
    start = nl + 1
  end
  return data:sub(start), lines
end

--- Build initialize params. clientCapabilities stays empty: the backend
--- never calls client fs/terminal methods, so we claim none (R8).
---@param client_version string plugin version
---@param completion_supported boolean opt into _tark/inlineCompletion
---@return table
function M.build_initialize(client_version, completion_supported)
  return {
    protocolVersion = M.PROTOCOL_VERSION,
    clientCapabilities = {},
    clientInfo = { name = M.CLIENT_NAME, version = client_version },
    _meta = { tark = { completion = { supported = completion_supported == true } } },
  }
end

--- Build session/new params. mcpServers MUST be empty: the backend
--- rejects entries explicitly (configure via mcp/servers.toml instead).
---@param cwd string working directory
---@return table
function M.build_session_new(cwd)
  return { cwd = cwd, mcpServers = {} }
end

--- Build session/prompt params from plain text.
---@param session_id string
---@param text string prompt text
---@return table
function M.build_prompt(session_id, text)
  return { sessionId = session_id, prompt = { { type = 'text', text = text } } }
end

--- Build the answer to a session/request_permission request.
---@param option_id string|nil selected optionId; nil means deny
---@return table result payload
function M.build_permission_result(option_id)
  if option_id == nil then
    return { outcome = 'cancelled' }
  end
  return { outcome = 'selected', optionId = option_id }
end

--- Validate an initialize response against the implemented surface (R8).
---@param result table decoded result
---@return boolean ok, string message
function M.validate_initialize_result(result)
  if type(result) ~= 'table' then
    return false, 'initialize response was not an object'
  end
  if result.protocolVersion ~= M.PROTOCOL_VERSION then
    return false, 'unsupported ACP protocolVersion ' .. tostring(result.protocolVersion) .. ' (supports 1)'
  end
  local caps = result.agentCapabilities
  if type(caps) ~= 'table' then
    return false, 'initialize response lacks agentCapabilities'
  end
  if caps.loadSession ~= false then
    return false, 'backend unexpectedly offers loadSession; this plugin only uses session/new'
  end
  return true, 'ACP initialize ok'
end

--- Create a client object. Does not spawn anything (see start()).
---@return table client
function M.new()
  return {
    job = nil,
    remainder = '',
    seq = 0,
    pending = {},
    session_id = nil,
    agent_info = nil,
    agent_capabilities = nil,
    completion_method = nil,
    handlers = {},
  }
end

local function next_id(client)
  client.seq = client.seq + 1
  return client.seq
end

--- Send a raw JSON-RPC value over the job channel (NDJSON only).
---@param client table
---@param value table
---@return boolean ok, string|nil err
local function send_value(client, value)
  if not client.job then
    return false, 'ACP subprocess is not running'
  end
  local payload = vim.json.encode(value)
  local frame, ferr = M.encode_frame(payload)
  if not frame then
    return false, ferr
  end
  local ok = vim.fn.chansend(client.job, frame)
  if ok == 0 then
    return false, 'failed to write to ACP subprocess'
  end
  return true, nil
end

--- Dispatch one decoded inbound message.
---@param client table
---@param msg table
local function dispatch(client, msg)
  if msg.method ~= nil then
    if msg.method == 'session/update' then
      local h = client.handlers.on_update
      if h then
        vim.schedule(function()
          h(msg.params or {})
        end)
      end
    elseif msg.method == 'session/request_permission' then
      local h = client.handlers.on_permission
      if h then
        vim.schedule(function()
          h(msg.id, msg.params or {})
        end)
      else
        -- No UI to answer: deny fail-closed (NFR1) so the agent never
        -- executes an unapproved risky action.
        M.respond_permission(client, msg.id, nil)
      end
    end
    return
  end
  if msg.id ~= nil and (msg.result ~= nil or msg.error ~= nil) then
    local cb = client.pending[msg.id]
    client.pending[msg.id] = nil
    if cb then
      vim.schedule(function()
        if msg.error ~= nil then
          cb(nil, msg.error.message or 'ACP error')
        else
          cb(msg.result, nil)
        end
      end)
    end
  end
end

--- Handle raw stdout bytes from the subprocess.
---@param client table
---@param chunk string
local function on_bytes(client, chunk)
  local remainder, lines = M.feed_buffer(client.remainder, chunk)
  client.remainder = remainder
  for _, line in ipairs(lines) do
    if M.is_content_length_framed(line) then
      -- Removed framing (R12): never reinterpret, just ignore the line.
      vim.schedule(function()
        vim.notify(
          '[tark] Ignored Content-Length framed ACP line; backend speaks NDJSON only.',
          vim.log.levels.WARN
        )
      end)
    else
      local ok, msg = pcall(vim.json.decode, line)
      if ok and type(msg) == 'table' then
        dispatch(client, msg)
      end
    end
  end
end

--- Spawn `tark acp` over stdio. Never blocks; all I/O is jobstart-based.
---@param binary string resolved tark path
---@param args table extra argv appended after 'acp'
---@param handlers table {on_update, on_permission, on_exit}
---@return table client, string|nil err
function M.start(binary, args, handlers)
  local client = M.new()
  client.handlers = handlers or {}
  local cmd = { binary, 'acp' }
  for _, a in ipairs(args or {}) do
    cmd[#cmd + 1] = a
  end
  local job = vim.fn.jobstart(cmd, {
    rpc = false,
    on_stdout = function(_, data)
      if data then
        on_bytes(client, table.concat(data, '\n'))
      end
    end,
    on_stderr = function(_, _)
      -- Backend diagnostics go to stderr; intentionally ignored here so
      -- a noisy log stream can never corrupt NDJSON parsing (NFR3).
    end,
    on_exit = function(_, code)
      local h = client.handlers.on_exit
      client.job = nil
      client.pending = {}
      if h then
        vim.schedule(function()
          h(code)
        end)
      end
    end,
  })
  if job <= 0 then
    return nil, 'could not spawn tark ACP subprocess'
  end
  client.job = job
  return client, nil
end

--- Send a request; cb(result_or_nil, err_or_nil) runs via vim.schedule.
---@param client table
---@param method string one of the implemented client->server methods
---@param params table
---@param cb function|nil
function M.request(client, method, params, cb)
  local id = next_id(client)
  if cb then
    client.pending[id] = cb
  end
  local ok, err = send_value(client, { jsonrpc = '2.0', id = id, method = method, params = params })
  if not ok then
    client.pending[id] = nil
    if cb then
      vim.schedule(function()
        cb(nil, err)
      end)
    end
    return nil
  end
  return id
end

--- Answer a session/request_permission request from the backend.
---@param client table
---@param id any request id to answer
---@param option_id string|nil selected optionId; nil denies
function M.respond_permission(client, id, option_id)
  send_value(client, { jsonrpc = '2.0', id = id, result = M.build_permission_result(option_id) })
end

--- Run initialize; validates the response surface (R8).
---@param client table
---@param client_version string
---@param completion_supported boolean
---@param cb function called as cb(ok, err)
function M.initialize(client, client_version, completion_supported, cb)
  M.request(client, 'initialize', M.build_initialize(client_version, completion_supported), function(result, err)
    if err then
      cb(false, 'ACP initialize failed: ' .. tostring(err))
      return
    end
    local ok, msg = M.validate_initialize_result(result or {})
    if not ok then
      cb(false, msg)
      return
    end
    client.agent_info = result.agentInfo
    client.agent_capabilities = result.agentCapabilities
    local meta = result._meta or {}
    if meta.tark and meta.tark.completion then
      client.completion_method = meta.tark.completion.method
    end
    cb(true, nil)
  end)
end

--- Create a session (session/new). mcpServers is always empty (R8).
---@param client table
---@param cwd string
---@param cb function called as cb(session_id_or_nil, err_or_nil)
function M.session_new(client, cwd, cb)
  M.request(client, 'session/new', M.build_session_new(cwd), function(result, err)
    if err then
      cb(nil, 'session/new failed: ' .. tostring(err))
      return
    end
    if type(result) ~= 'table' or not result.sessionId then
      cb(nil, 'session/new response lacks sessionId')
      return
    end
    client.session_id = result.sessionId
    cb(result.sessionId, nil)
  end)
end

--- Send a prompt; streamed session/update notifications follow.
--- The prompt result carries {accepted, requestId} for correlation.
---@param client table
---@param text string
---@param cb function called as cb(request_id_or_nil, err_or_nil)
function M.prompt(client, text, cb)
  if not client.session_id then
    if cb then
      vim.schedule(function()
        cb(nil, 'no ACP session; call session/new first')
      end)
    end
    return
  end
  M.request(client, 'session/prompt', M.build_prompt(client.session_id, text), function(result, err)
    if err then
      if cb then
        cb(nil, tostring(err))
      end
      return
    end
    if type(result) ~= 'table' or result.accepted ~= true then
      if cb then
        cb(nil, 'prompt was not accepted by the backend')
      end
      return
    end
    if cb then
      cb(result.requestId, nil)
    end
  end)
end

--- Cancel the running prompt (session/cancel). Session-scoped (NFR4).
---@param client table
---@param cb function|nil called as cb(cancelled_bool)
function M.cancel(client, cb)
  if not client.session_id then
    if cb then
      vim.schedule(function()
        cb(false)
      end)
    end
    return
  end
  M.request(client, 'session/cancel', { sessionId = client.session_id }, function(result, _)
    if cb then
      local cancelled = type(result) == 'table' and result.cancelled == true
      cb(cancelled)
    end
  end)
end

--- Close the session (session/close), best-effort.
---@param client table
---@param cb function|nil
function M.close(client, cb)
  if not client.session_id then
    if cb then
      vim.schedule(function()
        cb()
      end)
    end
    return
  end
  local sid = client.session_id
  client.session_id = nil
  M.request(client, 'session/close', { sessionId = sid }, function(_, _)
    if cb then
      cb()
    end
  end)
end

--- Switch the agent mode (session/set_mode). Only ask/plan/build exist.
---@param client table
---@param mode_id string 'ask'|'plan'|'build'
---@param cb function|nil called as cb(ok, err)
function M.set_mode(client, mode_id, cb)
  if mode_id ~= 'ask' and mode_id ~= 'plan' and mode_id ~= 'build' then
    if cb then
      vim.schedule(function()
        cb(false, "unknown mode '" .. tostring(mode_id) .. "' (supported: ask, plan, build)")
      end)
    end
    return
  end
  if not client.session_id then
    if cb then
      vim.schedule(function()
        cb(false, 'no ACP session')
      end)
    end
    return
  end
  M.request(client, 'session/set_mode', { sessionId = client.session_id, modeId = mode_id }, function(_, err)
    if cb then
      cb(err == nil, err)
    end
  end)
end

--- Send editor context (context/update) for the active session.
---@param client table
---@param context table {activeFile?, cursor?, selection?, activeExcerpt?, buffers?}
function M.context_update(client, context)
  if not client.session_id then
    return
  end
  local params = vim.tbl_extend('force', { sessionId = client.session_id }, context or {})
  M.request(client, 'context/update', params, nil)
end

--- Request an inline completion via the optional extension (R8 S22).
--- Requires the initialize opt-in; standard chat is unaffected otherwise.
---@param client table
---@param args table {path, line, col, prefix, suffix, maxTokens?, language?, triggerKind?, clientRequestId?, bufferVersion?}
---@param cb function called as cb(result_or_nil, err_or_nil)
function M.inline_completion(client, args, cb)
  local function fail(err)
    vim.schedule(function()
      cb(nil, err)
    end)
  end
  if not client.session_id then
    fail('no ACP session; start one before requesting completions')
    return
  end
  if client.completion_method == nil then
    fail('completion extension was not negotiated by the backend; chat still works')
    return
  end
  if client.completion_method ~= M.COMPLETION_METHOD then
    fail('unknown completion method ' .. tostring(client.completion_method))
    return
  end
  local params = {
    sessionId = client.session_id,
    path = args.path,
    cursor = { line = args.line, col = args.col },
    prefix = args.prefix,
    suffix = args.suffix,
  }
  if args.maxTokens then
    params.maxTokens = args.maxTokens
  end
  if args.language then
    params.language = args.language
  end
  if args.triggerKind then
    params.triggerKind = args.triggerKind
  end
  if args.clientRequestId then
    params.clientRequestId = args.clientRequestId
  end
  if args.bufferVersion then
    params.bufferVersion = args.bufferVersion
  end
  M.request(client, M.COMPLETION_METHOD, params, function(result, err)
    if err then
      cb(nil, tostring(err))
      return
    end
    cb(result or {}, nil)
  end)
end

--- Stop the subprocess. session/close is attempted first (best-effort),
--- then the job is killed so nothing is orphaned (S26 cleanup).
---@param client table
function M.stop(client)
  if not client then
    return
  end
  if client.job and client.session_id then
    pcall(send_value, client, {
      jsonrpc = '2.0',
      id = next_id(client),
      method = 'session/close',
      params = { sessionId = client.session_id },
    })
  end
  client.session_id = nil
  client.pending = {}
  if client.job then
    pcall(vim.fn.jobstop, client.job)
    client.job = nil
  end
end

--- True when the subprocess handle is alive.
---@param client table|nil
---@return boolean
function M.is_running(client)
  return client ~= nil and client.job ~= nil
end

return M
