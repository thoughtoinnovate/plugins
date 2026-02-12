local M = {}

local MAX_EXCERPT_BYTES = 20 * 1024
local WINDOW_LINES = 120

local function relpath(path)
    local cwd = vim.fn.getcwd()
    if path:sub(1, #cwd) == cwd then
        local suffix = path:sub(#cwd + 1)
        if suffix:sub(1, 1) == '/' then
            suffix = suffix:sub(2)
        end
        return suffix
    end
    return path
end

local function collect_buffers()
    local buffers = {}
    for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
        if vim.api.nvim_buf_is_loaded(bufnr) then
            local name = vim.api.nvim_buf_get_name(bufnr)
            if name ~= '' and vim.bo[bufnr].buftype == '' then
                table.insert(buffers, {
                    path = relpath(name),
                    name = vim.fn.fnamemodify(name, ':t'),
                    modified = vim.bo[bufnr].modified,
                })
            end
        end
    end
    return buffers
end

local function excerpt_for_buffer(bufnr, cursor_line)
    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local full = table.concat(lines, '\n')
    if #full <= MAX_EXCERPT_BYTES then
        return full
    end

    local start_line = math.max(1, cursor_line - WINDOW_LINES)
    local end_line = math.min(#lines, cursor_line + WINDOW_LINES)
    local excerpt_lines = vim.api.nvim_buf_get_lines(bufnr, start_line - 1, end_line, false)
    local excerpt = table.concat(excerpt_lines, '\n')
    if #excerpt > MAX_EXCERPT_BYTES then
        excerpt = excerpt:sub(1, MAX_EXCERPT_BYTES)
    end
    return excerpt
end

function M.from_current_buffer()
    local bufnr = vim.api.nvim_get_current_buf()
    local path = vim.api.nvim_buf_get_name(bufnr)
    local cursor = vim.api.nvim_win_get_cursor(0)

    return {
        active_file = relpath(path),
        cursor = { line = cursor[1], col = cursor[2] + 1 },
        active_excerpt = excerpt_for_buffer(bufnr, cursor[1]),
        buffers = collect_buffers(),
    }
end

function M.from_visual_selection(line1, line2)
    local bufnr = vim.api.nvim_get_current_buf()
    local path = vim.api.nvim_buf_get_name(bufnr)
    local cursor = vim.api.nvim_win_get_cursor(0)

    local start_mark = vim.api.nvim_buf_get_mark(bufnr, '<')
    local end_mark = vim.api.nvim_buf_get_mark(bufnr, '>')

    local start_line = line1
    local end_line = line2
    local start_col = 1
    local end_col = 1

    if start_mark and start_mark[1] > 0 then
        start_line = start_mark[1]
        start_col = start_mark[2] + 1
    end
    if end_mark and end_mark[1] > 0 then
        end_line = end_mark[1]
        end_col = end_mark[2] + 1
    end

    if start_line > end_line or (start_line == end_line and start_col > end_col) then
        local tl, tc = start_line, start_col
        start_line, start_col = end_line, end_col
        end_line, end_col = tl, tc
    end

    local selected = vim.api.nvim_buf_get_text(
        bufnr,
        start_line - 1,
        math.max(start_col - 1, 0),
        end_line - 1,
        math.max(end_col, 0),
        {}
    )

    return {
        active_file = relpath(path),
        cursor = { line = cursor[1], col = cursor[2] + 1 },
        selection = {
            start_line = start_line,
            start_col = start_col,
            end_line = end_line,
            end_col = end_col,
            text = table.concat(selected, '\n'),
        },
        active_excerpt = excerpt_for_buffer(bufnr, cursor[1]),
        buffers = collect_buffers(),
    }
end

return M
