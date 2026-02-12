local M = {}

local function collect_buffers()
    local buffers = {}
    for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
        if vim.api.nvim_buf_is_loaded(bufnr) then
            local name = vim.api.nvim_buf_get_name(bufnr)
            if name ~= '' and vim.bo[bufnr].buftype == '' then
                table.insert(buffers, {
                    path = name,
                    name = vim.fn.fnamemodify(name, ':t'),
                    modified = vim.bo[bufnr].modified,
                })
            end
        end
    end
    return buffers
end

function M.from_current_buffer()
    local path = vim.api.nvim_buf_get_name(0)
    local cursor = vim.api.nvim_win_get_cursor(0)
    local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
    local text = table.concat(lines, '\n')

    return {
        active_file = path,
        cursor = { line = cursor[1], col = cursor[2] + 1 },
        selection = {
            start_line = 1,
            start_col = 1,
            end_line = #lines,
            end_col = 1,
            text = text,
        },
        buffers = collect_buffers(),
    }
end

function M.from_visual_selection(line1, line2)
    local path = vim.api.nvim_buf_get_name(0)
    local cursor = vim.api.nvim_win_get_cursor(0)
    local selected_lines = vim.api.nvim_buf_get_lines(0, line1 - 1, line2, false)
    local text = table.concat(selected_lines, '\n')

    return {
        active_file = path,
        cursor = { line = cursor[1], col = cursor[2] + 1 },
        selection = {
            start_line = line1,
            start_col = 1,
            end_line = line2,
            end_col = 1,
            text = text,
        },
        buffers = collect_buffers(),
    }
end

return M
