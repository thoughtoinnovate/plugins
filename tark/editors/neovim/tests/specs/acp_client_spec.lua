local acp = require('tark.acp_client')

describe('acp client', function()
    it('exposes required ACP API functions', function()
        assert.is_function(acp.setup)
        assert.is_function(acp.on)
        assert.is_function(acp.ensure_started)
        assert.is_function(acp.send_message)
        assert.is_function(acp.inline_completion)
        assert.is_function(acp.set_mode)
        assert.is_function(acp.cancel)
        assert.is_function(acp.queue_size)
        assert.is_function(acp.is_connected)
        assert.is_function(acp.close)
        assert.is_function(acp.get_profile)
        assert.is_function(acp.get_config_options)
        assert.is_function(acp.get_config_option)
        assert.is_function(acp.supports_config_switch)
        assert.is_function(acp.get_timeout_for_method)
    end)

    it('starts with empty queue', function()
        assert.equals(0, acp.queue_size())
    end)

    it('defaults to generic resolved profile in auto mode before initialize', function()
        acp.setup({ profile = 'auto' })
        assert.equals('generic', acp.get_profile())
    end)

    it('supports per-method timeout config', function()
        acp.setup({
            profile = 'generic',
            timeouts = {
                prompt_ms = 0,
                set_mode_ms = 3210,
            },
        })
        assert.equals(0, acp.get_timeout_for_method('session/prompt'))
        assert.equals(3210, acp.get_timeout_for_method('session/set_mode'))
    end)
end)
