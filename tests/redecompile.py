"""Live/headless regression for native dedup lifetime, run in IDAPython/MCP.

Call verify_redecompile([ea, ...], '/absolute/path/to/unslopper.dylib').
There is no optimizer reset between rounds; mark_cfunc_dirty is sufficient.
"""
import ida_loader
import ida_hexrays


def verify_redecompile(addrs, plugin_path, rounds=3):
    if rounds < 2:
        raise ValueError('at least two rounds are required')
    plugin = ida_loader.load_plugin(plugin_path)
    if plugin is None:
        raise RuntimeError('Unslopper failed to load')
    ida_loader.run_plugin(plugin, 2)
    results = []
    for ea in addrs:
        texts = []
        for unused in range(rounds):
            ida_hexrays.mark_cfunc_dirty(ea, False)
            cfunc = ida_hexrays.decompile(ea)
            if cfunc is None:
                raise RuntimeError('decompilation failed at ' + hex(ea))
            texts.append(str(cfunc))
        stable = all(text == texts[0] for text in texts[1:])
        if not stable:
            raise AssertionError('unstable repeated decompilation at ' + hex(ea))
        results.append({'ea': hex(ea), 'rounds': rounds, 'stable': stable,
                        'lines': len(texts[0].splitlines()),
                        'gotos': texts[0].count('goto '),
                        'switches': texts[0].count('switch (')})
    return results
