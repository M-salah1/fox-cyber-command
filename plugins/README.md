# Plugins — FOX CYBER COMMAND v2.00

Plugins extend FOXCC with new tools. A plugin is a Python module in
this directory with `name`, `version`, `status` and a `run()` that
returns an honest status dict. Plugins never run silently-installed
binaries, never use `shell=True` with user input, and never return
invented results: a missing tool reports `missing` with install
instructions.

See `example_plugin.py` for the template. To register a plugin, add
its metadata to `foxcc/core/registry.py` (or load it via the
PluginManager in a future release) — the plugin file itself only
defines the interface.

Status values (foxcc.core.registry.PLUGIN_STATUS):
`INSTALLED / MISSING / PARTIAL / FAILED / INCOMPATIBLE / PC_ONLY /
DISABLED` — INSTALLED only after a real binary check.
