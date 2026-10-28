# Extras (parked)

Things that work but are not part of the main tool for now. Nothing in `run.py`, the web page or the tests uses them.

## adaptive_run.py: Claude as the attacker

Claude plays the user in a multi-turn conversation, reads each reply and writes the next message. It needs an Anthropic API key
and every request is billed, so it is parked until there is budget for it. It has only been tested against a fake server so far.

To switch it back on:

1. Move `adaptive_run.py` back to `tools/` (and `test_adaptive.py` to `tests/`).
2. Add `"adaptive"` to `TOOLS` in `run.py` and `ui/app.py`, and an entry for it in `REQUEST_HINTS` in `ui/app.py`.
3. `pip install anthropic`, set `ANTHROPIC_API_KEY` in your environment (never commit it), then `python run.py adaptive --target unguarded --tier smoke`.

To run its self-checks where it is now: `python extras/test_adaptive.py`.
