## Test suite runs on a clean Windows clone

`tests/unit/adapters/test_adapter_onboard_record.py` invoked its fixture CLI
(`tests/fixtures/probe/probe_recordable.py`) by executing the `.py` file
directly, relying on its `#!/usr/bin/env python3` shebang. Windows has no
shebang interpretation, so `scripts/run_tests.py -x` halted on a fresh
Windows clone with `FileNotFoundError [WinError 2]` before the fixture ever
ran. The test now invokes the fixture through the current interpreter
(`sys.executable <fixture path>`), which changes nothing about what the
fixture receives -- `InvocationSpec.build_argv` already emits
`[binary, *subcommands, ...]`. Test-only change; no production behavior
moves (#5647).
