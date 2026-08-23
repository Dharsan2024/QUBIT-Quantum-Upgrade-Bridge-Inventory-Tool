# T12_validation_gate — Patch validation gate (qubit_migrate.transform.validate)

All 243 combinations of five stages x {pass, fail, skipped} were evaluated. The verdict depends on only two things, and the collapse below is asserted sound against all 243. **A skipped stage never turns a failure into a pass, but it does mean the patch was not fully verified** — which is what `partial` reports, and what a caller must not ignore.

| any stage failed | any stage skipped | passed | partial | meaning |
|---|---|---|---|---|
| no | no | True | False | accepted and fully verified |
| no | yes | True | True | accepted, but not fully verified |
| yes | no | False | False | patch rejected |
| yes | yes | False | True | patch rejected |
