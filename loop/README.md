# loop/

Files copied byte for byte from [evidence-network/loop](https://github.com/evidence-network/loop)
at revision `9e45b3aad5655b041c5ee2079923870dcb6514f0`, the main branch after loop#32 merged.
The plugin reads them at build time; never edit them by hand. To take a newer revision, copy
the same paths again and change the revision here and in `network_join.rs`.

- `joins/SWITCH_CONSENT.txt`: the statement shown under the join switch. A join signs its sha256.
- `reporter/reporter.json`: the reporter node a join is sent to, and how long to wait between tries.
- `tests/fixtures/join/`: loop's signed join and leave fixtures, which the plugin's check must
  judge as `scripts/check_join.py` does.
