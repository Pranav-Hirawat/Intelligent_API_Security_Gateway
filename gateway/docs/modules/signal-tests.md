# Signal Test Scripts

`testing/signals/` sends traffic to a running gateway and checks that each signal is visible without granting a detector authority to reject its own triggering request.

```bash
bash testing/signals/run_all.sh
```

Run individual checks with `sqli.sh`, `brute_force.sh`, `flood.sh`, `traversal.sh`, `object_enumeration.sh`, and `ownership.sh`. `redis_inspect.sh` helps inspect Redis output.

For end-to-end policy tests, use an address in `203.0.113.x`; private/local targets are correctly rejected by the decision-engine policy writer.
