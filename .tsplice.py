p = 'crates/dig-node-service/src/collateral.rs'
lines = open(p, encoding='utf-8', newline='').read().split('\n')

start = None
end = None
for i, l in enumerate(lines):
    if start is None and '/// Unwrap a `Known` answer, or fail loudly naming what came back instead.' in l:
        start = i
    if start is not None and 'fn format_dig_keeps_three_decimals' in l:
        end = i - 1
        break
assert start is not None and end is not None and end > start, (start, end)
assert lines[end].strip() == '#[test]', lines[end]

new = open('.t.rs', encoding='utf-8', newline='').read().rstrip('\n').split('\n')
lines[start:end] = new + ['']
s = '\n'.join(lines)

# The tests need the contract's params const in scope.
old = '    use dig_mirror_collateral::{base_per_store, handicap_for_owners, required_per_store, EpochCensus};'
new_imp = ('    use dig_mirror_collateral::{\n'
           '        base_per_store, handicap_for_owners, required_per_store, EpochCensus,\n'
           '    };\n'
           '    use dig_node_control_interface::params::DEFAULT_BUFFER_HORIZON_EPOCHS;')
assert s.count(old) == 1, 'test import'
s = s.replace(old, new_imp, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)
print('ok')
