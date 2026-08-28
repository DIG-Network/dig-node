p = 'crates/dig-node-service/src/control.rs'
s = open(p, encoding='utf-8', newline='').read()


def rep(old, new, tag, n=1):
    global s
    assert s.count(old) == n, f'{tag}: {s.count(old)}'
    s = s.replace(old, new, n)


rep('"control.collateral.margin.set",\n', '"control.collateral.margin.set",\n    "control.collateral.buffer",\n',
    'lists', 2)
rep('        "control.collateral.margin.set" => collateral_margin_set(id, params),',
    '        "control.collateral.margin.set" => collateral_margin_set(id, params),\n'
    '        "control.collateral.buffer" => collateral_buffer(id),',
    'dispatch')

frag = open('.bufh.rs', encoding='utf-8', newline='').read()
anchor = "/// `control.collateral.margin.get` — the node's local safety margin, in basis points."
assert s.count(anchor) == 1, 'anchor'
s = s.replace(anchor, frag.strip('\n') + '\n\n' + anchor, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)

p = 'crates/dig-node-service/src/control_cli.rs'
s = open(p, encoding='utf-8', newline='').read()
rep('    ControlAction::CollateralMarginGet.method(),',
    '    ControlAction::CollateralMarginGet.method(),', 'noop-check')
rep('''    CollateralMarginGet,''',
    '''    CollateralMarginGet,
    /// `control.collateral.buffer` — the node's OWN answer: what it recommends holding and the
    /// funding state it is in, computed from the served set and balance the node itself knows.
    ///
    /// Distinct from the operator-supplied form of `dign collateral buffer`, which computes the
    /// same figures from operands a person types. The node's answer is authoritative; the operands
    /// exist so a person can get a number before the node can enumerate its own served set.
    CollateralBuffer,''', 'variant')
rep('''            ControlAction::CollateralMarginGet => "control.collateral.margin.get",''',
    '''            ControlAction::CollateralMarginGet => "control.collateral.margin.get",
            ControlAction::CollateralBuffer => "control.collateral.buffer",''', 'method')
rep('''        ControlAction::CollateralMarginGet.method(),''',
    '''        ControlAction::CollateralMarginGet.method(),
        ControlAction::CollateralBuffer.method(),''', 'covered')
open(p, 'w', encoding='utf-8', newline='').write(s)
print('ok')
