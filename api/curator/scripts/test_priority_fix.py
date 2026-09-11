from curator.pipeline.priority import calculate_priority

class A:
    def __init__(self, rule_id, severity):
        self.rule_id = rule_id
        self.severity = severity

alerts = [A('CUR-021','high'), A('CUR-003','high')]
hosts = {'NEWYORK.dmevals.local'}
score, reason = calculate_priority(alerts, hosts)
print("Score:", score)
for f in reason['factors']:
    print(f"  +{f['points']}: {f['reason']}")
print("Will surface:", score > 0)
