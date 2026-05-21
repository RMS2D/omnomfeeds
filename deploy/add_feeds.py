import json, sys

path = '/opt/omnomfeeds/config.json'
with open(path) as f:
    cfg = json.load(f)

# Find names already present
existing = {f['name'] for f in cfg['rss_feeds']}
new_feeds = [
    {'name': 'MSRC Update Guide',     'url': 'https://api.msrc.microsoft.com/update-guide/rss'},
    {'name': 'Mandiant Threat Intel', 'url': 'https://www.mandiant.com/resources/blog/rss.xml'},
]
added = []
# Insert just before "Ubuntu Security Notices" if it exists, else append
target_idx = next((i for i, f in enumerate(cfg['rss_feeds']) if f['name'] == 'Ubuntu Security Notices'), len(cfg['rss_feeds']))
for nf in reversed(new_feeds):
    if nf['name'] not in existing:
        cfg['rss_feeds'].insert(target_idx, nf)
        added.append(nf['name'])

with open(path, 'w') as f:
    json.dump(cfg, f, indent=2)
print('added:', added)
