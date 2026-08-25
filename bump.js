const fs = require('fs');
const p = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const q = p.version.split('.').map(Number); q[2]++; p.version = q.join('.');
fs.writeFileSync('package.json', JSON.stringify(p, null, 2) + '\n');
const f = 'app/api/system/update-status/route.js';
let s = fs.readFileSync(f, 'utf8').replace(/\r\n/g, '\n');
const note = [
  "  '" + p.version + "': [",
  "    'Palo Alto firewalls managed by Panorama now collect their rules again. Those rules are pushed centrally rather than stored on the firewall, and the code that read the pushed policy had never worked over this connection type.',",
  "  ],",
  "  '2.62.0': [",
].join('\n');
if (s.indexOf("  '2.62.0': [") === -1) { console.log('MISS'); process.exit(1); }
fs.writeFileSync(f, s.replace("  '2.62.0': [", note));
console.log(p.version);
