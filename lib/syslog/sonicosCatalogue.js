// lib/syslog/sonicosCatalogue.js
//
// SonicOS message-id (`m=`) dispatch: id -> (group, subcategory, logClass).
//
// ⛔ WHY A TABLE AT ALL. SonicOS Enhanced Syslog has no field naming the kind of
// event. `c=` looks like it (219/220 lines) and is AMBIGUOUS — measured, `c=32`
// covers Users/Authentication, Security Services/IPS, Security Services/Attacks
// AND Firewall Settings/Flood Protection at once, so it cannot separate `event`
// from `threat`. It is a legacy power-of-two category mask and is kept in
// `fields` as a coarse signal only. The id is the only precise key.
//
// ⛔ PROVENANCE, IN TWO TIERS, AND THEY ARE NOT THE SAME EVIDENCE.
//
//   VENDOR  — 349 ids from SonicWall's own published log-event reference, which
//             Elastic embedded verbatim as comments beside each code in its
//             `message_codes` map. Extracted to
//             secvault-lab/corpus/sonicwall/derived-sonicos-msgid-catalogue.csv.
//             The (group, subcategory) pair is the vendor's; the logClass is
//             OURS, assigned per pair below.
//
//   DERIVED — 21 further ids that a real appliance emitted and the vendor table
//             does NOT contain. ⛔ Their class is read off the message TEXT, not
//             stated by the vendor, and three of them are the highest-volume
//             event types on the device that produced them. They are kept apart
//             so nothing can present them as a vendor statement, and
//             `classOf()` reports which tier answered.
//
// ⛔ SonicOS has ~1,700 message ids. 349 + 21 is not the whole space, and an id
// in neither tier must resolve through `gcat=` or REFUSE — never a default
// bucket. Full analysis: secvault-lab/findings/SONICWALL-SYSLOG.md section 2.

'use strict';

// [group, subcategory, logClass, [message ids]]
// ⛔ The logClass column is the only part of this table that is ours. Where a
// GROUP spans classes the SUBCATEGORY decides: Security Services splits into
// threat (Attacks/IPS/IDP/Anti-Spyware/Botnet) and utm (Anti-Virus/Content
// Filter/App Control/Geo-IP/RBL), and Firewall Settings is `system` except
// Flood Protection, which is an attack.
const VENDOR_PAIRS = [
  ['Firewall', 'Access Rules', 'traffic', [440, 441, 442, 646, 647, 734, 735]],
  ['Firewall', 'Application Firewall', 'traffic', [793, 1654]],
  ['Firewall Settings', 'Advanced', 'system', [428, 1473, 1573, 1576, 1590]],
  ['Firewall Settings', 'Checksum Enforcement', 'system', [883, 884, 885, 886, 1448, 1449]],
  ['Firewall Settings', 'FTP', 'system', [446, 527, 528, 538]],
  ['Firewall Settings', 'Flood Protection', 'threat', [25, 856, 857, 858, 859, 860, 862, 863, 864, 897, 898, 901, 904, 905, 1180, 1213, 1214, 1366, 1369, 1450, 1451, 1452]],
  ['Firewall Settings', 'Multicast', 'system', [683, 690, 694, 1233]],
  ['Firewall Settings', 'SSL Control', 'system', [999, 1001, 1002, 1003, 1004, 1005, 1006, 1081]],
  ['High Availability', 'Cluster', 'system', [1149, 1152]],
  ['Log', 'Configuration Auditing', 'config', [1382, 1383, 1674]],
  ['Network', 'ARP', 'traffic', [45, 815, 1316]],
  ['Network', 'DNS', 'traffic', [1098, 1099]],
  ['Network', 'DNS Security', 'utm', [1593]],
  ['Network', 'ICMP', 'traffic', [38, 63, 175, 182, 188, 523, 597, 598, 1254, 1255, 1256, 1257, 1431, 1433, 1458]],
  ['Network', 'IP', 'traffic', [28, 522, 910, 1301, 1302, 1303, 1429, 1430]],
  ['Network', 'IPcomp', 'traffic', [651, 652, 653]],
  ['Network', 'IPv6 Tunneling', 'traffic', [1253]],
  ['Network', 'Interfaces', 'system', [58]],
  ['Network', 'NAT', 'traffic', [339, 1197, 1436]],
  ['Network', 'NAT Policy', 'traffic', [1313, 1314, 1315]],
  ['Network', 'Network Access', 'traffic', [41, 46, 98, 347, 524, 537, 590, 714, 1304]],
  ['Network', 'TCP', 'traffic', [36, 48, 173, 181, 580, 708, 709, 712, 713, 760, 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 1029, 1030, 1031, 1384, 1385, 1628, 1629]],
  ['Security Services', 'Anti-Spyware', 'threat', [794, 795, 796]],
  ['Security Services', 'Anti-Virus', 'utm', [123, 124, 125, 159, 408, 482]],
  ['Security Services', 'Application Control', 'utm', [1154, 1155]],
  ['Security Services', 'Attacks', 'threat', [22, 23, 27, 81, 82, 83, 177, 178, 179, 267, 606, 1373, 1374, 1375, 1376, 1387, 1471]],
  ['Security Services', 'Botnet Filter', 'threat', [1195, 1200, 1201, 1476, 1477, 1518, 1519]],
  ['Security Services', 'Content Filter', 'utm', [14, 16, 1599, 1600, 1601]],
  ['Security Services', 'Geo-IP Filter', 'utm', [1198, 1199, 1474, 1475]],
  ['Security Services', 'IDP', 'threat', [789, 790]],
  ['Security Services', 'IPS', 'threat', [608, 609]],
  ['Security Services', 'Next-Gen Anti-Virus', 'utm', [1559, 1560, 1561, 1562]],
  ['Security Services', 'RBL Filter', 'utm', [797, 798]],
  ['System', 'Administration', 'system', [340, 341]],
  ['System', 'Cloud Backup', 'system', [1511, 1512, 1513, 1514, 1515, 1516]],
  ['System', 'Restart', 'system', [93, 94, 95, 164, 599, 600, 601, 1046, 1047, 1392, 1393]],
  ['System', 'Settings', 'system', [573, 574, 1049, 1065, 1066, 1160, 1161, 1268, 1269, 1336, 1337, 1338, 1339, 1340, 1432, 1494, 1520, 1521, 1565, 1566, 1567, 1568, 1636, 1637]],
  ['System', 'Status', 'system', [4, 53, 521, 1107, 1196, 1332, 1495, 1496]],
  ['Users', 'Authentication Access', 'event', [24, 29, 30, 31, 32, 33, 34, 35, 199, 200, 235, 236, 237, 238, 246, 261, 262, 263, 264, 265, 328, 329, 438, 439, 486, 506, 507, 508, 509, 520, 549, 550, 551, 557, 558, 559, 560, 561, 562, 564, 583, 728, 729, 759, 986, 987, 994, 995, 996, 997, 998, 1008, 1035, 1048, 1080, 1117, 1118, 1119, 1120, 1121, 1122, 1123, 1124, 1157, 1158, 1243, 1333, 1334, 1335, 1341, 1342, 1517, 1570, 1571, 1572, 1585, 1627, 1655, 1672]],
  ['Users', 'Radius Authentication', 'event', [243, 244, 245, 744, 745, 746, 747, 748, 749, 750, 751, 753, 754, 755, 756, 757, 1011]],
  ['Users', 'SSO Agent Authentication', 'event', [988, 989, 990, 991]],
  ['VPN', 'DHCP Relay', 'vpn', [229]],
  ['Wireless', 'RF Monitoring', 'system', [879]],
  ['Wireless', 'WLAN', 'system', [1363]],
  ['Wireless', 'WLAN IDS', 'threat', [546, 548]],];

// ⛔ DERIVED FROM MESSAGE TEXT, NOT FROM THE VENDOR TABLE. Each is an id a real
// appliance emitted that SonicWall's published reference does not list. The
// comment is the observed `msg=`/`note=` the class was read from, so the
// evidence travels with the claim.
//
// ⛔ THE FIRST TWO ARE THE HIGH-VOLUME ONES AND SO THE MOST IMPORTANT TO CONFIRM
// AGAINST A LIVE DEVICE: m=526 is 26 of 220 corpus lines and m=97 is 6. A wrong
// class here misfiles an eighth of that device's events.
//
// ⛔ m=713 IS DELIBERATELY ABSENT FROM THIS LIST although it is the single most
// common id in the corpus (53 lines). It IS in the vendor table
// (Network / TCP -> traffic), and a derived entry for it would have been dead
// code that misreported a vendor-stated class as one we read off a string.
// `classOf` would never have returned it — which is exactly why it had to be
// removed rather than left as a harmless duplicate.
const DERIVED = [
  [526, 'event', 'Web management request allowed'],   // management plane, NOT traffic
  [97, 'utm', 'Web site hit'],                        // content filtering, carries Category=
  [1235, 'traffic', 'stack traffic always trusted'],
  [307, 'system', 'The network connection in use is NAT Static IP'],
  [326, 'system', 'Probing failure on NAT Static IP'],
  [436, 'system', 'Probing succeeded on NAT Static IP'],
  [435, 'system', 'WLB Failback initiated by preemption'],
  [584, 'system', 'WLB Failover in progress'],
  [585, 'system', 'WLB Resource is now available'],
  [586, 'system', 'WLB Resource failed'],
  [1220, 'system', 'Invalid SNMP packet'],
  [1230, 'system', 'Failed on updating time from NTP server'],
  [1231, 'system', 'Time update from NTP server was successful'],
  [1232, 'system', 'NTP Request sent'],
  [346, 'vpn', 'IKE Initiator: Start Quick Mode (Phase 2)'],
  [483, 'vpn', 'Received notify: INVALID_ID_INFO'],
  [1388, 'vpn', 'IPSec VPN Decryption Failed'],
  [866, 'threat', 'Possible SYN Flood continues'],
  [867, 'threat', 'Possible SYN Flood has ceased'],
  [1370, 'threat', 'Possible TCP Flood has ceased'],
  [1371, 'threat', 'Possible TCP Flood continues'],
];

const BY_ID = new Map();
for (const [group, subcategory, logClass, ids] of VENDOR_PAIRS) {
  for (const id of ids) BY_ID.set(String(id), { group, subcategory, logClass, source: 'vendor' });
}
for (const [id, logClass, note] of DERIVED) {
  // ⛔ A vendor entry is never overwritten by a derived one. If SonicWall's
  // table and a message string disagree, the vendor wins — the derived tier
  // exists only to cover ids the vendor table omits.
  if (!BY_ID.has(String(id))) {
    BY_ID.set(String(id), { group: null, subcategory: null, logClass, source: 'derived', note });
  }
}

// ⛔ `gcat=` IS THE SECOND SOURCE AND IT IS COARSER THAN THE ID. It names the
// GROUP only (SonicWall's own 21-value list), so it can resolve a class only
// where that group maps to exactly ONE class. Where it does not, this map omits
// it deliberately and the caller refuses rather than guessing.
//
// ⛔ THE THREE OMISSIONS ARE THE POINT, and two were measured rather than
// assumed:
//   3 Security Services — splits threat/utm with no majority (31 vs 23 ids).
//   5 Firewall Settings — `system` except Flood Protection, which is `threat`.
//   2 Log — every CATALOGUED Log id is Configuration Auditing (`config`), yet
//     gcat=2 is observed on 5 `m=97` WEB SITE HIT lines. The group's content and
//     its observed use disagree, so mapping it to `config` would file web
//     browsing as configuration changes. Refusing is the honest answer.
const GCAT_CLASS = new Map([
  ['1', 'system'],   // System
  ['4', 'event'],    // Users
  ['6', 'traffic'],  // Network
  ['7', 'vpn'],      // VPN
  ['8', 'system'],   // High Availability
  ['10', 'traffic'], // Firewall
  ['13', 'vpn'],     // SSL VPN
  ['20', 'vpn'],     // WireGuard
]);

// The full 21-value gcat vocabulary, for `fields` and for a reader checking
// which ids above were deliberately left unmapped.
const GCAT_GROUP = new Map(Object.entries({
  1: 'System', 2: 'Log', 3: 'Security Services', 4: 'Users', 5: 'Firewall Settings',
  6: 'Network', 7: 'VPN', 8: 'High Availability', 9: 'WWAN Modem', 10: 'Firewall',
  11: 'Wireless', 12: 'VoIP', 13: 'SSL VPN', 14: 'Anti-Spam', 15: 'WAN Acceleration',
  16: 'Object', 17: 'SD-WAN', 18: 'Multi-Instance', 19: 'Unified Policy Engine',
  20: 'WireGuard', 21: 'Cloud Secure Edge',
}));

/**
 * Resolve an event's class from `m=`, falling back to `gcat=`.
 *
 * ⛔ RETURNS THE SOURCE, ALWAYS. A caller — and a test — must be able to tell a
 * vendor-stated class from one read off a message string from one inferred from
 * a coarse group. Collapsing them to a bare string is how a derived guess ends
 * up quoted as a vendor fact.
 *
 * @returns {{logClass: string|null, logSubtype: string|null, group: string|null,
 *            source: 'vendor'|'derived'|'gcat'|null}}
 */
function classOf(m, gcat) {
  const hit = m === null || m === undefined ? undefined : BY_ID.get(String(m));
  if (hit) {
    return {
      logClass: hit.logClass,
      logSubtype: hit.subcategory,
      group: hit.group,
      source: hit.source,
    };
  }
  const g = gcat === null || gcat === undefined ? null : String(gcat);
  const viaGcat = g === null ? undefined : GCAT_CLASS.get(g);
  if (viaGcat) {
    // ⛔ No logSubtype from this path. `gcat` names a group, and inventing a
    // subcategory from it would put a value in that column that the device
    // never stated.
    return { logClass: viaGcat, logSubtype: null, group: GCAT_GROUP.get(g) || null, source: 'gcat' };
  }
  // ⛔ REFUSE. There is no 'other' bucket: an unclassified event is a gap in
  // this table and must look like one.
  return {
    logClass: null,
    logSubtype: null,
    group: g !== null ? GCAT_GROUP.get(g) || null : null,
    source: null,
  };
}

module.exports = { VENDOR_PAIRS, DERIVED, BY_ID, GCAT_CLASS, GCAT_GROUP, classOf };
