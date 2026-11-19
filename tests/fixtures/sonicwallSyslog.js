// tests/fixtures/sonicwallSyslog.js
//
// VERBATIM lines from Elastic's own SonicWall integration test corpus
// (`packages/sonicwall_firewall/data_stream/log/_dev/test/pipeline`), unedited.
//
// ⛔ THIRD-PARTY AND ANONYMISED — NOT our capture, and no SonicWall device has
// ever been connected to SecVault. That is the one place this vendor differs
// from Fortinet, Palo Alto, Cisco ASA and Sophos, every one of which was read
// off a live appliance. What 220 real lines DO settle is syntax, and strongly:
// our address splitter and Elastic's independent implementation agree on all
// **1,724 address facets across these 220 events, with zero mismatches**.
//
// ⛔ THE ANONYMISATION IS ITSELF LOAD-BEARING IN THREE PLACES, so do not
// "clean up" what looks wrong:
//   - `id=YYYYYY` on 3 lines where every other line says `id=firewall`. A
//     detector that validated that VALUE would reject real lines.
//   - `sn=` replaced with `000SERIAL`, `XXXX`, `123456789` and others. Any
//     length or charset rule built from these would be built from redactions.
//   - `msg="\uFFFD"` on all 53 `m=713` lines — a literal U+FFFD, the signature
//     of a decode/re-encode round trip. So `msg=` must not be assumed valid
//     UTF-8, and m=713's message text is simply UNKNOWN.
//
// ⛔ Three values are Elastic's SYNTHETIC BAD-VALUE TESTS, not device output:
// `op="testing bad value"`, `natSrcV6=not_an_IP`, `natDstV6=not_an_IP`. They
// prove Elastic's intended failure behaviour; they are not evidence about SonicOS.
//
// ⛔ DO NOT HAND-EDIT A LINE TO MAKE A TEST PASS. A disagreement between the
// code and these bytes is the code being wrong about a real device.
//
// 220 lines | 44 message ids | 55 keys | 431 compound-address occurrences.
// Full analysis: secvault-lab/findings/SONICWALL-SYSLOG.md

'use strict';

// ---------------------------------------------------------------------------
// test-drizzthacker.log — 32 lines
// ---------------------------------------------------------------------------
const DRIZZTHACKER = [
  // m=98
  "Apr 29 10:04:36 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-29 10:05:12\" fw=172.16.0.2 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=15243934 src=172.16.2.2:4522:X0 dst=81.2.69.143:443:X1 proto=tcp/https sent=60",
  // m=537
  "Apr 29 10:05:16 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-29 10:05:52\" fw=172.16.0.2 pri=6 c=1024 m=537 msg=\"Connection Closed\" app=11 n=15348774 src=172.16.2.2:64159:X0 dst=1.128.3.4:443:X1 srcMac=00:53:a5:10:44:b8 dstMac=00:53:2a:7d:1d:35 proto=tcp/https sent=4941 rcvd=7294 spkt=16 rpkt=13 cdur=112650",
  // m=97
  "Apr 27 10:01:58 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:02:30\" fw=172.16.0.2 pri=6 c=1024 m=97 app=9 n=558417 src=172.16.2.2:60102:X0 dst=89.160.20.156:80:X1 srcMac=00:53:a5:10:44:b8 dstMac=00:53:2a:7d:1d:35 proto=tcp/http op=1 sent=403 rcvd=719 dstname=www.sampledomain.es arg=/index.php?pingto=www.nessus.org%20|%20dir code=64 Category=\"Not Rated\"",
  // m=1220
  "Apr 27 10:05:02 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:05:34\" fw=172.16.0.2 pri=4 c=0 m=1220 msg=\"Invalid SNMP packet\" n=109062 src=172.16.2.2:36322 dst=172.16.2.1:161 note=\"Invalid engineID: 0\"",
  // m=994
  "Apr 27 10:23:51 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:24:23\" fw=172.16.0.2 pri=6 c=16 m=994 msg=\"Configuration mode administration session started\" sess=\"Web\" n=11 usr=\"admin\" src=172.16.2.2::X0 dst=172.16.2.1:4444:X0 proto=tcp/4444 note=\"admin at GUI from 172.16.2.2\"",
  // m=83
  "Apr 27 11:02:40 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 11:03:13\" fw=172.16.0.2 pri=1 c=32 m=83 msg=\"Probable port scan detected\" n=7652 src=89.160.20.156:443:X1 dst=172.16.0.2:45071:X1 srcMac=00:53:2a:7d:1d:35 dstMac=00:53:c5:ca:be:01 proto=tcp/45071 note=\"TCP scanned port list, 20566, 41385, 14480, 57223, 53623, 36878, 10199, 31096, 4738, 45071\"",
  // m=82
  "Apr 27 10:41:01 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:41:33\" fw=172.16.0.2 pri=1 c=32 m=82 msg=\"Possible port scan detected\" n=15066 src=89.160.20.156:443:X1 dst=172.16.0.2:35878:X1 srcMac=00:53:2a:7d:1d:35 dstMac=00:53:c5:ca:be:01 proto=tcp/35878 note=\"TCP scanned port list, 33159, 33981, 8161, 51557, 7847\"",
  // m=866
  "Apr 27 10:26:18 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:26:50\" fw=172.16.1.1 pri=4 c=32 m=866 msg=\"Possible SYN Flood on IF X0 - src: 172.16.2.2:42668 dst: 67.43.156.12:10617 - rate: 465/sec continues\" sess=\"Web\" n=7342 usr=\"admin\" src=172.16.2.2:42668:X0 dst=67.43.156.12:10617 srcMac=00:53:a5:10:44:b8 dstMac=00:53:c5:ca:be:00 proto=tcp/10617",
  // m=867
  "Apr 27 10:26:17 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:26:49\" fw=172.16.1.1 pri=1 c=32 m=867 msg=\"Possible SYN Flood on IF X0 - from machine xx:xx:a5:10:44:b8 with SYN rate of 173/sec has ceased\" sess=\"Web\" n=2158 usr=\"admin\" src=172.16.2.2:64983:X0 dst=81.2.69.144:80 srcMac=00:53:a5:10:44:b8 dstMac=00:53:c5:ca:be:00 proto=tcp/http",
  // m=53
  "Apr 27 10:23:10 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:23:41\" fw=172.16.0.2 pri=3 c=2 m=53 msg=\"The cache is full; %u open connections; some will be dropped32000 cacheCurrentInUse, 0 freed from pendingFreeList (Total 12)\" n=4094019 src=172.16.2.2:58636:X0 dst=67.43.156.13:56432:X1 srcMac=00:53:a5:10:44:b8 dstMac=00:53:c5:ca:be:00 proto=tcp/56432",
  // m=860
  "Apr 27 10:21:42 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:22:14\" fw=172.16.0.2 pri=1 c=32 m=860 msg=\"Possible SYN Flood on IF X0 - src: 172.16.2.2:60062 dst: 67.43.156.14:22402\" n=2152 src=172.16.2.2:60062:X0 dst=67.43.156.14:22402 srcMac=00:53:a5:10:44:b8 dstMac=00:53:c5:ca:be:00 proto=tcp/22402",
  // m=1231
  "Apr 27 21:37:24 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 21:37:57\" fw=172.16.0.2 pri=5 c=128 m=1231 msg=\"Time update from NTP server was successful\" n=458 src=172.16.0.2:123:X0 dst=67.43.156.15:123:X1 note=\"Received reply from NTP server 67.43.156.15. Update system time from 04/27/2022 21:37:56.416 to 04/27/2022 21:37:57.528\"",
  // m=326
  "Apr 27 23:03:37 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 23:04:10\" fw=172.16.1.1 pri=1 c=2 m=326 msg=\"Probing failure on NAT Static IP\" n=86 src=172.16.0.2::X1 dst=81.2.69.193:0:X1",
  // m=1232
  "Apr 27 11:34:04 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 11:34:36\" fw=172.16.0.2 pri=5 c=128 m=1232 msg=\"NTP Request sent\" n=455 src=172.16.0.2:123:X0 dst=67.43.156.15:123:X1 note=\"Send request to NTP server 67.43.156.15\"",
  // m=586
  "Apr 27 10:24:05 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:24:35\" fw=172.16.1.1 pri=1 c=2 m=586 msg=\"WLB Resource failed\" n=40 src=172.16.0.2::X1",
  // m=307
  "Apr 27 10:24:05 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:24:35\" fw=172.16.1.1 pri=4 c=2 m=307 msg=\"The network connection in use is NAT Static IP\" n=79 src=172.16.1.1::X5",
  // m=584
  "Apr 27 10:24:05 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:24:35\" fw=172.16.1.1 pri=1 c=2 m=584 msg=\"WLB Failover in progress\" n=41 src=172.16.0.2::X1 dst=172.16.1.1::X5",
  // m=1371
  "Apr 28 06:38:17 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-28 06:38:51\" fw=172.16.0.2 pri=4 c=32 m=1371 msg=\"Possible TCP Flood on IF X1 - src: 82.98.136.100:80 dst: 172.16.0.2:15912 - rate: 1869/sec continues\" n=151",
  // m=1370
  "Apr 28 06:37:25 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-28 06:37:59\" fw=172.16.0.2 pri=1 c=32 m=1370 msg=\"Possible TCP Flood on IF X1 - from machine xx:xx:2a:7d:1d:35 with TCP packet rate of 3/sec has ceased\" n=60 src=81.2.69.145:443:X1 dst=172.16.0.2:37462:X1 srcMac=00:53:2a:7d:1d:35 dstMac=00:53:c5:ca:be:01 proto=tcp/37462",
  // m=1369
  "Apr 28 06:36:54 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-28 06:37:28\" fw=172.16.0.2 pri=1 c=32 m=1369 msg=\"Possible TCP Flood on IF X1 - src: 81.2.69.145:443 dst: 172.16.0.2:12137\" n=58 src=81.2.69.145:443:X1 dst=172.16.0.2:12137:X1 srcMac=00:53:2a:7d:1d:35 dstMac=00:53:c5:ca:be:01 proto=tcp/12137",
  // m=177
  "Apr 28 06:36:28 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-28 06:37:02\" fw=172.16.0.2 pri=1 c=32 m=177 msg=\"Probable TCP FIN scan detected\" n=70 src=81.2.69.145:80:X1 dst=172.16.0.2:61017:X1 srcMac=00:53:2a:7d:1d:35 dstMac=00:53:c5:ca:be:01 proto=tcp/61017 note=\"TCP scanned port list, 42998, 30957, 8099, 65027, 42142, 35538, 13062, 40855, 35544, 61017\"",
  // m=436
  "Apr 27 23:03:52 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 23:04:26\" fw=172.16.0.2 pri=1 c=2 m=436 msg=\"Probing succeeded on NAT Static IP\" n=47 src=172.16.0.2::X1 dst=89.160.20.112:0:X1",
  // m=585
  "Apr 27 23:03:52 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 23:04:26\" fw=172.16.0.2 pri=1 c=2 m=585 msg=\"WLB Resource is now available\" n=44 src=172.16.0.2::X1",
  // m=267
  "Apr 27 19:29:07 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 19:29:40\" fw=172.16.0.2 pri=1 c=32 m=267 msg=\"TCP Xmas Tree dropped\" n=56 src=175.16.199.1:16345:X1 dst=172.16.0.2:81 srcMac=00:53:2a:7d:1d:35 dstMac=00:53:c5:ca:be:01 proto=tcp/81",
  // m=998
  "Apr 27 10:32:18 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:32:51\" fw=172.16.0.2 pri=6 c=16 m=998 msg=\"GUI administration session ended\" sess=\"Web\" dur=510 n=11 usr=\"admin\" src=172.16.2.2::X0 dst=172.16.2.1:4444:X0 proto=tcp/4444 note=\"admin\"",
  // m=995
  "Apr 27 10:32:18 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:32:51\" fw=172.16.0.2 pri=6 c=16 m=995 msg=\"Configuration mode administration session ended\" n=11 src=172.16.2.2::X0 dst=172.16.2.1:4444:X0 proto=tcp/4444 note=\"admin at GUI from 172.16.2.2\"",
  // m=29
  "Apr 27 10:23:51 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:24:23\" fw=172.16.0.2 pri=6 c=16 m=29 msg=\"Administrator login allowed\" sess=\"Web\" n=11 usr=\"admin\" src=172.16.2.2::X0 dst=172.16.2.1:4444:X0 proto=tcp/4444",
  // m=262
  "Apr 27 10:32:18 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 10:32:51\" fw=172.16.0.2 pri=6 c=16 m=262 msg=\"Administrator logged out - inactivity timer expired\" sess=\"Web\" dur=510 n=11 usr=\"admin\" src=172.16.2.2::X0 dst=172.16.2.1:4444:X0",
  // m=435
  "Apr 27 23:03:52 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 23:04:26\" fw=172.16.0.2 pri=1 c=2 m=435 msg=\"WLB Failback initiated by preemption due to a more preferred interface being operational\" n=40 src=172.16.1.1::X5 dst=172.16.0.2::X1",
  // m=1107
  "Apr 29 03:46:20 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-29 03:46:56\" fw=172.16.0.2 pri=1 c=2 m=1107 msg=\"Response from NTP Server is either incomplete or invalid\" n=8",
  // m=1230
  "Apr 29 03:46:20 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-29 03:46:56\" fw=172.16.0.2 pri=5 c=128 m=1230 msg=\"Failed on updating time from NTP server\" n=8 src=172.16.0.2:123:X0 dst=67.43.156.15:123:X1 note=\"invalid NTP server 67.43.156.15\"",
  // m=30
  "Apr 27 09:42:51 172.16.2.1 id=firewall sn=0000A0AAAA00 time=\"2022-04-27 09:42:51\" fw=172.16.0.2 pri=1 c=32 m=30 msg=\"Administrator login denied due to bad credentials\" sess=\"Web\" n=1 usr=\"admin\" src=172.16.2.2:17391:X0 dst=172.16.2.1:4444:X0 proto=tcp/4444",
];

// ---------------------------------------------------------------------------
// test-general.log — 38 lines
// ---------------------------------------------------------------------------
const GENERAL = [
  // m=98
  "Jan  3 13:45:36 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:06\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23419 src=216.160.83.57:36701:WAN dst=1.128.3.4:50000:WAN proto=tcp/50000",
  // m=30
  "Jan  3 13:45:36 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:07\" fw=1.128.3.4 pri=1 c=32 m=30 msg=\"Administrator login denied due to bad credentials\" n=7 src=216.160.83.57:36701:WAN dst=1.128.3.4:50000:WAN",
  // m=98
  "Jan  3 13:45:36 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:07\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23420 src=216.160.83.57:36702:WAN dst=1.128.3.4:50000:WAN proto=tcp/50000",
  // m=537
  "Jan  3 13:45:37 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:07\" fw=1.128.3.4 pri=6 c=1024 m=537 msg=\"Connection Closed\" n=567996 src=192.168.4.10:27577:WAN dst=192.168.5.10:53:LAN proto=tcp/dns sent=257 rcvd=242",
  // m=537
  "Jan  3 13:45:37 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:08\" fw=1.128.3.4 pri=6 c=1024 m=537 msg=\"Connection Closed\" n=567997 src=192.168.5.56:4277:LAN dst=192.168.1.100:1026:WAN proto=tcp/1026 sent=3590 rcvd=13042 vpnpolicy=\"name\"",
  // m=537
  "Jan  3 13:45:39 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:10\" fw=1.128.3.4 pri=6 c=1024 m=537 msg=\"Connection Closed\" n=567999 src=192.168.5.56:4280:LAN dst=192.168.2.81:41850:WAN proto=tcp/41850 sent=386026 rcvd=454118 vpnpolicy=\"name\"",
  // m=537
  "Jan  3 13:45:39 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:10\" fw=1.128.3.4 pri=6 c=1024 m=537 msg=\"Connection Closed\" n=567999 src=1.128.3.4:500:WAN dst=216.160.83.57:500:WAN proto=udp/500 sent=344 rcvd=152",
  // m=98
  "Jan  3 13:45:40 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:10\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23421 src=216.160.83.57:36703:WAN dst=1.128.3.4:50000:WAN proto=tcp/50000",
  // m=30
  "Jan  3 13:45:40 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:10\" fw=1.128.3.4 pri=1 c=32 m=30 msg=\"Administrator login denied due to bad credentials\" n=8 src=216.160.83.57:36703:WAN dst=1.128.3.4:50000:WAN",
  // m=98
  "Jan  3 13:45:40 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:11\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23422 src=216.160.83.57:36704:WAN dst=1.128.3.4:50000:WAN proto=tcp/50000",
  // m=38
  "Jan  3 13:45:43 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:14\" fw=1.128.3.4 pri=5 c=256 m=38 msg=\"ICMP packet dropped\" n=22070 src=89.160.20.112:1026:WAN dst=1.128.3.4:6822:WAN  type=3 code=3",
  // m=537
  "Jan  3 13:45:43 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:14\" fw=1.128.3.4 pri=6 c=1024 m=537 msg=\"Connection Closed\" n=568000 src=89.160.20.112:1026:WAN dst=1.128.3.4:0:WAN proto=udp/0",
  // m=346
  "Jan  3 13:45:44 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:15\" fw=1.128.3.4 pri=6 c=16 m=346 msg=\"IKE Initiator: Start Quick Mode (Phase 2).\" n=171872 src=216.160.83.57:500 dst=1.128.3.4:500",
  // m=98
  "Jan  3 13:45:44 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:15\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23423 src=1.128.3.4:500:WAN dst=216.160.83.57:500:WAN proto=udp/500",
  // m=483
  "Jan  3 13:45:44 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:15\" fw=1.128.3.4 pri=4 c=16 m=483 msg=\"Received notify: INVALID_ID_INFO\" n=171625 src=216.160.83.57:500 dst=1.128.3.4:500",
  // m=98
  "Jan  3 13:45:45 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:15\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23424 src=192.168.115.10:11549:WAN dst=192.168.5.10:53:LAN proto=tcp/dns",
  // m=98
  "Jan  3 13:45:46 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:17\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23425 src=192.168.5.64:3182:LAN dst=192.168.1.100:445:WAN proto=tcp/445",
  // m=537
  "Jan  3 13:45:47 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:18\" fw=1.128.3.4 pri=6 c=1024 m=537 msg=\"Connection Closed\" n=568001 src=216.160.83.57:36699:WAN dst=1.128.3.4:50000:WAN proto=tcp/50000 sent=1557 rcvd=957",
  // m=537
  "Jan  3 13:45:49 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:20\" fw=1.128.3.4 pri=6 c=1024 m=537 msg=\"Connection Closed\" n=568002 src=192.168.5.10:3417:LAN dst=192.168.1.100:53:WAN proto=udp/dns sent=401 rcvd=254 rpkt=3 spkt=2 vpnpolicy=\"name\"",
  // m=98
  "Jan  3 13:45:50 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:20\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23426 src=192.168.125.75:524:WAN dst=192.168.5.10:3582:LAN proto=udp/3582",
  // m=98
  "Jan  3 13:45:50 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:21\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23427 src=192.168.6.10:28503 dst=192.168.5.10 proto=tcp/dns",
  // m=98
  "Jan  3 13:45:51 192.168.5.1 id=firewall sn=000SERIAL time=\"2007-01-03 14:48:22\" fw=1.128.3.4 pri=6 c=262144 m=98 msg=\"Connection Opened\" n=23427 src=:28503:WAN:SOURCEHOST srcV6=2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6 dst=::LAN:DSTHOST proto=tcp/dns dstV6=::1",
  // m=-
  "id=firewall sn=XXXXXXX time=\"2015-11-21 14:30:38\" fw=10.0.0.1 pri=5 msg=\"Unhandled link-local or multicast IPv6 packet dropped\" srcV6=fe80::d4db:99b9:6f20:f6bd dstV6=ff02::c srcMac=00:53:ff:ff:55:55 dstMac=00:53:00:00:00:0c proto=udp/65535",
  // m=1388
  "id=YYYYYY sn=XXXX time=\"2019-03-14 16:37:19 UTC\" fw=172.29.1.2 pri=1 c=32 m=1388 msg=\"IPSec VPN Decryption Failed\" n=1064050271 src=67.43.156.15 dst=81.2.69.193 note=\"Replay check failure.\"",
  // m=1197
  "id=YYYYYY  sn=XXXX time=\"2019-02-27 12:55:40 UTC\" fw=10.1.1.1 pri=5 c=0 m=1197 msg=\"NAT Mapping\" n=4748427 src=10.12.14.9::X500 dst=81.2.69.144::X3 proto=icmp note=\"Source: 2.228.169.242, 63130, Destination: 217.56.236.4, 8, Protocol: 1\" rule=\"17 (LAN->WAN)\"",
  // m=14
  "id=YYYYYY sn=XXXX time=\"2019-03-19 06:44:01 UTC\" fw=10.1.1.1 pri=3 c=4 m=14 msg=\"Web site access denied\" app=49177 appName=\"General HTTPS\" n=856789 src=192.168.0.46:59668:X0:nb020.example.com dst=175.16.199.1:443:X1:example.com srcMac=00:53:ff:ff:99:c5 dstMac=00:53:66:66:99:99 proto=tcp/https dstname=example.com arg=/ code=49 Category=\"Freeware/Software Downloads\"",
  // m=98 fw_action=NA
  "10.0.0.1 id=firewall sn=123456789 time=\"2022-02-22 18:24:30 UTC\" fw=10.0.0.2 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=10.0.0.3:52379:X0 natSrc=10.0.0.2:48245 dst=216.160.83.61:443:X1 natDst=216.160.83.61:443 usr=\"Unknown (SSO failed)\" proto=tcp/https sent=52 app=49177 appName='General HTTPS' n=123456789 fw_action=\"NA\" dpi=0",
  // m=97 fw_action=NA
  "10.0.0.1 id=firewall sn=123456789 time=\"2022-02-22 18:29:37 UTC\" fw=10.0.0.2 pri=6 c=1024 gcat=2 m=97 msg=\"Web site hit\" srcMac=12:34:56:78:90:ab src=10.0.0.3:64828:X0 srcZone=Trusted natSrc=10.0.0.2:47621 dstMac=ab:09:87:65:43:21 dst=216.160.83.61:443:X1 dstZone=Untrusted natDst=216.160.83.61:443 usr=\"Unknown (SSO failed)\" proto=tcp/https sent=3523 rcvd=14226 app=7927 dstname=chat-pa.clients6.google.com arg=/ code=29 Category=\"Search Engines and Portals\" note=\"Policy: cfsZonePolicy0, Info: 6148 \" n=123456789 fw_action=\"NA\" dpi=1",
  // m=97 fw_action=NA
  "10.0.0.1 id=firewall sn=12345678 time=\"2022-02-22 18:34:21 UTC\" fw=10.0.0.2 pri=6 c=1024 gcat=2 m=97 msg=\"Web site hit\" srcMac=12:34:56:78:90:ab src=10.0.0.3:49217:X0 srcZone=Trusted natSrc=10.0.0.2:53466 dstMac=ab:09:87:65:43:21 dst=216.160.83.61:443:X1 dstZone=Untrusted natDst=216.160.83.61:443 usr=\"Unknown (SSO failed)\" proto=tcp/https sent=2079 rcvd=6642 app=7927 dstname=seg.ad.gt arg=/ code=15 Category=\"Business and Economy\" note=\"Policy: cfsZonePolicy0, Info: 6148 \" n=123456789 fw_action=\"NA\" dpi=1 op=3",
  // m=97 fw_action=NA
  "10.0.0.1  id=firewall sn=12345678 time=\"2022-03-09 14:58:44 UTC\" fw=10.0.0.2 pri=6 c=1024 gcat=2 m=97 msg=\"Web site hit\" srcMac=12:34:56:78:90:ab src=10.0.0.3:56242:X0 srcZone=Trusted natSrc=10.0.0.2:18447 dstMac=ab:09:87:65:43:21 dst=67.43.156.13:443:X1 dstZone=Untrusted natDst=67.43.156.13:443 usr=\"Unknown (SSO failed)\" proto=tcp/https sent=1749 rcvd=968 app=7927 dstname=rcs-us-east-1.neoservice-aws.com arg=/ code=27 Category=\"Information Technology/Computers\" note=\"Policy: cfsZonePolicy0, Info: 6148 \" n=368203630 fw_action=\"NA\" dpi=1 op=\"testing bad value\"",
  // m=97 fw_action=NA
  "10.0.0.1  id=firewall sn=12345678 time=\"2022-03-09 05:29:32 UTC\" fw=10.0.0.2 pri=6 c=1024 gcat=2 m=97 msg=\"Web site hit\" srcMac=12:34:56:78:90:ab src=10.0.0.3:56502:X0 srcZone=Trusted natSrc=10.0.0.2:15926 dstMac=ab:09:87:65:43:21 dst=67.43.156.14:80:X1 dstZone=Untrusted natDst=67.43.156.14:80 usr=\"Unknown (SSO failed)\" proto=tcp/http sent=510 rcvd=955 app=5147 op=1 dstname=ocsp.digicert.com arg=/abcd code=27 Category=\"Information Technology/Computers\" note=\"Policy: cfsZonePolicy0, Info: 6147 \" n=367895985 fw_action=\"NA\" dpi=1",
  // m=537 fw_action=NA
  "10.0.0.1  id=firewall sn=12345678 time=\"2022-03-09 18:44:05 UTC\" fw=10.0.0.2 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" src=10.0.0.4:37153:X0 natSrc=10.0.0.2:12325 dst=89.160.20.112:8800:X1 natDst=89.160.20.112:8800 proto=udp/8800 sent=284 spkt=1 app=49202 appName='General UDP' n=1846613339 fw_action=\"NA\" dpi=0",
  // m=608 fw_action=NA
  "10.0.0.1  id=firewall sn=12345678 time=\"2022-03-09 18:57:05 UTC\" fw=10.0.0.2 pri=1 c=32 gcat=3 m=608 src=67.43.156.15:8:X1 dst=10.0.0.3:1850:X0 msg=\"IPS Detection Alert: ICMP Echo Reply, SID: 316, Priority: Low\" msg=\"IPS Detection Alert: ICMP Echo Reply\" sid=316 ipscat=\"ICMP Echo Reply\" ipspri=3  n=174072 fw_action=\"NA\"",
  // m=97 fw_action=NA
  "10.0.0.1 id=firewall sn=12345678 time=\"2022-03-11 14:17:52 UTC\" fw=10.0.0.2 pri=6 c=1024 gcat=2 m=97 srcMac=12:34:56:78:90:ab src=10.0.0.4:41856:X0 srcZone=Trusted natSrc=10.0.0.2:8689 dstMac=ab:09:87:65:43:21 dst=89.160.20.112:443:X1 dstZone=Untrusted natDst=89.160.20.112:443 usr=\"Unknown (SSO failed)\" proto=tcp/https sent=104 rcvd=230 rule=\"15 (LAN->WAN)\" app=5 af_polid=4 ipscat=N/A appcat=\"PROXY-ACCESS\" appid=2900 dstname=89.160.20.112 arg=/ code=64 Category=\"Not Rated\" note=\"Policy: cfsZonePolicy0, Info: 6148 \" n=2520325 fw_action=\"NA\" dpi=1 op=0",
  // m=609 fw_action=drop
  "<129> id=firewall sn=ZZZZZZZZZ time=\"2022-02-24 03:29:07\" fw=192.168.33.1 pri=1 c=32 m=609 msg=\"IPS Prevention Alert: WEB-ATTACKS Apache Log4j2 JNDI Log Messages Remote Code Execution\" sid=2307 ipscat=\"WEB-ATTACKS Apache Log4j2 JNDI Log Messages Remote Code Execution\" ipspri=2 n=8158 src=216.160.83.61:54192:X20-V60 dst=:8080:X20-V68 dstV6=2a02:cf40:add:4002:91f2:a9b2:e09a:6fc6 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=xxxxxxxxxxxxxxx time=\"2022-05-06 16:10:06\" fw=192.168.255.6 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=89.160.20.112:42082:X4-V1032 dst=67.43.156.12:4433:X4-V1032 proto=tcp/4433 sent=52 app=49330 appName='Service iMesh' n=3591578 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=xxxxxxxxxxxxxxx time=\"2022-05-06 16:10:06\" fw=192.168.255.6 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=1.128.3.4:26391:X4-V1032 dst=67.43.156.12:4433:X4-V1032 proto=tcp/4433 sent=52 app=49330 appName='Service iMesh' n=3591579 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=xxxxxxxxxxxxxxx time=\"2022-05-06 16:10:06\" fw=192.168.255.6 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" src=192.168.24.228:56783:X4-V1032 srcZone=TEST dstMac=00:53:12:34:56:78 dst=67.43.156.12:53:X6 dstZone=Trusted usr=\"TheUser\" proto=udp/dns sent=63 rcvd=115 spkt=1 rpkt=1 cdur=30016 sess=\"sslvpnc\" rule=\"157 (SSLVPN->SERVER)\" app=49169 appName='General DNS' n=54094499 fw_action=\"NA\" dpi=0",
];

// ---------------------------------------------------------------------------
// test-nat.log — 4 lines
// ---------------------------------------------------------------------------
const NAT = [
  // m=1235 fw_action=forward
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:21\" fw=10.0.0.96 pri=6 c=0 gcat=6 m=1235 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:54606:X1 srcZone=Untrusted natSrc=10.0.0.96 dstMac=00:17:c5:30:f9:d9 dst=169.254.169.254:80:X1 dstZone=Untrusted natDst=169.254.169.254 proto=tcp/http sent=52 app=9 msg=\"\" note=\"stack traffic always trusted\" n=153 fw_action=\"forward\"",
  // m=1235 fw_action=forward
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:21\" fw=10.0.0.96 pri=6 c=0 gcat=6 m=1235 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:54606:X1 srcZone=Untrusted natSrcV6=2a02:cf40::1 dstMac=00:17:c5:30:f9:d9 dst=169.254.169.254:80:X1 dstZone=Untrusted natDstV6=2a02:cf40::2 proto=tcp/http sent=52 app=9 msg=\"\" note=\"stack traffic always trusted\" n=153 fw_action=\"forward\"",
  // m=1235 fw_action=forward
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:21\" fw=10.0.0.96 pri=6 c=0 gcat=6 m=1235 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:54606:X1 srcZone=Untrusted natSrcV6=[2a02:cf40::1]:1234 dstMac=00:17:c5:30:f9:d9 dst=169.254.169.254:80:X1 dstZone=Untrusted natDstV6=[2a02:cf40::2]:5678 proto=tcp/http sent=52 app=9 msg=\"\" note=\"stack traffic always trusted\" n=153 fw_action=\"forward\"",
  // m=1235 fw_action=forward
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:21\" fw=10.0.0.96 pri=6 c=0 gcat=6 m=1235 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:54606:X1 srcZone=Untrusted natSrcV6=not_an_IP dstMac=00:17:c5:30:f9:d9 dst=169.254.169.254:80:X1 dstZone=Untrusted natDstV6=not_an_IP proto=tcp/http sent=52 app=9 msg=\"\" note=\"stack traffic always trusted\" n=153 fw_action=\"forward\"",
];

// ---------------------------------------------------------------------------
// test-sonicos70-aws.log — 146 lines
// ---------------------------------------------------------------------------
const SONICOS70_AWS = [
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 15:22:26 UTC\" fw=10.0.0.96 pri=6 c=1024 m=537 msg=\"Connection Closed\" app=12 sess=\"Web\" n=795 usr=\"admin\" src=81.2.69.193:65055:X1 dst=10.0.0.96:443:X1 srcMac=06:08:25:81:11:30 proto=tcp/https sent=1930 rcvd=1545 spkt=11 rpkt=7 dpi=0 cdur=2133 rule=\"Default Access Rule\" fw_action=\"NA\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 15:22:26 UTC\" fw=10.0.0.96 pri=6 c=1024 m=537 msg=\"Connection Closed\" app=12 sess=\"Web\" n=797 usr=\"admin\" src=81.2.69.193:65056:X1 dst=10.0.0.96:443:X1 srcMac=06:08:25:81:11:30 proto=tcp/https sent=2146 rcvd=1611 spkt=11 rpkt=9 dpi=0 cdur=2483 rule=\"Default Access Rule\" fw_action=\"NA\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 15:22:27 UTC\" fw=10.0.0.96 pri=6 c=1024 m=537 msg=\"Connection Closed\" app=12 sess=\"Web\" n=799 usr=\"admin\" src=81.2.69.193:65057:X1 dst=10.0.0.96:443:X1 srcMac=06:08:25:81:11:30 proto=tcp/https sent=1919 rcvd=1547 spkt=10 rpkt=7 dpi=0 cdur=2183 rule=\"Default Access Rule\" fw_action=\"NA\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 15:22:28 UTC\" fw=10.0.0.96 pri=6 c=262144 m=98 msg=\"Connection Opened\" app=12 sess=\"Web\" n=780 usr=\"admin\" src=81.2.69.193:65058:X1 dst=10.0.0.96:443:X1 proto=tcp/https sent=64 dpi=0 fw_action=\"NA\"",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 15:22:28 UTC\" fw=10.0.0.96 pri=5 c=16 m=526 msg=\"Web management request allowed\" app=12 sess=\"Web\" n=927 usr=\"admin\" src=81.2.69.193:65058:X1 dst=10.0.0.96:443:X1 srcMac=06:08:25:81:11:30 dstMac=06:6e:64:57:48:02 proto=tcp/https uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\" rule=\"15 (WAN->WAN)\" fw_action=\"mgmt\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:39\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64889:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=692 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:39\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64889:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=694 fw_action=\"drop\"",
  // m=1382 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:39\" fw=10.0.0.96 pri=6 c=16 gcat=2 m=1382 src=81.2.69.193:64889 dst=10.0.0.96:443:X1 usr=\"admin\" sess=\"API\" msg=\"Configuration succeeded:  'Logging Level' , changed from [WARNING], changed to [DEBUG]\" n=35 fw_action=\"NA\" auditId=34 tranxId=26 userMode=\"Full\" oldValue=\"WARNING\"",
  // m=1382 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:39\" fw=10.0.0.96 pri=6 c=16 gcat=2 m=1382 src=81.2.69.193:64889 dst=10.0.0.96:443:X1 usr=\"admin\" sess=\"API\" msg=\"Configuration succeeded:  'Alert Level' , changed from [ALERT], changed to [WARNING]\" n=37 fw_action=\"NA\" auditId=35 tranxId=27 userMode=\"Full\" oldValue=\"ALERT\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:41\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64888:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=2463 rcvd=1691 spkt=12 rpkt=10 cdur=2566 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=449 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:41\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64889:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1935 rcvd=1577 spkt=10 rpkt=8 cdur=2183 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=451 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:41\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=89.160.20.156:29675:X1 srcZone=Untrusted dst=10.0.0.96:22:X1 dstZone=Untrusted proto=tcp/22 sent=180 rcvd=416 spkt=3 rpkt=8 cdur=334100 rule=\"Default Access Rule\" app=42 n=453 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64890:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=460 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64890:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=639 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64891:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=462 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64891:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=641 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64892:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=464 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64892:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=643 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64891:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=696 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64891:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=698 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64890:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=700 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:42\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64890:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=702 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:43\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64892:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=704 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:43\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64892:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=706 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:44\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64893:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=466 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:44\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64893:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=645 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:44\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64891:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1871 rcvd=1378 spkt=10 rpkt=7 cdur=2366 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=455 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:44\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64890:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1915 rcvd=3526 spkt=11 rpkt=8 cdur=2366 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=457 fw_action=\"NA\" dpi=0",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:45\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64893:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=708 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:45\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64893:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=710 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:45\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64892:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1896 rcvd=1279 spkt=11 rpkt=8 cdur=3450 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=459 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:47\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64893:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=8740 rcvd=256305 spkt=159 rpkt=181 cdur=2766 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=461 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:47\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64894:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=468 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:47\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64894:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=647 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:47\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64894:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=712 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:47\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64894:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=714 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:47\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64895:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=470 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:47\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64895:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=649 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:47\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64895:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=716 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:47\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64895:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=718 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:49\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64894:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=3259 rcvd=16551 spkt=18 rpkt=18 cdur=2183 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=463 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:49\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64895:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1868 rcvd=1545 spkt=10 rpkt=7 cdur=2166 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=465 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:51\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=89.160.20.156:53022:X1 srcZone=Untrusted dst=10.0.0.96:22:X1 dstZone=Untrusted proto=tcp/22 sent=180 rcvd=416 spkt=3 rpkt=8 cdur=334050 rule=\"Default Access Rule\" app=42 n=467 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:52\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64896:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=472 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:52\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64896:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=651 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:52\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64897:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=474 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:52\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64897:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=653 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:52\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64896:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=720 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:52\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64896:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=722 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:52\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64897:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=724 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:52\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64897:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=726 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:53\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64898:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=476 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:53\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64898:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=655 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:54\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64898:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=728 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:54\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64898:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=730 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:54\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64899:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=478 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:54\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64899:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=657 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:54\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64896:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1931 rcvd=3588 spkt=11 rpkt=9 cdur=2133 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=469 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:54\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64897:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1887 rcvd=1394 spkt=10 rpkt=7 cdur=2133 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=471 fw_action=\"NA\" dpi=0",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:55\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64899:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=732 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:55\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64899:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=734 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:56\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64898:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1866 rcvd=1301 spkt=10 rpkt=8 cdur=2116 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=473 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:18:57\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64899:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=8392 rcvd=253313 spkt=152 rpkt=179 cdur=2916 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=475 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64901:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=480 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64901:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=659 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64901:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=736 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64901:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=738 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64902:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=482 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64902:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=661 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64903:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=484 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64903:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=663 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64903:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=740 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64903:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=742 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64902:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=744 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:02\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64902:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=746 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:04\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64904:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=486 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:04\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64904:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=665 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:04\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64904:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=748 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:04\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64904:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=750 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:04\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64905:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=488 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:04\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64905:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=667 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:04\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64901:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=3243 rcvd=16551 spkt=18 rpkt=18 cdur=2216 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=477 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:04\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64903:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1871 rcvd=1394 spkt=10 rpkt=7 cdur=2133 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=479 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:04\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64902:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1915 rcvd=3526 spkt=11 rpkt=8 cdur=2133 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=481 fw_action=\"NA\" dpi=0",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:05\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64905:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=752 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:05\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64905:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=754 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:06\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64904:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1866 rcvd=1255 spkt=10 rpkt=7 cdur=2166 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=483 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:07\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.145:43466:X1 dst=10.0.0.96:443:X1 proto=tcp/https sent=60 app=12 n=490 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:07\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.145:43466:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted proto=tcp/https rcvd=60 rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=669 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:07\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64905:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=8438 rcvd=253369 spkt=153 rpkt=180 cdur=3283 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=485 fw_action=\"NA\" dpi=0",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:08\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=06:08:25:81:11:30 src=81.2.69.145:43466:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted proto=tcp/https rcvd=46 rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=756 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:08\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=06:08:25:81:11:30 src=81.2.69.145:43466:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted proto=tcp/https rcvd=46 rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=758 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:08\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=06:08:25:81:11:30 src=81.2.69.145:43466:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted proto=tcp/https rcvd=46 rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=760 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:10\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.145:43466:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted proto=tcp/https sent=1172 rcvd=2121 spkt=11 rpkt=8 cdur=3050 rule=\"Default Access Rule\" app=12 n=487 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:12\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64906:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=492 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:12\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64906:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=671 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:12\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64907:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=494 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:12\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64907:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=673 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:13\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64906:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=762 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:13\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64906:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=764 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:13\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64907:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=766 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:13\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64907:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=768 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:14\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64908:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=496 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:14\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64908:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=675 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:14\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64908:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=770 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:14\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64908:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=772 fw_action=\"drop\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:14\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64909:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=498 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:14\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64909:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=677 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:15\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64906:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1885 rcvd=3542 spkt=10 rpkt=8 cdur=2166 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=489 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:15\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64907:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1887 rcvd=1378 spkt=10 rpkt=7 cdur=2166 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=491 fw_action=\"NA\" dpi=0",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:15\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64909:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=774 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:15\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64909:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=776 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:16\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64908:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1850 rcvd=1301 spkt=10 rpkt=8 cdur=2166 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=493 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:16\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=89.160.20.156:43808:X1 srcZone=Untrusted dst=10.0.0.96:22:X1 dstZone=Untrusted proto=tcp/22 sent=180 rcvd=416 spkt=3 rpkt=8 cdur=334116 rule=\"Default Access Rule\" app=42 n=495 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:17\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64909:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=8438 rcvd=253354 spkt=153 rpkt=180 cdur=3266 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=497 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:17\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64910:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=500 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:17\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64910:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=679 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:17\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64910:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=778 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:17\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64910:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=780 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:19\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64910:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=3243 rcvd=16567 spkt=18 rpkt=18 cdur=2183 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=499 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:21\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=10.0.0.96:54604:X1 natSrc=10.0.0.96:41479 dst=169.254.169.254:80:X1 natDst=169.254.169.254:80 proto=tcp/http sent=52 app=9 n=502 fw_action=\"NA\" dpi=0",
  // m=1235 fw_action=forward
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:21\" fw=10.0.0.96 pri=6 c=0 gcat=6 m=1235 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:54604:X1 srcZone=Untrusted natSrc=10.0.0.96:41479 dstMac=00:17:c5:30:f9:d9 dst=169.254.169.254:80:X1 dstZone=Untrusted natDst=169.254.169.254:80 proto=tcp/http sent=52 app=9 msg=\"\" note=\"stack traffic always trusted\" n=151 fw_action=\"forward\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:21\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=10.0.0.96:54606:X1 natSrc=10.0.0.96:58515 dst=169.254.169.254:80:X1 natDst=169.254.169.254:80 proto=tcp/http sent=52 app=9 n=504 fw_action=\"NA\" dpi=0",
  // m=1235 fw_action=forward
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:21\" fw=10.0.0.96 pri=6 c=0 gcat=6 m=1235 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:54606:X1 srcZone=Untrusted natSrc=10.0.0.96:58515 dstMac=00:17:c5:30:f9:d9 dst=169.254.169.254:80:X1 dstZone=Untrusted natDst=169.254.169.254:80 proto=tcp/http sent=52 app=9 msg=\"\" note=\"stack traffic always trusted\" n=153 fw_action=\"forward\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:21\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=89.160.20.156:27465:X1 srcZone=Untrusted dst=10.0.0.96:22:X1 dstZone=Untrusted proto=tcp/22 sent=180 rcvd=416 spkt=3 rpkt=8 cdur=334083 rule=\"Default Access Rule\" app=42 n=501 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64912:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=506 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64912:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=681 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64913:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=508 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64913:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=683 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64913:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=782 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64913:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=784 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64912:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=786 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64912:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=788 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" src=10.0.0.96:54604:X1 natSrc=10.0.0.96:41479 dstMac=06:08:25:81:11:30 dst=169.254.169.254:80:X1 natDst=169.254.169.254:80 proto=tcp/http sent=350 rcvd=916 spkt=5 rpkt=5 cdur=2050 app=9 n=503 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:23\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" src=10.0.0.96:54606:X1 natSrc=10.0.0.96:58515 dstMac=06:08:25:81:11:30 dst=169.254.169.254:80:X1 natDst=169.254.169.254:80 proto=tcp/http sent=334 rcvd=694 spkt=5 rpkt=5 cdur=2033 app=9 n=505 fw_action=\"NA\" dpi=0",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:24\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64914:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=510 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:24\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64914:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=685 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=98 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:24\" fw=10.0.0.96 pri=6 c=262144 gcat=6 m=98 msg=\"Connection Opened\" src=81.2.69.193:64915:X1 dst=10.0.0.96:443:X1 usr=\"admin\" proto=tcp/https sent=64 sess=\"Web\" app=12 n=512 fw_action=\"NA\" dpi=0",
  // m=526 fw_action=mgmt
  "<133>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:24\" fw=10.0.0.96 pri=5 c=16 gcat=6 m=526 msg=\"Web management request allowed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64915:X1 srcZone=Untrusted dstMac=06:6e:64:57:48:02 dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https rcvd=64 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 note=\"policyCheck\" n=687 fw_action=\"mgmt\" uuid=\"18d4ad2b-4fa2-a827-0700-0040103ce114\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:24\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64914:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=790 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:24\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64914:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=792 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:25\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64913:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1887 rcvd=1378 spkt=10 rpkt=7 cdur=2150 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=507 fw_action=\"NA\" dpi=0",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:25\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64912:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1931 rcvd=3526 spkt=11 rpkt=8 cdur=2150 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=509 fw_action=\"NA\" dpi=0",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:25\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64915:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=794 fw_action=\"drop\"",
  // m=713 fw_action=drop
  "<135>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:25\" fw=10.0.0.96 pri=7 c=512 gcat=6 m=713 srcMac=00:06:b1:dd:4f:d4 src=10.0.0.96:443:X1 srcZone=Untrusted dstMac=00:17:c5:30:f9:d9 dst=81.2.69.193:64915:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=46 sess=\"Web\" rule=\"15 (WAN->WAN)\" app=12 msg=\"�\" note=\"TCP Flag(s): RST\" n=796 fw_action=\"drop\"",
  // m=537 fw_action=NA
  "<134>  id=firewall sn=0040103CE114 time=\"2022-05-16 08:19:26\" fw=10.0.0.96 pri=6 c=1024 gcat=6 m=537 msg=\"Connection Closed\" srcMac=06:08:25:81:11:30 src=81.2.69.193:64914:X1 srcZone=Untrusted dst=10.0.0.96:443:X1 dstZone=Untrusted usr=\"admin\" proto=tcp/https sent=1850 rcvd=1239 spkt=10 rpkt=7 cdur=2116 sess=\"Web\" rule=\"Default Access Rule\" app=12 n=511 fw_action=\"NA\" dpi=0",
];

// Every line, in file order — the detector and mapping sweeps run over this.
const ALL = [].concat(DRIZZTHACKER, GENERAL, NAT, SONICOS70_AWS);

module.exports = { DRIZZTHACKER, GENERAL, NAT, SONICOS70_AWS, ALL };
