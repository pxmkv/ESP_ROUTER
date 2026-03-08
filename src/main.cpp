#include <Arduino.h>
#include <SPI.h>
#include <Ethernet.h>

// ============================
// Waveshare ESP32-S3-ETH (W5500 SPI)
// ============================
static constexpr uint8_t W5500_CS   = 14;
static constexpr uint8_t W5500_RST  = 9;
static constexpr uint8_t W5500_INT  = 10;
static constexpr uint8_t W5500_MISO = 12;
static constexpr uint8_t W5500_MOSI = 11;
static constexpr uint8_t W5500_SCK  = 13;

// ============================
// LAN config
// ============================
static byte kMac[6] = {0x02, 0x45, 0x53, 0x50, 0x53, 0x33};
static const IPAddress kServerIP(192, 168, 50, 1);
static const IPAddress kSubnet(255, 255, 255, 0);
static const IPAddress kGateway(192, 168, 50, 1);
static const IPAddress kDns(192, 168, 50, 1);
static const IPAddress kBroadcast(255, 255, 255, 255);
static constexpr uint8_t kPoolStart = 100;
static constexpr uint8_t kPoolEnd   = 150;
static constexpr uint32_t kLeaseTimeSec = 24UL * 60UL * 60UL; // 24h
static constexpr uint32_t kT1Sec = kLeaseTimeSec / 2;
static constexpr uint32_t kT2Sec = (kLeaseTimeSec * 7UL) / 8UL;

EthernetUDP dhcpUdp;
EthernetServer httpServer(80);

// ============================
// DHCP definitions
// ============================
static constexpr uint16_t DHCP_SERVER_PORT = 67;
static constexpr uint16_t DHCP_CLIENT_PORT = 68;
static constexpr uint32_t DHCP_MAGIC_COOKIE = 0x63825363UL;

enum DhcpMessageType : uint8_t {
  DHCPDISCOVER = 1,
  DHCPOFFER    = 2,
  DHCPREQUEST  = 3,
  DHCPDECLINE  = 4,
  DHCPACK      = 5,
  DHCPNAK      = 6,
  DHCPRELEASE  = 7,
  DHCPINFORM   = 8,
};

struct DhcpPacket {
  uint8_t  op;
  uint8_t  htype;
  uint8_t  hlen;
  uint8_t  hops;
  uint8_t  xid[4];
  uint8_t  secs[2];
  uint8_t  flags[2];
  uint8_t  ciaddr[4];
  uint8_t  yiaddr[4];
  uint8_t  siaddr[4];
  uint8_t  giaddr[4];
  uint8_t  chaddr[16];
  uint8_t  sname[64];
  uint8_t  file[128];
  uint8_t  options[312];
};

struct LeaseEntry {
  bool active;
  bool committed;
  byte mac[6];
  IPAddress ip;
  uint32_t leaseStartMs;
};

static constexpr size_t kMaxLeases = (kPoolEnd - kPoolStart + 1);
LeaseEntry leases[kMaxLeases];

// ============================
// Helpers
// ============================
String macToString(const byte* mac, size_t len = 6) {
  char buf[3 * 6];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

void pulseW5500Reset() {
  pinMode(W5500_RST, OUTPUT);
  digitalWrite(W5500_RST, LOW);
  delay(50);
  digitalWrite(W5500_RST, HIGH);
  delay(200);
}

uint32_t readU32BE(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
}

void writeU32BE(uint8_t* p, uint32_t v) {
  p[0] = (v >> 24) & 0xFF;
  p[1] = (v >> 16) & 0xFF;
  p[2] = (v >> 8) & 0xFF;
  p[3] = (v) & 0xFF;
}

void writeIP(uint8_t* dst, const IPAddress& ip) {
  dst[0] = ip[0];
  dst[1] = ip[1];
  dst[2] = ip[2];
  dst[3] = ip[3];
}

IPAddress readIP(const uint8_t* src) {
  return IPAddress(src[0], src[1], src[2], src[3]);
}

bool isZeroIP(const IPAddress& ip) {
  return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0;
}

bool macEquals(const byte* a, const byte* b) {
  for (size_t i = 0; i < 6; ++i) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool ipInPool(const IPAddress& ip) {
  return ip[0] == kServerIP[0] && ip[1] == kServerIP[1] && ip[2] == kServerIP[2] &&
         ip[3] >= kPoolStart && ip[3] <= kPoolEnd;
}

int findLeaseByMac(const byte* mac) {
  for (size_t i = 0; i < kMaxLeases; ++i) {
    if (leases[i].active && macEquals(leases[i].mac, mac)) return (int)i;
  }
  return -1;
}

int findLeaseByIp(const IPAddress& ip) {
  for (size_t i = 0; i < kMaxLeases; ++i) {
    if (leases[i].active && leases[i].ip == ip) return (int)i;
  }
  return -1;
}

void expireOldLeases() {
  const uint32_t now = millis();
  for (size_t i = 0; i < kMaxLeases; ++i) {
    if (!leases[i].active) continue;
    if ((uint32_t)(now - leases[i].leaseStartMs) > (kLeaseTimeSec * 1000UL)) {
      Serial.printf("[DHCP] Lease expired: %s -> %s\n", macToString(leases[i].mac).c_str(), leases[i].ip.toString().c_str());
      leases[i].active = false;
      leases[i].committed = false;
      leases[i].ip = IPAddress(0, 0, 0, 0);
      memset(leases[i].mac, 0, sizeof(leases[i].mac));
    }
  }
}

IPAddress allocateLeaseIp(const byte* mac, const IPAddress& requested, bool commit) {
  expireOldLeases();

  int idx = findLeaseByMac(mac);
  if (idx >= 0) {
    leases[idx].leaseStartMs = millis();
    if (commit) leases[idx].committed = true;
    return leases[idx].ip;
  }

  if (ipInPool(requested)) {
    int existing = findLeaseByIp(requested);
    if (existing < 0) {
      size_t slot = requested[3] - kPoolStart;
      leases[slot].active = true;
      leases[slot].committed = commit;
      memcpy(leases[slot].mac, mac, 6);
      leases[slot].ip = requested;
      leases[slot].leaseStartMs = millis();
      return leases[slot].ip;
    }
  }

  for (uint8_t last = kPoolStart; last <= kPoolEnd; ++last) {
    IPAddress candidate(kServerIP[0], kServerIP[1], kServerIP[2], last);
    if (findLeaseByIp(candidate) >= 0) continue;
    size_t slot = last - kPoolStart;
    leases[slot].active = true;
    leases[slot].committed = commit;
    memcpy(leases[slot].mac, mac, 6);
    leases[slot].ip = candidate;
    leases[slot].leaseStartMs = millis();
    return leases[slot].ip;
  }

  return IPAddress(0, 0, 0, 0);
}

void releaseLease(const byte* mac) {
  int idx = findLeaseByMac(mac);
  if (idx >= 0) {
    Serial.printf("[DHCP] Release: %s -> %s\n", macToString(leases[idx].mac).c_str(), leases[idx].ip.toString().c_str());
    leases[idx].active = false;
    leases[idx].committed = false;
    leases[idx].ip = IPAddress(0, 0, 0, 0);
    memset(leases[idx].mac, 0, sizeof(leases[idx].mac));
  }
}

bool parseDhcpOptions(const DhcpPacket& pkt,
                      uint8_t& msgType,
                      IPAddress& requestedIP,
                      IPAddress& serverId,
                      String& hostName) {
  msgType = 0;
  requestedIP = IPAddress(0, 0, 0, 0);
  serverId = IPAddress(0, 0, 0, 0);
  hostName = "";

  const uint8_t* opt = pkt.options;
  if (readU32BE(opt) != DHCP_MAGIC_COOKIE) return false;
  opt += 4;

  while ((opt - pkt.options) < (int)sizeof(pkt.options)) {
    uint8_t code = *opt++;
    if (code == 0xFF) break;
    if (code == 0x00) continue;
    if ((opt - pkt.options) >= (int)sizeof(pkt.options)) break;
    uint8_t len = *opt++;
    if ((opt - pkt.options + len) > (int)sizeof(pkt.options)) break;

    switch (code) {
      case 53: // DHCP message type
        if (len >= 1) msgType = opt[0];
        break;
      case 50: // requested IP
        if (len == 4) requestedIP = readIP(opt);
        break;
      case 54: // server identifier
        if (len == 4) serverId = readIP(opt);
        break;
      case 12: // host name
        for (uint8_t i = 0; i < len; ++i) hostName += char(opt[i]);
        break;
      default:
        break;
    }
    opt += len;
  }
  return msgType != 0;
}

size_t buildDhcpReply(uint8_t* out,
                      const DhcpPacket& req,
                      DhcpMessageType type,
                      const IPAddress& yiaddr) {
  memset(out, 0, 548);
  DhcpPacket* rep = reinterpret_cast<DhcpPacket*>(out);

  rep->op = 2;      // BOOTREPLY
  rep->htype = 1;   // Ethernet
  rep->hlen = 6;
  rep->hops = 0;
  memcpy(rep->xid, req.xid, 4);
  memcpy(rep->secs, req.secs, 2);
  memcpy(rep->flags, req.flags, 2);
  writeIP(rep->yiaddr, yiaddr);
  writeIP(rep->siaddr, kServerIP);
  memcpy(rep->chaddr, req.chaddr, 16);

  uint8_t* opt = rep->options;
  writeU32BE(opt, DHCP_MAGIC_COOKIE);
  opt += 4;

  *opt++ = 53; *opt++ = 1; *opt++ = static_cast<uint8_t>(type);    // msg type
  *opt++ = 54; *opt++ = 4; writeIP(opt, kServerIP); opt += 4;       // server id

  if (type != DHCPNAK) {
    *opt++ = 1;  *opt++ = 4; writeIP(opt, kSubnet);  opt += 4;      // subnet mask
    *opt++ = 3;  *opt++ = 4; writeIP(opt, kGateway); opt += 4;      // router
    *opt++ = 6;  *opt++ = 4; writeIP(opt, kDns);     opt += 4;      // dns
    *opt++ = 51; *opt++ = 4; writeU32BE(opt, kLeaseTimeSec); opt += 4;
    *opt++ = 58; *opt++ = 4; writeU32BE(opt, kT1Sec); opt += 4;
    *opt++ = 59; *opt++ = 4; writeU32BE(opt, kT2Sec); opt += 4;
  }

  *opt++ = 255; // end
  return static_cast<size_t>(opt - out);
}

void sendDhcpReply(const DhcpPacket& req, DhcpMessageType type, const IPAddress& yiaddr) {
  uint8_t frame[548];
  size_t len = buildDhcpReply(frame, req, type, yiaddr);

  // Most clients are still unconfigured, so broadcast is the safest choice.
  dhcpUdp.beginPacket(kBroadcast, DHCP_CLIENT_PORT);
  dhcpUdp.write(frame, len);
  dhcpUdp.endPacket();

  Serial.printf("[DHCP] Sent %s to %s, yiaddr=%s\n",
                (type == DHCPOFFER ? "OFFER" : type == DHCPACK ? "ACK" : type == DHCPNAK ? "NAK" : "OTHER"),
                macToString(req.chaddr).c_str(), yiaddr.toString().c_str());
}

void printLeaseTable() {
  Serial.println("[DHCP] Active leases:");
  bool any = false;
  for (size_t i = 0; i < kMaxLeases; ++i) {
    if (!leases[i].active) continue;
    any = true;
    Serial.printf("  %s -> %s%s\n",
                  macToString(leases[i].mac).c_str(),
                  leases[i].ip.toString().c_str(),
                  leases[i].committed ? "" : " (offered)");
  }
  if (!any) Serial.println("  (none)");
}

void handleDhcpPacket() {
  int packetSize = dhcpUdp.parsePacket();
  if (packetSize <= 0) return;
  if (packetSize < (int)sizeof(DhcpPacket) - (int)sizeof(((DhcpPacket*)nullptr)->options) + 4) {
    // Too small to hold DHCP header + cookie.
    while (dhcpUdp.available()) dhcpUdp.read();
    return;
  }

  uint8_t buffer[548];
  int n = dhcpUdp.read(buffer, sizeof(buffer));
  if (n <= 0) return;

  DhcpPacket req{};
  memset(&req, 0, sizeof(req));
  memcpy(&req, buffer, min((size_t)n, sizeof(req)));

  if (req.op != 1 || req.htype != 1 || req.hlen != 6) return;

  uint8_t msgType = 0;
  IPAddress requestedIP;
  IPAddress serverId;
  String hostName;
  if (!parseDhcpOptions(req, msgType, requestedIP, serverId, hostName)) return;

  const String mac = macToString(req.chaddr);
  const IPAddress ciaddr = readIP(req.ciaddr);
  Serial.printf("[DHCP] RX type=%u mac=%s ciaddr=%s requested=%s host=%s\n",
                msgType,
                mac.c_str(),
                ciaddr.toString().c_str(),
                requestedIP.toString().c_str(),
                hostName.c_str());

  switch (msgType) {
    case DHCPDISCOVER: {
      IPAddress offer = allocateLeaseIp(req.chaddr, requestedIP, false);
      if (!isZeroIP(offer)) {
        sendDhcpReply(req, DHCPOFFER, offer);
      }
      break;
    }

    case DHCPREQUEST: {
      if (!isZeroIP(serverId) && serverId != kServerIP) {
        // Client selected another DHCP server.
        break;
      }

      IPAddress chosen = requestedIP;
      if (isZeroIP(chosen) && !isZeroIP(ciaddr) && ipInPool(ciaddr)) {
        chosen = ciaddr;
      }
      if (isZeroIP(chosen)) {
        int idx = findLeaseByMac(req.chaddr);
        if (idx >= 0) chosen = leases[idx].ip;
      }

      if (!ipInPool(chosen)) {
        sendDhcpReply(req, DHCPNAK, IPAddress(0, 0, 0, 0));
        break;
      }

      int owner = findLeaseByIp(chosen);
      if (owner >= 0 && !macEquals(leases[owner].mac, req.chaddr)) {
        sendDhcpReply(req, DHCPNAK, IPAddress(0, 0, 0, 0));
        break;
      }

      IPAddress ack = allocateLeaseIp(req.chaddr, chosen, true);
      if (isZeroIP(ack)) {
        sendDhcpReply(req, DHCPNAK, IPAddress(0, 0, 0, 0));
      } else {
        sendDhcpReply(req, DHCPACK, ack);
        printLeaseTable();
      }
      break;
    }

    case DHCPRELEASE:
    case DHCPDECLINE:
      releaseLease(req.chaddr);
      printLeaseTable();
      break;

    case DHCPINFORM:
      // INFORM asks for options, not an address.
      sendDhcpReply(req, DHCPACK, ciaddr);
      break;

    default:
      break;
  }
}

void serveHttp() {
  EthernetClient client = httpServer.available();
  if (!client) return;

  unsigned long start = millis();
  while (client.connected() && millis() - start < 1000) {
    if (!client.available()) {
      delay(1);
      continue;
    }

    String req = client.readStringUntil('\n');
    (void)req;

    // Skip rest of headers.
    while (client.connected()) {
      String line = client.readStringUntil('\n');
      if (line == "\r" || line.length() == 0) break;
    }

    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: text/html; charset=utf-8");
    client.println("Connection: close");
    client.println();
    client.println("<!doctype html><html><head><meta charset='utf-8'><title>ESP32-S3 DHCP LAN</title>");
    client.println("<style>body{font-family:Arial,sans-serif;margin:24px;}table{border-collapse:collapse;}td,th{border:1px solid #888;padding:8px 12px;}code{background:#f3f3f3;padding:2px 6px;}</style>");
    client.println("</head><body>");
    client.println("<h1>ESP32-S3 Wired DHCP LAN</h1>");
    client.print("<p>Server IP: <code>"); client.print(Ethernet.localIP()); client.println("</code></p>");
    client.print("<p>Subnet: <code>"); client.print(kSubnet); client.println("</code></p>");
    client.print("<p>Pool: <code>192.168.50."); client.print(kPoolStart); client.print(" - 192.168.50."); client.print(kPoolEnd); client.println("</code></p>");
    client.println("<h2>Active leases</h2>");
    client.println("<table><tr><th>MAC</th><th>IP</th><th>Status</th></tr>");
    bool any = false;
    for (size_t i = 0; i < kMaxLeases; ++i) {
      if (!leases[i].active) continue;
      any = true;
      client.print("<tr><td>"); client.print(macToString(leases[i].mac)); client.print("</td><td>");
      client.print(leases[i].ip); client.print("</td><td>"); client.print(leases[i].committed ? "ACKed" : "Offered");
      client.println("</td></tr>");
    }
    if (!any) client.println("<tr><td colspan='3'>(none)</td></tr>");
    client.println("</table></body></html>");
    break;
  }

  delay(1);
  client.stop();
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("ESP32-S3 ETH DHCP LAN starting...");

  pinMode(W5500_INT, INPUT_PULLUP);
  pulseW5500Reset();

  SPI.begin(W5500_SCK, W5500_MISO, W5500_MOSI, W5500_CS);
  Ethernet.init(W5500_CS);

  // Static IP for the ESP32 itself; it acts as a single-port LAN gateway/control node.
  Ethernet.begin(kMac, kServerIP, kDns, kGateway, kSubnet);
  delay(300);

  Serial.print("Local IP: ");
  Serial.println(Ethernet.localIP());
  Serial.print("Subnet : ");
  Serial.println(Ethernet.subnetMask());
  Serial.print("Gateway: ");
  Serial.println(Ethernet.gatewayIP());

  dhcpUdp.begin(DHCP_SERVER_PORT);
  httpServer.begin();

  Serial.println("DHCP server listening on UDP/67");
  Serial.println("HTTP status page listening on TCP/80");
  Serial.println("Connect the RJ45 port to a switch, then connect clients to the same switch.");
}

void loop() {
  handleDhcpPacket();
  serveHttp();
  expireOldLeases();
  delay(1);
}
