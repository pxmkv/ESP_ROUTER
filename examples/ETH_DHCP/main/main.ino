#include <SPI.h>
#include <Ethernet.h>
#include <EthernetUdp.h>

// =========================
// Waveshare ESP32-S3-ETH pins
// =========================
#define W5500_CS    14
#define W5500_RST    9
#define W5500_INT   10
#define W5500_MISO  12
#define W5500_MOSI  11
#define W5500_SCK   13

// =========================
// Config
// =========================
byte mac[] = { 0x02, 0x12, 0x34, 0x56, 0x78, 0x9A };

IPAddress serverIP(192, 168, 50, 1);
IPAddress subnetMask(255, 255, 255, 0);
IPAddress gatewayIP(192, 168, 50, 1);
IPAddress dnsIP(192, 168, 50, 1);   // 当前仅本地网，先填自己

const uint8_t POOL_START = 100;
const uint8_t POOL_END   = 150;

const uint16_t DHCP_SERVER_PORT = 67;
const uint16_t DHCP_CLIENT_PORT = 68;

const uint8_t DHCPDISCOVER = 1;
const uint8_t DHCPOFFER    = 2;
const uint8_t DHCPREQUEST  = 3;
const uint8_t DHCPDECLINE  = 4;
const uint8_t DHCPACK      = 5;
const uint8_t DHCPNAK      = 6;
const uint8_t DHCPRELEASE  = 7;
const uint8_t DHCPINFORM   = 8;

const uint32_t LEASE_TIME_SEC = 86400UL; // 24h
constexpr size_t DHCP_BUF_SIZE = 600;

// 为了稳定性，默认关闭周期租约表打印
#define ENABLE_LEASE_TABLE_PRINT 1
const uint32_t LEASE_TABLE_PRINT_INTERVAL_MS = 30000UL;

EthernetUDP dhcpUdp;

static uint8_t g_dhcpRxBuf[DHCP_BUF_SIZE];
static uint8_t g_dhcpTxBuf[DHCP_BUF_SIZE];

struct Lease {
  bool used;
  uint8_t mac[6];
  IPAddress ip;
  uint32_t expiresAt; // millis() based
};

Lease leases[16];

// -------------------------
// Utils
// -------------------------
bool macEqual(const uint8_t* a, const uint8_t* b) {
  for (int i = 0; i < 6; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void macCopy(uint8_t* dst, const uint8_t* src) {
  for (int i = 0; i < 6; i++) {
    dst[i] = src[i];
  }
}

bool isLeaseExpired(const Lease& l) {
  if (!l.used) return true;
  return (int32_t)(millis() - l.expiresAt) >= 0;
}

void cleanupExpiredLeases() {
  for (int i = 0; i < 16; i++) {
    if (leases[i].used && isLeaseExpired(leases[i])) {
      leases[i].used = false;
    }
  }
}

bool isInPool(IPAddress ip) {
  return ip[0] == 192 && ip[1] == 168 && ip[2] == 50 &&
         ip[3] >= POOL_START && ip[3] <= POOL_END;
}

int findLeaseByMac(const uint8_t* mac6) {
  for (int i = 0; i < 16; i++) {
    if (leases[i].used && !isLeaseExpired(leases[i]) && macEqual(leases[i].mac, mac6)) {
      return i;
    }
  }
  return -1;
}

int findLeaseByIP(IPAddress ip) {
  for (int i = 0; i < 16; i++) {
    if (leases[i].used && !isLeaseExpired(leases[i]) && leases[i].ip == ip) {
      return i;
    }
  }
  return -1;
}

int findFreeLeaseSlot() {
  for (int i = 0; i < 16; i++) {
    if (!leases[i].used || isLeaseExpired(leases[i])) return i;
  }
  return -1;
}

IPAddress firstFreeIP() {
  for (uint8_t last = POOL_START; last <= POOL_END; last++) {
    IPAddress candidate(192, 168, 50, last);
    if (findLeaseByIP(candidate) < 0) {
      return candidate;
    }
  }
  return IPAddress(0, 0, 0, 0);
}

IPAddress reserveOrGetIP(const uint8_t* mac6, IPAddress preferred = IPAddress(0,0,0,0)) {
  cleanupExpiredLeases();

  int macIdx = findLeaseByMac(mac6);
  if (macIdx >= 0) {
    leases[macIdx].expiresAt = millis() + LEASE_TIME_SEC * 1000UL;
    return leases[macIdx].ip;
  }

  IPAddress chosen(0,0,0,0);

  if (preferred != IPAddress(0,0,0,0) && isInPool(preferred)) {
    if (findLeaseByIP(preferred) < 0) {
      chosen = preferred;
    }
  }

  if (chosen == IPAddress(0,0,0,0)) {
    chosen = firstFreeIP();
  }

  if (chosen == IPAddress(0,0,0,0)) {
    return chosen;
  }

  int slot = findFreeLeaseSlot();
  if (slot < 0) return IPAddress(0,0,0,0);

  leases[slot].used = true;
  macCopy(leases[slot].mac, mac6);
  leases[slot].ip = chosen;
  leases[slot].expiresAt = millis() + LEASE_TIME_SEC * 1000UL;

  return chosen;
}

void releaseLease(const uint8_t* mac6) {
  int idx = findLeaseByMac(mac6);
  if (idx >= 0) {
    leases[idx].used = false;
  }
}

void printLeaseTable() {
#if ENABLE_LEASE_TABLE_PRINT
  Serial.println("==== Lease Table ====");

  char macStr[18];

  for (int i = 0; i < 16; i++) {
    if (leases[i].used && !isLeaseExpired(leases[i])) {
      Lease l = leases[i];

      snprintf(
        macStr, sizeof(macStr),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        l.mac[0], l.mac[1], l.mac[2],
        l.mac[3], l.mac[4], l.mac[5]
      );

      Serial.printf(
        "#%d  %s  ->  %u.%u.%u.%u\r\n",
        i, macStr,
        l.ip[0], l.ip[1], l.ip[2], l.ip[3]
      );
    }
  }

  Serial.println("=====================");
#endif
}

// -------------------------
// DHCP option parsing
// -------------------------
int findDhcpOption(const uint8_t* buf, int len, uint8_t code) {
  if (len < 240) return -1;

  int i = 240;
  while (i < len) {
    uint8_t opt = buf[i];

    if (opt == 0xFF) break;         // END
    if (opt == 0x00) { i++; continue; }  // PAD

    if (i + 1 >= len) break;
    uint8_t optLen = buf[i + 1];
    if (i + 2 + optLen > len) break;

    if (opt == code) return i;
    i += 2 + optLen;
  }

  return -1;
}

uint8_t getDhcpMessageType(const uint8_t* buf, int len) {
  int idx = findDhcpOption(buf, len, 53);
  if (idx >= 0 && idx + 2 < len && buf[idx + 1] == 1) {
    return buf[idx + 2];
  }
  return 0;
}

IPAddress getRequestedIP(const uint8_t* buf, int len) {
  int idx = findDhcpOption(buf, len, 50);
  if (idx >= 0 && idx + 5 < len && buf[idx + 1] == 4) {
    return IPAddress(buf[idx + 2], buf[idx + 3], buf[idx + 4], buf[idx + 5]);
  }
  return IPAddress(0,0,0,0);
}

IPAddress getCiaddr(const uint8_t* buf) {
  return IPAddress(buf[12], buf[13], buf[14], buf[15]);
}

// -------------------------
// DHCP reply builder
// -------------------------
void writeIP(uint8_t* p, IPAddress ip) {
  p[0] = ip[0];
  p[1] = ip[1];
  p[2] = ip[2];
  p[3] = ip[3];
}

int buildDhcpReply(
  const uint8_t* req,
  uint8_t* out,
  uint8_t replyType,
  IPAddress yiaddr
) {
  memset(out, 0, DHCP_BUF_SIZE);

  // BOOTP fixed header
  out[0] = 2;  // BOOTREPLY
  out[1] = 1;  // htype Ethernet
  out[2] = 6;  // hlen
  out[3] = 0;  // hops

  // xid
  out[4] = req[4];
  out[5] = req[5];
  out[6] = req[6];
  out[7] = req[7];

  // secs
  out[8] = req[8];
  out[9] = req[9];

  // flags
  out[10] = req[10];
  out[11] = req[11];

  // yiaddr
  writeIP(&out[16], yiaddr);

  // siaddr = server IP
  writeIP(&out[20], serverIP);

  // giaddr copy
  out[24] = req[24];
  out[25] = req[25];
  out[26] = req[26];
  out[27] = req[27];

  // chaddr (16 bytes)
  for (int i = 0; i < 16; i++) {
    out[28 + i] = req[28 + i];
  }

  // magic cookie
  out[236] = 0x63;
  out[237] = 0x82;
  out[238] = 0x53;
  out[239] = 0x63;

  int idx = 240;

  // Option 53: DHCP Message Type
  out[idx++] = 53;
  out[idx++] = 1;
  out[idx++] = replyType;

  // Option 54: Server Identifier
  out[idx++] = 54;
  out[idx++] = 4;
  out[idx++] = serverIP[0];
  out[idx++] = serverIP[1];
  out[idx++] = serverIP[2];
  out[idx++] = serverIP[3];

  // Option 51: Lease Time
  out[idx++] = 51;
  out[idx++] = 4;
  out[idx++] = (LEASE_TIME_SEC >> 24) & 0xFF;
  out[idx++] = (LEASE_TIME_SEC >> 16) & 0xFF;
  out[idx++] = (LEASE_TIME_SEC >> 8) & 0xFF;
  out[idx++] = (LEASE_TIME_SEC >> 0) & 0xFF;

  // Option 1: Subnet Mask
  out[idx++] = 1;
  out[idx++] = 4;
  out[idx++] = subnetMask[0];
  out[idx++] = subnetMask[1];
  out[idx++] = subnetMask[2];
  out[idx++] = subnetMask[3];

  // Option 3: Router
  out[idx++] = 3;
  out[idx++] = 4;
  out[idx++] = gatewayIP[0];
  out[idx++] = gatewayIP[1];
  out[idx++] = gatewayIP[2];
  out[idx++] = gatewayIP[3];

  // Option 6: DNS
  out[idx++] = 6;
  out[idx++] = 4;
  out[idx++] = dnsIP[0];
  out[idx++] = dnsIP[1];
  out[idx++] = dnsIP[2];
  out[idx++] = dnsIP[3];

  // Option 58: Renewal Time
  {
    uint32_t t1 = LEASE_TIME_SEC / 2;
    out[idx++] = 58;
    out[idx++] = 4;
    out[idx++] = (t1 >> 24) & 0xFF;
    out[idx++] = (t1 >> 16) & 0xFF;
    out[idx++] = (t1 >> 8) & 0xFF;
    out[idx++] = (t1 >> 0) & 0xFF;
  }

  // Option 59: Rebinding Time
  {
    uint32_t t2 = (LEASE_TIME_SEC * 7UL) / 8UL;
    out[idx++] = 59;
    out[idx++] = 4;
    out[idx++] = (t2 >> 24) & 0xFF;
    out[idx++] = (t2 >> 16) & 0xFF;
    out[idx++] = (t2 >> 8) & 0xFF;
    out[idx++] = (t2 >> 0) & 0xFF;
  }

  // End
  out[idx++] = 255;

  return idx;
}

void sendDhcpReply(const uint8_t* req, uint8_t replyType, IPAddress yiaddr) {
  int outLen = buildDhcpReply(req, g_dhcpTxBuf, replyType, yiaddr);

  IPAddress dst(255, 255, 255, 255);
  dhcpUdp.beginPacket(dst, DHCP_CLIENT_PORT);
  dhcpUdp.write(g_dhcpTxBuf, outLen);
  dhcpUdp.endPacket();
}

// -------------------------
// DHCP handler
// -------------------------
void handleDhcpPacket(uint8_t* buf, int len) {
  if (len < 240) return;
  if (buf[0] != 1) return; // BOOTREQUEST only

  if (!(buf[236] == 0x63 && buf[237] == 0x82 && buf[238] == 0x53 && buf[239] == 0x63)) {
    return;
  }

  uint8_t msgType = getDhcpMessageType(buf, len);
  const uint8_t* clientMac = &buf[28];

  if (msgType == 0) return;

  Serial.printf(
    "[DHCP] RX type=%u from %02X:%02X:%02X:%02X:%02X:%02X\r\n",
    msgType,
    clientMac[0], clientMac[1], clientMac[2],
    clientMac[3], clientMac[4], clientMac[5]
  );

  if (msgType == DHCPDISCOVER) {
    IPAddress offer = reserveOrGetIP(clientMac);
    if (offer != IPAddress(0,0,0,0)) {
      Serial.printf(
        "[DHCP] OFFER %u.%u.%u.%u\r\n",
        offer[0], offer[1], offer[2], offer[3]
      );
      sendDhcpReply(buf, DHCPOFFER, offer);
    } else {
      Serial.println("[DHCP] No free IP for DISCOVER");
    }
    return;
  }

  if (msgType == DHCPREQUEST) {
    IPAddress requested = getRequestedIP(buf, len);
    if (requested == IPAddress(0,0,0,0)) {
      requested = getCiaddr(buf);
    }

    IPAddress ackIP = reserveOrGetIP(clientMac, requested);

    if (ackIP != IPAddress(0,0,0,0)) {
      Serial.printf(
        "[DHCP] ACK %u.%u.%u.%u to %02X:%02X:%02X:%02X:%02X:%02X\r\n",
        ackIP[0], ackIP[1], ackIP[2], ackIP[3],
        clientMac[0], clientMac[1], clientMac[2],
        clientMac[3], clientMac[4], clientMac[5]
      );
      sendDhcpReply(buf, DHCPACK, ackIP);
    } else {
      Serial.println("[DHCP] NAK / no free IP");
      sendDhcpReply(buf, DHCPNAK, IPAddress(0,0,0,0));
    }
    return;
  }

  if (msgType == DHCPRELEASE) {
    releaseLease(clientMac);
    Serial.printf(
      "[DHCP] RELEASE from %02X:%02X:%02X:%02X:%02X:%02X\r\n",
      clientMac[0], clientMac[1], clientMac[2],
      clientMac[3], clientMac[4], clientMac[5]
    );
    return;
  }

  if (msgType == DHCPINFORM) {
    IPAddress ciaddr = getCiaddr(buf);
    if (ciaddr != IPAddress(0,0,0,0)) {
      sendDhcpReply(buf, DHCPACK, ciaddr);
    }
    return;
  }
}

// -------------------------
// Setup / Loop
// -------------------------
void resetW5500() {
  pinMode(W5500_RST, OUTPUT);
  digitalWrite(W5500_RST, LOW);
  delay(50);
  digitalWrite(W5500_RST, HIGH);
  delay(200);
}

void setup() {
  Serial.begin(115200);
  delay(300);

  Serial.println();
  Serial.println("ESP32-S3-ETH DHCP Server starting...");

  pinMode(W5500_CS, OUTPUT);
  digitalWrite(W5500_CS, HIGH);

  resetW5500();

  SPI.begin(W5500_SCK, W5500_MISO, W5500_MOSI, W5500_CS);
  Ethernet.init(W5500_CS);

  memset(leases, 0, sizeof(leases));

  Ethernet.begin(mac, serverIP, dnsIP, gatewayIP, subnetMask);
  delay(1000);

  Serial.print("Server IP: ");
  Serial.println(Ethernet.localIP());

  if (dhcpUdp.begin(DHCP_SERVER_PORT)) {
    Serial.println("DHCP server listening on UDP 67");
  } else {
    Serial.println("Failed to start DHCP UDP server");
    while (true) {
      delay(1000);
    }
  }

  Serial.println("Connect a switch to RJ45, then plug clients into that switch.");
  Serial.println("Pool: 192.168.50.100 ~ 192.168.50.150");
}

void loop() {
  int packetSize = dhcpUdp.parsePacket();
  if (packetSize > 0) {
    int len = dhcpUdp.read(g_dhcpRxBuf, sizeof(g_dhcpRxBuf));
    if (len > 0) {
      handleDhcpPacket(g_dhcpRxBuf, len);
    }
  }

#if ENABLE_LEASE_TABLE_PRINT
  static uint32_t lastPrint = 0;
  if (millis() - lastPrint > LEASE_TABLE_PRINT_INTERVAL_MS) {
    lastPrint = millis();
    cleanupExpiredLeases();
    printLeaseTable();
  }
#endif

  delay(1);
}