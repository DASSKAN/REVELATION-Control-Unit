/*
  REVELATION — ESP32 RPF handheld: alert receiver + scan reporter
  ---------------------------------------------------------------
  - Joins the same Wi-Fi as the Control Unit
  - Polls  GET /api/handheld/alerts?device_id=HAND_ESP_01  every 2 s (also acts as heartbeat)
  - On a dispatched alert: buzzer + LED + prints type and coordinates on Serial
    (and on a 0.96" SSD1306 OLED if USE_OLED is 1)
  - Button ACK   (GPIO 0 / BOOT)  -> POST /api/alerts/<id>/officer  {"action":"ACK"}
  - Button SCAN  (GPIO 4)         -> POST /api/handheld/data  with the protocol envelope,
                                     alert_id attached, using readSensor() for the result.
    Replace readSensor() with the IMS / gas-sensor reading when the hardware is ready.

  Security: every request is signed (HMAC-SHA256 with this device's key + timestamp + nonce),
  so the Control Unit rejects forged, altered or replayed packets. Get DEVICE_SECRET from the
  dashboard: Security -> Devices -> "Create device key" (supervisor), same DEVICE_ID.

  Libraries: ArduinoJson (v7), and for the OLED: Adafruit SSD1306 + Adafruit GFX.
  Board: any ESP32 dev board.
*/
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/md.h"

#define USE_OLED 0
#if USE_OLED
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
Adafruit_SSD1306 oled(128, 64, &Wire, -1);
#endif

// ---------------- configure ----------------
const char* WIFI_SSID = "RPF_OPS";
const char* WIFI_PASS = "change-me";
const char* CU        = "http://192.168.1.10:5000";   // Control Unit address
const char* DEVICE_ID = "HAND_ESP_01";
const char* DEVICE_SECRET = "PASTE_64_HEX_CHARS_FROM_SECURITY_CENTRE";

const int PIN_BUZZER = 25;
const int PIN_LED    = 2;
const int PIN_ACK    = 0;    // BOOT button
const int PIN_SCAN   = 4;    // push button to GND

// ---------------- state ----------------
String runId = "";
String serverTime = "";   // CU clock from the last poll (no internet/NTP needed on a closed network)
String alertId = "", alertType = "", alertStatus = "", alertZone = "";
double alertLat = 0, alertLon = 0;
bool alarmOn = false;
unsigned long lastPoll = 0, lastBeep = 0;
uint32_t msgCounter = 0;

void show(const String& l1, const String& l2 = "", const String& l3 = "", const String& l4 = "") {
  Serial.println(l1 + " | " + l2 + " | " + l3 + " | " + l4);
#if USE_OLED
  oled.clearDisplay(); oled.setTextSize(1); oled.setTextColor(SSD1306_WHITE);
  oled.setCursor(0, 0);  oled.println(l1);
  oled.setCursor(0, 16); oled.println(l2);
  oled.setCursor(0, 32); oled.println(l3);
  oled.setCursor(0, 48); oled.println(l4);
  oled.display();
#endif
}

// ---------------- request signing
long clockOffset = 0;                 // server epoch - millis()/1000

String toHex(const uint8_t* b, size_t n) {
  static const char* h = "0123456789abcdef"; String s; s.reserve(n * 2);
  for (size_t i = 0; i < n; i++) { s += h[b[i] >> 4]; s += h[b[i] & 15]; }
  return s;
}
String sha256Hex(const String& data) {
  uint8_t out[32];
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const uint8_t*)data.c_str(), data.length(), out);
  return toHex(out, 32);
}
String hmacHex(const String& msg) {
  uint8_t key[32], out[32];
  for (int i = 0; i < 32; i++) key[i] = strtol(String(DEVICE_SECRET).substring(i * 2, i * 2 + 2).c_str(), NULL, 16);
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, (const uint8_t*)msg.c_str(), msg.length(), out);
  return toHex(out, 32);
}
void syncClock() {                     // no internet needed: the Control Unit tells us the time
  HTTPClient http; http.begin(String(CU) + "/api/time");
  if (http.GET() == 200) { JsonDocument d; deserializeJson(d, http.getString()); clockOffset = (long)d["epoch"].as<long>() - millis() / 1000; }
  http.end();
}

int httpJson(const String& method, const String& path, const String& body, JsonDocument& out) {
  if (WiFi.status() != WL_CONNECTED) return -1;
  HTTPClient http;
  http.begin(String(CU) + path);
  http.setTimeout(3000);
  http.addHeader("Content-Type", "application/json");
  String p = path; int q = p.indexOf('?'); if (q >= 0) p = p.substring(0, q);
  String ts = String(clockOffset + millis() / 1000);
  uint8_t nb[12]; esp_fill_random(nb, 12); String nonce = toHex(nb, 12);
  String sig = hmacHex(ts + "\n" + nonce + "\n" + method + "\n" + p + "\n" + sha256Hex(method == "GET" ? "" : body));
  http.addHeader("X-Device-Id", DEVICE_ID);
  http.addHeader("X-Timestamp", ts);
  http.addHeader("X-Nonce", nonce);
  http.addHeader("X-Signature", sig);
  int code = method == "GET" ? http.GET() : http.POST(body);
  if (code > 0) deserializeJson(out, http.getString());
  if (code == 401) show("SECURITY REJECT", out["error"] | "check DEVICE_SECRET");
  http.end();
  return code;
}

// ---- replace with the real detector ----
// returns detection label, threat level and confidence
void readSensor(String& det, String& level, float& conf) {
  int raw = analogRead(34);                 // e.g. gas / IMS front-end output on GPIO34
  conf = constrain(raw / 4095.0, 0.0, 1.0);
  if (conf > 0.7)      { det = "EXPLOSIVE"; level = "HIGH"; }
  else if (conf > 0.5) { det = "SUSPICIOUS_ITEM"; level = "MEDIUM"; }
  else                 { det = "CLEAR"; level = "LOW"; conf = 1.0 - conf; }
}

void poll() {
  JsonDocument doc;
  int code = httpJson("GET", String("/api/handheld/alerts?device_id=") + DEVICE_ID, "", doc);
  if (code != 200) { show("LINK DOWN", String(code)); return; }
  runId = doc["run_id"] | "";
  serverTime = doc["server_time"] | "";
  JsonArray alerts = doc["alerts"].as<JsonArray>();
  if (alerts.size() == 0) {
    if (alertId.length()) show("No active tasks", "run " + runId);
    alertId = ""; alarmOn = false; return;
  }
  JsonObject a = alerts[0];
  String id = a["alert_id"].as<String>();
  if (id != alertId) alarmOn = true;          // new alert -> sound
  alertId = id;
  alertType = a["detection"].as<String>();
  alertStatus = a["status"].as<String>();
  alertZone = a["zone"] | "";
  alertLat = a["latitude"] | 0.0;
  alertLon = a["longitude"] | 0.0;
  if (alertStatus != "DISPATCHED") alarmOn = false;
  show(alertType, String(alertLat, 6) + "," , String(alertLon, 6), alertStatus + " " + alertId);
}

void ack() {
  if (!alertId.length()) return;
  JsonDocument out;
  String body = String("{\"device_id\":\"") + DEVICE_ID + "\",\"action\":\"ACK\"}";
  int code = httpJson("POST", "/api/alerts/" + alertId + "/officer", body, out);
  alarmOn = false;
  show(code == 200 ? "ACKNOWLEDGED" : "ACK FAILED", alertId, String(code));
}

void scan() {
  if (!runId.length()) { show("No active run"); return; }
  String det, level; float conf;
  readSensor(det, level, conf);
  JsonDocument msg;
  msg["message_id"]   = String(DEVICE_ID) + "_" + String(millis()) + "_" + String(msgCounter++);
  msg["device_id"]    = DEVICE_ID;
  msg["device_type"]  = "HANDHELD";
  msg["run_id"]       = runId;
  msg["timestamp"]    = serverTime.substring(0, 19);   // CU time, at most one poll old
  msg["detection"]    = det;
  msg["threat_level"] = level;
  msg["confidence"]   = conf;
  if (alertId.length()) { msg["alert_id"] = alertId; msg["zone"] = alertZone; }
  String body; serializeJson(msg, body);
  JsonDocument out;
  int code = httpJson("POST", "/api/handheld/data", body, out);
  show("SCAN " + det, level + " " + String(conf, 2), code == 200 ? String(out["alert_status"] | "sent") : "ERR " + String(code));
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_BUZZER, OUTPUT); pinMode(PIN_LED, OUTPUT);
  pinMode(PIN_ACK, INPUT_PULLUP); pinMode(PIN_SCAN, INPUT_PULLUP);
#if USE_OLED
  oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
#endif
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  show("Connecting Wi-Fi", WIFI_SSID);
  while (WiFi.status() != WL_CONNECTED) delay(300);
  show("Wi-Fi OK", WiFi.localIP().toString(), DEVICE_ID);
  syncClock();
}

void loop() {
  if (millis() - lastPoll > 2000) { lastPoll = millis(); poll(); }
  if (alarmOn && millis() - lastBeep > 600) {
    lastBeep = millis();
    static bool on = false; on = !on;
    digitalWrite(PIN_LED, on); if (on) tone(PIN_BUZZER, 2200, 300);
  } else if (!alarmOn) digitalWrite(PIN_LED, LOW);
  if (digitalRead(PIN_ACK) == LOW)  { delay(40); if (digitalRead(PIN_ACK) == LOW)  { ack();  while (digitalRead(PIN_ACK) == LOW) delay(10); } }
  if (digitalRead(PIN_SCAN) == LOW) { delay(40); if (digitalRead(PIN_SCAN) == LOW) { scan(); while (digitalRead(PIN_SCAN) == LOW) delay(10); } }
}
