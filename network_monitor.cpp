#include <arpa/inet.h>
#include <ctime>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
using namespace std;

// =============================================
//   STRUCT
// =============================================
struct ScanResult {
  string ip;
  int port;
  bool isOpen;
  string service;
};

// =============================================
//   UTILITY FUNCTIONS
// =============================================

// Ambil waktu sekarang sebagai string
string getCurrentTime() {
  time_t now = time(0);
  char buf[20];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
  return string(buf);
}

// Nama service dari port number
string getServiceName(int port) {
  switch (port) {
  case 21:
    return "FTP";
  case 22:
    return "SSH";
  case 23:
    return "Telnet";
  case 25:
    return "SMTP";
  case 53:
    return "DNS";
  case 80:
    return "HTTP";
  case 110:
    return "POP3";
  case 135:
    return "RPC";
  case 139:
    return "NetBIOS";
  case 143:
    return "IMAP";
  case 443:
    return "HTTPS";
  case 445:
    return "SMB";
  case 3306:
    return "MySQL";
  case 3389:
    return "RDP";
  case 5432:
    return "PostgreSQL";
  case 6379:
    return "Redis";
  case 8080:
    return "HTTP-Alt";
  case 8443:
    return "HTTPS-Alt";
  default:
    return "Unknown";
  }
}

// Cek apakah port open
bool isPortOpen(const string &ip, int port, int timeoutSec = 2) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return false;

  struct timeval timeout;
  timeout.tv_sec = timeoutSec;
  timeout.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

  int result = connect(sock, (struct sockaddr *)&server, sizeof(server));
  close(sock);
  return result == 0;
}

// Cek apakah host aktif (ping port 80 atau 22)
bool isHostAlive(const string &ip) {
  return isPortOpen(ip, 80, 1) || isPortOpen(ip, 22, 1) ||
         isPortOpen(ip, 443, 1);
}

// Simpan hasil ke file
void saveToFile(const vector<ScanResult> &results, const string &ip,
                const string &scanType) {
  string filename = "scan_" + ip + "_" + scanType + ".txt";
  ofstream f(filename);

  f << "================================================" << endl;
  f << "         NETWORK MONITOR - SCAN RESULTS         " << endl;
  f << "================================================" << endl;
  f << "Scan Type : " << scanType << endl;
  f << "Target    : " << ip << endl;
  f << "Time      : " << getCurrentTime() << endl;
  f << "------------------------------------------------" << endl;

  int openCount = 0;
  for (const auto &r : results) {
    if (r.isOpen) {
      f << "[OPEN]   Port " << r.port << "\t- " << r.service << endl;
      openCount++;
    } else {
      f << "[CLOSED] Port " << r.port << "\t- " << r.service << endl;
    }
  }

  f << "------------------------------------------------" << endl;
  f << "Total open  : " << openCount << endl;
  f << "Total scan  : " << results.size() << endl;
  f.close();

  cout << "Hasil disimpan ke: " << filename << endl;
}

// =============================================
//   FITUR 1: PORT SCANNER
// =============================================
void runPortScanner() {
  string ip;
  int start, end;

  cout << "\n=== PORT SCANNER ===" << endl;
  cout << "IP Target     : ";
  cin >> ip;
  cout << "Port mulai    : ";
  cin >> start;
  cout << "Port selesai  : ";
  cin >> end;

  cout << "\nScanning " << ip << " port " << start << "-" << end << "..."
       << endl;
  cout << "------------------------------------" << endl;

  vector<ScanResult> results;
  int openCount = 0;

  for (int port = start; port <= end; port++) {
    cout << "Checking port " << port << "...\r" << flush;
    bool open = isPortOpen(ip, port);
    string svc = getServiceName(port);
    results.push_back({ip, port, open, svc});
    if (open) {
      cout << "[OPEN]   Port " << port << " - " << svc << "          " << endl;
      openCount++;
    }
  }

  cout << "------------------------------------" << endl;
  cout << "Selesai! Open: " << openCount << " port" << endl;
  saveToFile(results, ip, "portscan");
}

// =============================================
//   FITUR 2: QUICK SCAN (top 20 port penting)
// =============================================
void runQuickScan() {
  string ip;
  cout << "\n=== QUICK SCAN (Top 20 Ports) ===" << endl;
  cout << "IP Target : ";
  cin >> ip;

  vector<int> topPorts = {21,   22,   23,   25,   53,   80,   110,
                          135,  139,  143,  443,  445,  3306, 3389,
                          5432, 6379, 8080, 8443, 8888, 9090};

  cout << "\nScanning " << ip << "..." << endl;
  cout << "------------------------------------" << endl;

  vector<ScanResult> results;
  int openCount = 0;

  for (int port : topPorts) {
    cout << "Checking port " << port << "...\r" << flush;
    bool open = isPortOpen(ip, port, 1);
    string svc = getServiceName(port);
    results.push_back({ip, port, open, svc});
    if (open) {
      cout << "[OPEN]   Port " << port << " - " << svc << "          " << endl;
      openCount++;
    }
  }

  cout << "------------------------------------" << endl;
  cout << "Selesai! Open: " << openCount << "/" << topPorts.size() << " port"
       << endl;
  saveToFile(results, ip, "quickscan");
}

// =============================================
//   FITUR 3: HOST DISCOVERY
// =============================================
void runHostDiscovery() {
  string baseIP;
  cout << "\n=== HOST DISCOVERY ===" << endl;
  cout << "Masukkan base IP (contoh: 192.168.1): ";
  cin >> baseIP;

  cout << "\nScanning " << baseIP << ".1 - " << baseIP << ".20..." << endl;
  cout << "(Scan 20 host pertama)" << endl;
  cout << "------------------------------------" << endl;

  vector<string> aliveHosts;

  for (int i = 1; i <= 20; i++) {
    string ip = baseIP + "." + to_string(i);
    cout << "Checking " << ip << "...\r" << flush;
    if (isHostAlive(ip)) {
      cout << "[ALIVE]  " << ip << "          " << endl;
      aliveHosts.push_back(ip);
    }
  }

  cout << "------------------------------------" << endl;
  cout << "Selesai! " << aliveHosts.size() << " host aktif ditemukan." << endl;

  // Simpan ke file
  string filename = "hosts_" + baseIP + ".txt";
  ofstream f(filename);
  f << "HOST DISCOVERY RESULTS" << endl;
  f << "Base IP : " << baseIP << ".x" << endl;
  f << "Time    : " << getCurrentTime() << endl;
  f << "------------------------" << endl;
  for (const auto &h : aliveHosts) {
    f << "[ALIVE] " << h << endl;
  }
  f << "------------------------" << endl;
  f << "Total alive: " << aliveHosts.size() << endl;
  f.close();
  cout << "Hasil disimpan ke: " << filename << endl;
}

// =============================================
//   MAIN MENU
// =============================================
int main() {
  int pilihan;

  while (true) {
    cout << "\n================================================" << endl;
    cout << "         NETWORK MONITOR v1.0                   " << endl;
    cout << "         by Muhammad Fikri Taufikillah           " << endl;
    cout << "================================================" << endl;
    cout << "  1. Port Scanner (custom range)" << endl;
    cout << "  2. Quick Scan (top 20 ports)" << endl;
    cout << "  3. Host Discovery" << endl;
    cout << "  0. Exit" << endl;
    cout << "------------------------------------------------" << endl;
    cout << "Pilihan : ";
    cin >> pilihan;

    switch (pilihan) {
    case 1:
      runPortScanner();
      break;
    case 2:
      runQuickScan();
      break;
    case 3:
      runHostDiscovery();
      break;
    case 0:
      cout << "\nTerima kasih! Sampai jumpa." << endl;
      return 0;
    default:
      cout << "Pilihan tidak valid!" << endl;
    }
  }

  return 0;
}