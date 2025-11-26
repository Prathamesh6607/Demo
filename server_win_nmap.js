// server_win_nmap.js
// Node.js Express server with nmap and Bluetooth scan endpoints for IoT dashboard

const express = require('express');
const path = require('path');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory scan results
let nmapResults = [];
let openPorts = 0;
let bluetoothResults = [];

// Serve static files
app.use(express.static(path.join(__dirname, 'static')));

// Helper: Fetch Wi-Fi networks using netsh (Windows)
function getWifiNetworks(callback) {
  exec('netsh wlan show networks mode=Bssid', (err, stdout) => {
    if (err) return callback([]);
    const networks = [];
    const lines = stdout.split('\n');
    lines.forEach(line => {
      const match = line.match(/SSID [0-9]+ : (.+)/);
      if (match) networks.push({ name: match[1], type: 'WiFi Network', status: 'Visible' });
    });
    callback(networks);
  });
}

// Helper: Fetch Bluetooth devices using PowerShell (Windows)
function getBluetoothDevices(callback) {
  const psCmd = 'powershell "Get-PnpDevice -Class Bluetooth | Where-Object { $_.Status -eq \"OK\" } | Select-Object -ExpandProperty FriendlyName"';
  exec(psCmd, (err, stdout) => {
    if (err) return callback([]);
    const devices = stdout.split('\n').filter(Boolean).map(name => ({
      name: name.trim(),
      type: 'Bluetooth Device',
      status: 'Paired'
    }));
    callback(devices);
  });
}

// Helper: Run nmap quick scan (requires nmap installed)
function runNmapQuickScan(callback) {
  // Scan local subnet for alive hosts and open ports (top 1000)
  // You may want to adjust the subnet below
  const subnet = '192.168.1.0/24';
  exec(`nmap -sn ${subnet}`, (err, stdout) => {
    if (err) return callback([]);
    // Parse alive hosts
    const hosts = [];
    let currentIP = null;
    stdout.split('\n').forEach(line => {
      const ipMatch = line.match(/Nmap scan report for ([0-9.]+)/);
      if (ipMatch) {
        currentIP = ipMatch[1];
        hosts.push({ ip: currentIP, status: 'Alive', type: 'Network', mac: '', vendor: '' });
      }
      const macMatch = line.match(/MAC Address: ([0-9A-F:]+) \(([^)]+)\)/i);
      if (macMatch && hosts.length > 0) {
        hosts[hosts.length - 1].mac = macMatch[1];
        hosts[hosts.length - 1].vendor = macMatch[2];
      }
    });
    // For each alive host, run a quick port scan (top 10 ports)
    let completed = 0;
    openPorts = 0;
    if (hosts.length === 0) return callback([]);
    hosts.forEach((host, idx) => {
      exec(`nmap -T4 --top-ports 10 ${host.ip}`, (err2, out2) => {
        if (!err2 && out2) {
          const portLines = out2.split('\n').filter(l => l.match(/^\d+\/tcp/));
          host.open_ports = portLines.map(l => parseInt(l.split('/')[0]));
          openPorts += host.open_ports.length;
        } else {
          host.open_ports = [];
        }
        completed++;
        if (completed === hosts.length) {
          callback(hosts);
        }
      });
    });
  });
}

// API endpoint for device data
app.get('/api/devices', (req, res) => {
  getWifiNetworks(wifiDevices => {
    res.json({
      wifi: wifiDevices,
      bluetooth: bluetoothResults,
      nmap: nmapResults,
      open_ports: openPorts
    });
  });
});

// API endpoint to trigger nmap scan
app.get('/api/nmap', (req, res) => {
  runNmapQuickScan(results => {
    nmapResults = results;
    res.json({ success: true, nmap: nmapResults, open_ports: openPorts });
  });
});

// API endpoint to trigger Bluetooth scan
app.get('/api/bluetooth', (req, res) => {
  getBluetoothDevices(devices => {
    bluetoothResults = devices;
    res.json({ success: true, bluetooth: bluetoothResults });
  });
});

// Serve identify.html (must be in ./templates)
app.get('/identify', (req, res) => {
  res.sendFile(path.join(__dirname, 'templates', 'identify.html'));
});

// Root redirect
app.get('/', (req, res) => {
  res.redirect('/identify');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
