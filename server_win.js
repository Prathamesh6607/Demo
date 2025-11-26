// server_win.js
// Node.js Express server using system commands for Wi-Fi and Bluetooth device info (Windows)

const express = require('express');
const path = require('path');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

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

// API endpoint for device data
app.get('/api/devices', (req, res) => {
  getWifiNetworks(wifiDevices => {
    getBluetoothDevices(btDevices => {
      res.json({ wifi: wifiDevices, bluetooth: btDevices });
    });
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
