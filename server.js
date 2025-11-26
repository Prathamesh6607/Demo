// server.js
// Node.js Express server for Wi-Fi and Bluetooth device dashboard

const express = require('express');
const path = require('path');
const wifi = require('node-wifi');
const { BluetoothSerialPort } = require('bluetooth-serial-port');

const app = express();
const PORT = process.env.PORT || 3000;

// Init wifi module
wifi.init({ iface: null }); // null = auto-detect

// Serve static files
app.use(express.static(path.join(__dirname, 'static')));

// Helper: Fetch Wi-Fi devices (connected clients)
async function getWifiDevices() {
  try {
    // node-wifi only lists available networks, not connected clients.
    // For hotspot clients, platform-specific code is needed (not cross-platform).
    // We'll list visible Wi-Fi networks as a fallback.
    const networks = await wifi.scan();
    return networks.map(n => ({
      name: n.ssid,
      status: n.security || 'Unknown',
      type: 'WiFi Network',
    }));
  } catch (err) {
    return [];
  }
}

// Helper: Fetch Bluetooth devices (paired/visible)
function getBluetoothDevices() {
  return new Promise((resolve) => {
    const btSerial = new BluetoothSerialPort();
    const devices = [];
    let finished = false;
    btSerial.on('found', function(address, name) {
      devices.push({
        name: name || address,
        status: 'Visible',
        type: 'Bluetooth Device',
      });
    });
    btSerial.inquire();
    // Timeout after 10s
    setTimeout(() => {
      if (!finished) {
        finished = true;
        resolve(devices);
      }
    }, 10000);
    btSerial.on('finished', function() {
      if (!finished) {
        finished = true;
        resolve(devices);
      }
    });
  });
}

// API endpoint for device data
app.get('/api/devices', async (req, res) => {
  try {
    const [wifiDevices, btDevices] = await Promise.all([
      getWifiDevices(),
      getBluetoothDevices(),
    ]);
    res.json({ wifi: wifiDevices, bluetooth: btDevices });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch devices' });
  }
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
