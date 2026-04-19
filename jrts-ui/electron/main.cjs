const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');

let mainWindow;

function createWindow() {
  // Determine icon path — works in both dev and installed locations
  let iconPath = path.join(__dirname, '../public/jabber.png');
  if (!fs.existsSync(iconPath)) {
    iconPath = path.join(__dirname, '../jabber.png');
  }

  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 800,
    title: 'JABBER — Red Teaming Suite',
    icon: iconPath,
    backgroundColor: '#0d1117',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0d1117',
      symbolColor: '#ff4444',
      height: 36,
    },
    frame: true,
    autoHideMenuBar: true,
    show: false,  // Don't show until ready — avoids blank flash
  });

  const isDev = process.env.NODE_ENV === 'development' || process.argv.includes('--dev');

  if (isDev) {
    // Dev mode: load from Vite dev server
    mainWindow.loadURL('http://localhost:5173').catch(err => {
      console.error('Failed to load dev server:', err.message);
      console.error('Ensure frontend is running on port 5173');
    });
  } else {
    // Production mode: EXACTLY matching jabber web
    // The bash wrapper ensures backend is online before this runs!
    console.log("Loading frontend securely from backend proxy: http://localhost:8314");
    mainWindow.loadURL('http://localhost:8314').catch(err => {
      console.error('Failed to connect securely to backend:', err.message);
    });
  }

  // Show window when content is ready — prevents blank flash
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
