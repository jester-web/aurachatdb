const { app, BrowserWindow, ipcMain, session } = require('electron');
const path = require('path');
const { autoUpdater } = require('electron-updater');
const pjson = require('./package.json'); // 💡 YENİ: package.json dosyasını okumak için

let mainWindow;
let splashWindow;

function createWindow() {
  // Ana uygulama penceresini oluştur
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 650,
    // 💡 YENİ SATIR: Pencere ve görev çubuğu ikonunu ayarlar. Proje ana dizininde 'icon.png' olmalıdır.
    icon: path.join(__dirname, 'icon.png'),
    // 💡 YENİ SATIR: Çerçeveyi ve menü çubuğunu kaldırır.
    frame: false, 
    // --------------------------izin--------------------------
    show: false, // Başlangıçta titremeyi önlemek için gizle
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false 
    }
  });

  // 💡 YENİ: Açılış ekranı (splash) penceresini oluştur.
  splashWindow = new BrowserWindow({
    width: 400,
    height: 300,
    transparent: true,
    frame: false,
    alwaysOnTop: true,
    icon: path.join(__dirname, 'icon.png'),
  });
  splashWindow.loadFile('splash.html');

  // Ana pencere içeriği yüklendiğinde, açılış ekranını kapat ve ana pencereyi göster
  mainWindow.once('ready-to-show', () => { 
    // Yüklemenin çok hızlı bitmesi durumunda bile splash'in kısa bir süre görünmesi için küçük bir gecikme ekle.
    setTimeout(() => {
        if (splashWindow) {
            splashWindow.destroy();
        }
        mainWindow.show(); // 💡 DÜZELTME: Ana pencereyi burada göster.
    }, 4500); // 4.5 saniye bekle
  });

  // 💡 YENİ: Pencere yüklendiğinde, uygulama versiyonunu arayüze gönder.
  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.send('app-version', pjson.version);
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));  
  // 💡 YENİ: Medya erişim izinlerini yönetmek için en kararlı yöntem.
  // Bu handler, arayüzden gelen izin isteklerini yakalar ve callback ile yanıtlar.
  session.defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    // 'media' izni istendiğinde otomatik olarak onayla.
    // Bu, getUserMedia'nın işletim sistemi düzeyinde izin istemesini tetikler.
    if (permission === 'media') {
      return callback(true);
    }
    // Diğer tüm izinleri varsayılan olarak reddet
    return callback(false);
  });
  
  // --- OTOMATİK GÜNCELLEME ---
  // Geliştirme ortamında loglamayı etkinleştir
  autoUpdater.logger = require("electron-log");
  autoUpdater.logger.transports.file.level = "info";  
  
  // 💡 DÜZELTME: Otomatik bildirimleri devre dışı bırakıp manuel kontrol sağlıyoruz.
  // autoUpdater.checkForUpdatesAndNotify();

  autoUpdater.on('update-available', () => {
    console.log('[Updater] Yeni bir güncelleme mevcut.');
    // Bu olayı dinleyerek arayüzde "Güncelleme bulunuyor..." gibi bir mesaj gösterebilirsiniz.
  });

  autoUpdater.on('update-downloaded', () => {
    console.log('[Updater] Yeni güncelleme indirildi. Arayüze haber veriliyor.');
    // 💡 YENİ: Güncelleme indirildiğinde arayüze haber ver.
    mainWindow.webContents.send('update-ready');
  });

  autoUpdater.on('error', (err) => {
    console.error('[Updater] Güncelleme sırasında hata:', err);
  });
  
  // 💡 YENİ: Arayüzden gelen yeniden başlatma isteğini dinle
  ipcMain.on('restart-and-update', () => {
    autoUpdater.quitAndInstall();
  });

  // 💡 YENİ: Arayüzden gelen "Güncellemeleri Kontrol Et" isteğini dinle
  ipcMain.on('check-for-updates', () => {
    mainWindow.webContents.send('update-check-status', 'Güncellemeler kontrol ediliyor...');
    autoUpdater.checkForUpdates();
  });

  autoUpdater.on('checking-for-update', () => {
    console.log('[Updater] Güncelleme kontrol ediliyor...');
  });

  // Pencere kontrol olaylarını dinle
  ipcMain.on('minimize-app', () => {
    mainWindow.minimize();
  });

  ipcMain.on('maximize-app', () => {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  });
  ipcMain.on('close-app', () => {
    mainWindow.close();
  });

  // 💡 YENİ: Arayüzden gelen okunmamış mesaj sayısını dinle ve tepsi ikonuna yansıt.
  ipcMain.on('update-badge', (event, count) => {
    app.setBadgeCount(count);
  });
}

app.whenReady().then(() => {
  createWindow();
  
  // 💡 YENİ: Uygulama hazır olduğunda güncelleme kontrolünü başlat.
  autoUpdater.checkForUpdates();

  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});
