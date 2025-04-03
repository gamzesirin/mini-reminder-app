const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ethers } = require('ethers');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'sifre-yoneticisi-gizli-anahtar',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 1 gün
}));

// Veri klasörü kontrolü
const dataDir = path.join(__dirname, 'data');
const usersDir = path.join(dataDir, 'users');

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

if (!fs.existsSync(usersDir)) {
  fs.mkdirSync(usersDir);
}

// Yardımcı fonksiyonlar
function getUserDir(userId) {
  return path.join(usersDir, userId);
}

function getPasswordsFile(userId) {
  return path.join(getUserDir(userId), 'passwords.json');
}

function getSetupFile(userId) {
  return path.join(getUserDir(userId), 'setup.json');
}

function getMetaMaskFile(address) {
  return path.join(usersDir, 'metamask-' + address.toLowerCase() + '.json');
}

function createUserDirectory(userId) {
  const userDir = getUserDir(userId);
  if (!fs.existsSync(userDir)) {
    fs.mkdirSync(userDir);
  }
  return userDir;
}

function hashPassword(password, method = 'AES') {
  return crypto.createHash('sha256').update(password + method).digest('hex');
}

// Ethereum imza doğrulama fonksiyonu
function verifyEthereumSignature(message, signature, address) {
  try {
    console.log('Doğrulama bilgileri:');
    console.log('Mesaj:', message);
    console.log('İmza:', signature);
    console.log('Adres:', address);
    
    // Düz metni doğrudan kullan
    const signerAddress = ethers.utils.verifyMessage(message, signature);
    console.log('İmzalayan adres:', signerAddress);
    
    // İmzalayan adresin beklenen adres olup olmadığını kontrol et
    const result = signerAddress.toLowerCase() === address.toLowerCase();
    console.log('Doğrulama sonucu:', result);
    
    return result;
  } catch (error) {
    console.error('İmza doğrulama hatası:', error);
    return false;
  }
}

// Oturum kontrolü middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Oturum açmanız gerekiyor!' });
  }
  next();
}

// API Rotaları

// Oturum kontrolü
app.get('/api/auth/check', (req, res) => {
  if (req.session.userId) {
    return res.status(200).json({ authenticated: true });
  }
  res.status(401).json({ authenticated: false });
});

// Kurulum kontrolü
app.get('/api/setup-status', (req, res) => {
  try {
    if (req.session.userId) {
      const setupFile = getSetupFile(req.session.userId);
      if (fs.existsSync(setupFile)) {
        return res.json({ isComplete: true });
      }
    }
    
    // Kullanıcı giriş yapmış ama kurulum yok veya kullanıcı giriş yapmamış
    res.json({ isComplete: false });
  } catch (error) {
    res.status(500).json({ error: 'Kurulum durumu kontrol edilirken bir hata oluştu.' });
  }
});

// Kurulum
app.post('/api/setup', (req, res) => {
  try {
    const { encryptionMethod, masterPassword } = req.body;
    
    if (!encryptionMethod || !masterPassword) {
      return res.status(400).json({ error: 'Şifreleme yöntemi ve ana şifre gereklidir.' });
    }
    
    // Kullanıcı ID oluştur (basit bir UUID benzeri)
    const userId = crypto.randomBytes(16).toString('hex');
    
    // Kullanıcı dizini oluştur
    const userDir = createUserDirectory(userId);
    
    // Ana şifreyi hashle ve setup bilgisini kaydet
    const hashedPassword = hashPassword(masterPassword, encryptionMethod);
    const setupData = {
      encryptionMethod,
      passwordHash: hashedPassword,
      createdAt: new Date().toISOString()
    };
    
    fs.writeFileSync(getSetupFile(userId), JSON.stringify(setupData));
    fs.writeFileSync(getPasswordsFile(userId), JSON.stringify([]));
    
    // Oturum bilgisini ayarla
    req.session.userId = userId;
    req.session.encryptionMethod = encryptionMethod;
    
    res.json({ success: true, userId: userId });
  } catch (error) {
    console.error('Kurulum hatası:', error);
    res.status(500).json({ error: 'Kurulum sırasında bir hata oluştu.' });
  }
});

// Giriş
app.post('/api/login', (req, res) => {
  try {
    const { masterPassword, userId } = req.body;
    
    if (!userId || !masterPassword) {
      return res.status(400).json({ error: 'Kullanıcı ID ve ana şifre gereklidir.' });
    }
    
    const setupFile = getSetupFile(userId);
    
    if (!fs.existsSync(setupFile)) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
    }
    
    const setupData = JSON.parse(fs.readFileSync(setupFile, 'utf8'));
    const hashedPassword = hashPassword(masterPassword, setupData.encryptionMethod);
    
    if (hashedPassword !== setupData.passwordHash) {
      return res.status(401).json({ error: 'Yanlış şifre!' });
    }
    
    // Oturum bilgilerini ayarla
    req.session.userId = userId;
    req.session.encryptionMethod = setupData.encryptionMethod;
    
    res.json({ success: true });
  } catch (error) {
    console.error('Giriş hatası:', error);
    res.status(500).json({ error: 'Giriş sırasında bir hata oluştu.' });
  }
});

// MetaMask ile Giriş
app.post('/api/login/metamask', (req, res) => {
  try {
    const { address, message, signature } = req.body;
    
    if (!address || !message || !signature) {
      return res.status(400).json({ error: 'Adres, mesaj ve imza gereklidir.' });
    }
    
    // İmzayı doğrula
    const isSignatureValid = verifyEthereumSignature(message, signature, address);
    
    if (!isSignatureValid) {
      return res.status(401).json({ error: 'Geçersiz imza!' });
    }
    
    // Adrese bağlı kullanıcı bilgisi var mı kontrol et
    const metaMaskFile = getMetaMaskFile(address);
    let userId;
    
    if (fs.existsSync(metaMaskFile)) {
      // Varolan MetaMask kullanıcısı
      const userData = JSON.parse(fs.readFileSync(metaMaskFile, 'utf8'));
      userId = userData.userId;
    } else {
      // Yeni MetaMask kullanıcısı ise, yeni bir kullanıcı oluştur
      userId = crypto.randomBytes(16).toString('hex');
      
      // Kullanıcı dizini oluştur
      const userDir = createUserDirectory(userId);
      
      // MetaMask kullanıcı bilgisini kaydet
      const userData = {
        userId,
        address: address.toLowerCase(),
        createdAt: new Date().toISOString()
      };
      
      fs.writeFileSync(metaMaskFile, JSON.stringify(userData));
      fs.writeFileSync(getPasswordsFile(userId), JSON.stringify([]));
      
      // Kurulum bilgisini de kaydet (MetaMask için)
      const setupData = {
        encryptionMethod: 'AES', // Varsayılan şifreleme yöntemi
        isMetaMask: true,
        createdAt: new Date().toISOString()
      };
      
      fs.writeFileSync(getSetupFile(userId), JSON.stringify(setupData));
    }
    
    // Oturum bilgisini ayarla
    req.session.userId = userId;
    req.session.metaMaskAddress = address.toLowerCase();
    
    res.json({ success: true });
  } catch (error) {
    console.error('MetaMask giriş hatası:', error);
    res.status(500).json({ error: 'MetaMask ile giriş sırasında bir hata oluştu.' });
  }
});

// Çıkış
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Şifreleri getir
app.get('/api/passwords', requireAuth, (req, res) => {
  try {
    const passwordsFile = getPasswordsFile(req.session.userId);
    
    if (!fs.existsSync(passwordsFile)) {
      return res.json([]);
    }
    
    const passwords = JSON.parse(fs.readFileSync(passwordsFile, 'utf8'));
    res.json(passwords);
  } catch (error) {
    console.error('Şifreleri getirme hatası:', error);
    res.status(500).json({ error: 'Şifreler yüklenirken bir hata oluştu.' });
  }
});

// Yeni şifre ekle
app.post('/api/passwords', requireAuth, (req, res) => {
  try {
    const { title, username, email, password } = req.body;
    
    if (!title || !password) {
      return res.status(400).json({ error: 'Başlık ve şifre zorunludur.' });
    }
    
    const passwordsFile = getPasswordsFile(req.session.userId);
    let passwords = [];
    
    if (fs.existsSync(passwordsFile)) {
      passwords = JSON.parse(fs.readFileSync(passwordsFile, 'utf8'));
    }
    
    // Yeni şifre oluştur
    const newPassword = {
      id: Date.now(),
      title,
      username: username || '',
      email: email || '',
      password,
      createdAt: new Date().toISOString()
    };
    
    passwords.push(newPassword);
    fs.writeFileSync(passwordsFile, JSON.stringify(passwords));
    
    res.json({ success: true, passwordId: newPassword.id });
  } catch (error) {
    console.error('Şifre ekleme hatası:', error);
    res.status(500).json({ error: 'Şifre eklenirken bir hata oluştu.' });
  }
});

// Şifre güncelle
app.put('/api/passwords/:id', requireAuth, (req, res) => {
  try {
    const passwordId = parseInt(req.params.id);
    const { title, username, email, password } = req.body;
    
    if (!title || !password) {
      return res.status(400).json({ error: 'Başlık ve şifre zorunludur.' });
    }
    
    const passwordsFile = getPasswordsFile(req.session.userId);
    
    if (!fs.existsSync(passwordsFile)) {
      return res.status(404).json({ error: 'Şifre bulunamadı.' });
    }
    
    let passwords = JSON.parse(fs.readFileSync(passwordsFile, 'utf8'));
    const passwordIndex = passwords.findIndex(p => p.id === passwordId);
    
    if (passwordIndex === -1) {
      return res.status(404).json({ error: 'Şifre bulunamadı.' });
    }
    
    // Şifreyi güncelle
    passwords[passwordIndex] = {
      ...passwords[passwordIndex],
      title,
      username: username || '',
      email: email || '',
      password,
      updatedAt: new Date().toISOString()
    };
    
    fs.writeFileSync(passwordsFile, JSON.stringify(passwords));
    
    res.json({ success: true });
  } catch (error) {
    console.error('Şifre güncelleme hatası:', error);
    res.status(500).json({ error: 'Şifre güncellenirken bir hata oluştu.' });
  }
});

// Şifre sil
app.delete('/api/passwords/:id', requireAuth, (req, res) => {
  try {
    const passwordId = parseInt(req.params.id);
    const passwordsFile = getPasswordsFile(req.session.userId);
    
    if (!fs.existsSync(passwordsFile)) {
      return res.status(404).json({ error: 'Şifre bulunamadı.' });
    }
    
    let passwords = JSON.parse(fs.readFileSync(passwordsFile, 'utf8'));
    const passwordIndex = passwords.findIndex(p => p.id === passwordId);
    
    if (passwordIndex === -1) {
      return res.status(404).json({ error: 'Şifre bulunamadı.' });
    }
    
    // Şifreyi kaldır
    passwords.splice(passwordIndex, 1);
    fs.writeFileSync(passwordsFile, JSON.stringify(passwords));
    
    res.json({ success: true });
  } catch (error) {
    console.error('Şifre silme hatası:', error);
    res.status(500).json({ error: 'Şifre silinirken bir hata oluştu.' });
  }
});

// Yedekleme oluştur
app.post('/api/backup', requireAuth, (req, res) => {
  try {
    console.log('Yedekleme isteği alındı:', req.body);
    
    const { backupType } = req.body;
    
    if (!['daily', 'weekly', 'monthly'].includes(backupType)) {
      console.log('Geçersiz yedekleme türü:', backupType);
      return res.status(400).json({ error: 'Geçersiz yedekleme türü.' });
    }
    
    const userDir = getUserDir(req.session.userId);
    console.log('Kullanıcı dizini:', userDir);
    
    const passwordsFile = getPasswordsFile(req.session.userId);
    console.log('Şifre dosyası:', passwordsFile);
    
    const backupsDir = path.join(userDir, 'backups');
    console.log('Yedekleme dizini:', backupsDir);
    
    if (!fs.existsSync(backupsDir)) {
      console.log('Yedekleme dizini oluşturuluyor');
      fs.mkdirSync(backupsDir);
    }
    
    if (!fs.existsSync(passwordsFile)) {
      console.log('Şifre dosyası bulunamadı');
      return res.status(404).json({ error: 'Yedeklenecek şifre bulunamadı.' });
    }
    
    // Yedek dosyasını oluştur
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const backupFile = path.join(backupsDir, `backup-${backupType}-${timestamp}.json`);
    console.log('Yedek dosyası oluşturuluyor:', backupFile);
    
    fs.copyFileSync(passwordsFile, backupFile);
    console.log('Yedekleme başarılı');
    
    res.json({ success: true, backupFile: path.basename(backupFile) });
  } catch (error) {
    console.error('Yedekleme hatası:', error);
    res.status(500).json({ error: 'Yedekleme sırasında bir hata oluştu: ' + error.message });
  }
});

// Kullanıcı bilgisi
app.get('/api/user', requireAuth, (req, res) => {
  try {
    const setupFile = getSetupFile(req.session.userId);
    
    if (!fs.existsSync(setupFile)) {
      return res.status(404).json({ error: 'Kullanıcı bilgisi bulunamadı.' });
    }
    
    const setupData = JSON.parse(fs.readFileSync(setupFile, 'utf8'));
    
    const userData = {
      userId: req.session.userId,
      encryptionMethod: setupData.encryptionMethod,
      createdAt: setupData.createdAt
    };
    
    // Eğer MetaMask ile giriş yapılmışsa adres bilgisini de ekle
    if (req.session.metaMaskAddress) {
      userData.metaMaskAddress = req.session.metaMaskAddress;
      userData.isMetaMask = true;
    }
    
    res.json(userData);
  } catch (error) {
    console.error('Kullanıcı bilgisi hatası:', error);
    res.status(500).json({ error: 'Kullanıcı bilgisi alınırken bir hata oluştu.' });
  }
});

// Kurulum durumu kontrolü için
app.get('/api/config', (req, res) => {
  try {
    // Herhangi bir kullanıcı var mı diye kontrol et
    const users = fs.readdirSync(usersDir);
    
    if (users.length > 0) {
      // En az bir kullanıcı var
      res.status(200).json({ 
        isSetup: true,
        message: "Kurulum yapılmış. Lütfen giriş yapın." 
      });
    } else {
      // Henüz kullanıcı yok
      res.status(404).json({ 
        isSetup: false,
        message: "Kurulum yapılmamış. Lütfen kurulum yapın." 
      });
    }
  } catch (error) {
    console.error('Konfigürasyon kontrolü hatası:', error);
    res.status(500).json({ error: 'Konfigürasyon durumu kontrol edilirken bir hata oluştu.' });
  }
});

// Yedekleme listesini getir
app.get('/api/backups', requireAuth, (req, res) => {
  try {
    const userDir = getUserDir(req.session.userId);
    const backupsDir = path.join(userDir, 'backups');
    
    if (!fs.existsSync(backupsDir)) {
      return res.json([]);
    }
    
    // Tüm yedek dosyalarını oku
    const backupFiles = fs.readdirSync(backupsDir)
      .filter(file => file.endsWith('.json'))
      .map(file => {
        const fullPath = path.join(backupsDir, file);
        const stats = fs.statSync(fullPath);
        
        // Dosya adından yedekleme türü (daily/weekly/monthly) çıkar
        const backupType = file.includes('-daily-') 
          ? 'daily' 
          : file.includes('-weekly-') 
            ? 'weekly' 
            : 'monthly';
            
        return {
          filename: file,
          type: backupType,
          createdAt: stats.birthtime,
          size: stats.size
        };
      })
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)); // En yeniden eskiye sırala
    
    res.json(backupFiles);
  } catch (error) {
    console.error('Yedekleme listesi hatası:', error);
    res.status(500).json({ error: 'Yedekleme listesi alınırken bir hata oluştu: ' + error.message });
  }
});

// Sunucuyu başlat
app.listen(PORT, () => {
  console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
}); 