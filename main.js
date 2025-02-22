const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const fs = require('fs')
const CryptoJS = require('crypto-js')

let mainWindow

function createWindow() {
	mainWindow = new BrowserWindow({
		width: 900,
		height: 700,
		webPreferences: {
			nodeIntegration: true,
			contextIsolation: false
		}
	})

	mainWindow.loadFile('index.html')
}

app.whenReady().then(createWindow)

app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') {
		app.quit()
	}
})

app.on('activate', () => {
	if (BrowserWindow.getAllWindows().length === 0) {
		createWindow()
	}
})

// Şifreli klasör işlemleri için gerekli fonksiyonlar
ipcMain.handle('createEncryptedFolder', async (event, { password, method }) => {
	const userDataPath = app.getPath('userData')
	const encryptedFolderPath = path.join(userDataPath, 'encrypted_passwords')

	if (!fs.existsSync(encryptedFolderPath)) {
		fs.mkdirSync(encryptedFolderPath)
	}

	// Şifreleme yöntemi ve ana şifreyi kaydet
	const config = {
		method,
		passwordHash: CryptoJS.SHA256(password).toString()
	}

	fs.writeFileSync(path.join(encryptedFolderPath, 'config.json'), JSON.stringify(config))

	return true
})

// Şifre kaydetme fonksiyonu
ipcMain.handle('savePassword', async (event, { title, username, email, password, masterPassword }) => {
	const userDataPath = app.getPath('userData')
	const encryptedFolderPath = path.join(userDataPath, 'encrypted_passwords')
	const configPath = path.join(encryptedFolderPath, 'config.json')

	// Config dosyasını kontrol et
	const config = JSON.parse(fs.readFileSync(configPath, 'utf8'))

	// Ana şifreyi doğrula
	if (CryptoJS.SHA256(masterPassword).toString() !== config.passwordHash) {
		throw new Error('Hatalı ana şifre!')
	}

	// Şifreyi encrypt et
	const encryptedData = CryptoJS.AES.encrypt(
		JSON.stringify({ title, username, email, password }),
		masterPassword
	).toString()

	// Şifreyi kaydet
	const passwordsPath = path.join(encryptedFolderPath, 'passwords.json')
	let passwords = []

	if (fs.existsSync(passwordsPath)) {
		passwords = JSON.parse(fs.readFileSync(passwordsPath, 'utf8'))
	}

	passwords.push({
		id: Date.now(),
		data: encryptedData
	})

	fs.writeFileSync(passwordsPath, JSON.stringify(passwords))
	return true
})

// Şifreleri getirme fonksiyonu
ipcMain.handle('getPasswords', async (event, masterPassword) => {
	const userDataPath = app.getPath('userData')
	const encryptedFolderPath = path.join(userDataPath, 'encrypted_passwords')
	const passwordsPath = path.join(encryptedFolderPath, 'passwords.json')
	const configPath = path.join(encryptedFolderPath, 'config.json')

	// Config dosyasını kontrol et
	const config = JSON.parse(fs.readFileSync(configPath, 'utf8'))

	// Ana şifreyi doğrula
	if (CryptoJS.SHA256(masterPassword).toString() !== config.passwordHash) {
		throw new Error('Hatalı ana şifre!')
	}

	if (!fs.existsSync(passwordsPath)) {
		return []
	}

	const passwords = JSON.parse(fs.readFileSync(passwordsPath, 'utf8'))

	// Şifreleri decrypt et
	return passwords.map((item) => {
		const decrypted = CryptoJS.AES.decrypt(item.data, masterPassword).toString(CryptoJS.enc.Utf8)
		return {
			id: item.id,
			...JSON.parse(decrypted)
		}
	})
})

// Yedekleme fonksiyonu
ipcMain.handle('backupPasswords', async (event, { masterPassword, backupType }) => {
	const userDataPath = app.getPath('userData')
	const encryptedFolderPath = path.join(userDataPath, 'encrypted_passwords')
	const passwordsPath = path.join(encryptedFolderPath, 'passwords.json')
	const configPath = path.join(encryptedFolderPath, 'config.json')

	// Config ve şifre dosyasının varlığını kontrol et
	if (!fs.existsSync(configPath) || !fs.existsSync(passwordsPath)) {
		throw new Error('Yedeklenecek veri bulunamadı!')
	}

	// Ana şifreyi doğrula
	const config = JSON.parse(fs.readFileSync(configPath, 'utf8'))
	if (CryptoJS.SHA256(masterPassword).toString() !== config.passwordHash) {
		throw new Error('Hatalı ana şifre!')
	}

	// Yedekleme klasörünü oluştur
	const backupsPath = path.join(userDataPath, 'backups')
	if (!fs.existsSync(backupsPath)) {
		fs.mkdirSync(backupsPath)
	}

	const date = new Date()
	const backupFileName = `backup_${date.getFullYear()}${(date.getMonth() + 1).toString().padStart(2, '0')}${date
		.getDate()
		.toString()
		.padStart(2, '0')}.json`

	// Yedek dosyasını oluştur
	const backupData = {
		passwords: JSON.parse(fs.readFileSync(passwordsPath, 'utf8')),
		config: config,
		backupDate: date.toISOString(),
		backupType: backupType
	}

	fs.writeFileSync(path.join(backupsPath, backupFileName), JSON.stringify(backupData))

	// Eski yedekleri temizle
	const backupFiles = fs.readdirSync(backupsPath)
	const maxBackups = {
		daily: 7, // Son 7 günlük yedek
		weekly: 4, // Son 4 haftalık yedek
		monthly: 12 // Son 12 aylık yedek
	}

	if (backupFiles.length > maxBackups[backupType]) {
		const sortedFiles = backupFiles
			.map((file) => ({
				name: file,
				time: fs.statSync(path.join(backupsPath, file)).mtime.getTime()
			}))
			.sort((a, b) => b.time - a.time)

		// En eski yedekleri sil
		sortedFiles.slice(maxBackups[backupType]).forEach((file) => {
			fs.unlinkSync(path.join(backupsPath, file.name))
		})
	}

	return true
})

// Şifre silme fonksiyonu
ipcMain.handle('deletePassword', async (event, { id, masterPassword }) => {
	const userDataPath = app.getPath('userData')
	const encryptedFolderPath = path.join(userDataPath, 'encrypted_passwords')
	const passwordsPath = path.join(encryptedFolderPath, 'passwords.json')
	const configPath = path.join(encryptedFolderPath, 'config.json')

	// Ana şifreyi doğrula
	const config = JSON.parse(fs.readFileSync(configPath, 'utf8'))
	if (CryptoJS.SHA256(masterPassword).toString() !== config.passwordHash) {
		throw new Error('Hatalı ana şifre!')
	}

	// Şifreleri oku ve güncelle
	const passwords = JSON.parse(fs.readFileSync(passwordsPath, 'utf8'))
	const updatedPasswords = passwords.filter((item) => item.id !== id)

	fs.writeFileSync(passwordsPath, JSON.stringify(updatedPasswords))
	return true
})

// Şifre güncelleme fonksiyonu
ipcMain.handle('updatePassword', async (event, { id, title, username, email, password, masterPassword }) => {
	const userDataPath = app.getPath('userData')
	const encryptedFolderPath = path.join(userDataPath, 'encrypted_passwords')
	const passwordsPath = path.join(encryptedFolderPath, 'passwords.json')
	const configPath = path.join(encryptedFolderPath, 'config.json')

	// Ana şifreyi doğrula
	const config = JSON.parse(fs.readFileSync(configPath, 'utf8'))
	if (CryptoJS.SHA256(masterPassword).toString() !== config.passwordHash) {
		throw new Error('Hatalı ana şifre!')
	}

	// Yeni veriyi şifrele
	const encryptedData = CryptoJS.AES.encrypt(
		JSON.stringify({ title, username, email, password }),
		masterPassword
	).toString()

	// Şifreleri oku ve güncelle
	const passwords = JSON.parse(fs.readFileSync(passwordsPath, 'utf8'))
	const updatedPasswords = passwords.map((item) => (item.id === id ? { id, data: encryptedData } : item))

	fs.writeFileSync(passwordsPath, JSON.stringify(updatedPasswords))
	return true
})
