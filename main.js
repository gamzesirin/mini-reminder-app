const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const fs = require('fs')
const CryptoJS = require('crypto-js')
require('@electron/remote/main').initialize()

let mainWindow

function createWindow() {
	mainWindow = new BrowserWindow({
		width: 1280,
		height: 800,
		minWidth: 1024,
		minHeight: 768,
		frame: false,
		icon: path.join(__dirname, 'assets', process.platform === 'win32' ? 'icon.ico' : 'icon.png'),
		webPreferences: {
			nodeIntegration: true,
			contextIsolation: false,
			enableRemoteModule: true,
			sandbox: false,
			webSecurity: true,
			devTools: true
		}
	})

	require('@electron/remote/main').enable(mainWindow.webContents)

	mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
		callback({
			responseHeaders: {
				...details.responseHeaders,
				'Content-Security-Policy': ["default-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com"]
			}
		})
	})

	mainWindow.loadFile('index.html')

	mainWindow.webContents.on('did-finish-load', () => {
		mainWindow.webContents.executeJavaScript(`
			document.querySelectorAll('input, select, textarea').forEach(el => {
				el.removeAttribute('disabled');
				el.removeAttribute('readonly');
			});
		`)
	})

	mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
		console.error('Sayfa yükleme hatası:', errorCode, errorDescription)
	})

	mainWindow.webContents.on('console-message', (event, level, message) => {
		console.log('Renderer Process Log:', message)
	})
}

// Uygulama hazır olduğunda
app.whenReady().then(() => {
	createWindow()

	app.on('activate', () => {
		if (BrowserWindow.getAllWindows().length === 0) {
			createWindow()
		}
	})
})

// Tüm pencereler kapandığında
app.on('window-all-closed', () => {
	if (process.platform !== 'darwin') {
		app.quit()
	}
})

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
ipcMain.handle('savePassword', async (event, { title, username, email, password }) => {
	const userDataPath = app.getPath('userData')
	const passwordsPath = path.join(userDataPath, 'passwords.json')
	let passwords = []

	if (fs.existsSync(passwordsPath)) {
		passwords = JSON.parse(fs.readFileSync(passwordsPath, 'utf8'))
	}

	passwords.push({
		id: Date.now(),
		title,
		username,
		email,
		password
	})

	fs.writeFileSync(passwordsPath, JSON.stringify(passwords))
	return true
})

// Şifreleri getirme fonksiyonu
ipcMain.handle('getPasswords', async () => {
	const userDataPath = app.getPath('userData')
	const passwordsPath = path.join(userDataPath, 'passwords.json')

	if (!fs.existsSync(passwordsPath)) {
		return []
	}

	const passwords = JSON.parse(fs.readFileSync(passwordsPath, 'utf8'))
	return passwords
})

// Yedekleme fonksiyonu
ipcMain.handle('backupPasswords', async (event, { backupType }) => {
	const userDataPath = app.getPath('userData')
	const passwordsPath = path.join(userDataPath, 'passwords.json')

	if (!fs.existsSync(passwordsPath)) {
		throw new Error('Yedeklenecek veri bulunamadı!')
	}

	const backupsPath = path.join(userDataPath, 'backups')
	if (!fs.existsSync(backupsPath)) {
		fs.mkdirSync(backupsPath)
	}

	const date = new Date()
	const backupFileName = `backup_${date.getFullYear()}${(date.getMonth() + 1).toString().padStart(2, '0')}${date
		.getDate()
		.toString()
		.padStart(2, '0')}_${backupType}.json`

	const backupData = {
		passwords: JSON.parse(fs.readFileSync(passwordsPath, 'utf8')),
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
ipcMain.handle('deletePassword', async (event, { id }) => {
	const userDataPath = app.getPath('userData')
	const passwordsPath = path.join(userDataPath, 'passwords.json')

	if (!fs.existsSync(passwordsPath)) {
		throw new Error('Şifre bulunamadı!')
	}

	let passwords = JSON.parse(fs.readFileSync(passwordsPath, 'utf8'))
	passwords = passwords.filter((item) => item.id !== id)

	fs.writeFileSync(passwordsPath, JSON.stringify(passwords))
	return true
})

// Şifre güncelleme fonksiyonu
ipcMain.handle('updatePassword', async (event, { id, title, username, email, password }) => {
	const userDataPath = app.getPath('userData')
	const passwordsPath = path.join(userDataPath, 'passwords.json')

	if (!fs.existsSync(passwordsPath)) {
		throw new Error('Şifre bulunamadı!')
	}

	let passwords = JSON.parse(fs.readFileSync(passwordsPath, 'utf8'))
	passwords = passwords.map((item) => (item.id === id ? { id, title, username, email, password } : item))

	fs.writeFileSync(passwordsPath, JSON.stringify(passwords))
	return true
})
