const sharp = require('sharp')
const fs = require('fs')
const path = require('path')

const svgPath = path.join(__dirname, '..', 'assets', 'icon.svg')
const pngPath = path.join(__dirname, '..', 'assets', 'icon.png')
const icoPath = path.join(__dirname, '..', 'assets', 'icon.ico')

// SVG'yi PNG'ye dönüştür
sharp(svgPath)
	.resize(256, 256)
	.png()
	.toBuffer()
	.then((data) => {
		// PNG dosyasını kaydet
		fs.writeFileSync(pngPath, data)
		console.log('PNG oluşturuldu')

		// PNG'yi ICO'ya dönüştür
		sharp(pngPath)
			.resize(256, 256)
			.toFormat('ico')
			.toBuffer()
			.then((icoData) => {
				fs.writeFileSync(icoPath, icoData)
				console.log('ICO oluşturuldu')
			})
			.catch((err) => console.error('ICO oluşturma hatası:', err))
	})
	.catch((err) => console.error('PNG oluşturma hatası:', err))
