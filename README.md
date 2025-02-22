# Şifre Yöneticisi Uygulaması

Bu uygulama, kullanıcıların şifrelerini güvenli bir şekilde yönetmelerine olanak sağlayan bir Electron tabanlı masaüstü uygulamasıdır.

## Özellikler

- 🔐 AES veya DES şifreleme yöntemleriyle güvenli veri saklama
- 👤 Kullanıcı adı, e-posta ve şifre bilgilerini saklama
- 🔄 Şifre kayıtlarını düzenleme ve silme
- 💾 Otomatik yedekleme sistemi (Günlük, Haftalık, Aylık)
- 🎨 Modern ve kullanıcı dostu arayüz (Tailwind CSS)

## Veri Depolama

Uygulama, verileri işletim sisteminin kullanıcıya özel uygulama veri dizininde saklar:

- **Windows:** `C:\Users\[Kullanıcı Adı]\AppData\Roaming\password-manager`
- **macOS:** `~/Library/Application Support/password-manager`
- **Linux:** `~/.config/password-manager`

Dosya yapısı:

- `passwords.json`: Şifrelenmiş şifre kayıtları
- `config.json`: Şifreleme yöntemi ve ana şifre hash'i
- `backups/`: Yedekleme dosyaları
  - `backup_YYYYMMDD.json`: Tarih formatında yedek dosyaları

## Kurulum

### Gereksinimler

- Node.js (v14 veya üzeri)
- npm (Node Package Manager)

### Kurulum Adımları

1. Projeyi klonlayın:

```bash
git clone [repo-url]
cd password-manager
```

2. Bağımlılıkları yükleyin:

```bash
npm install
```

3. Uygulamayı başlatın:

```bash
npm start
```

## Kullanım

### İlk Kurulum

1. Uygulama ilk açıldığında, bir şifreleme yöntemi (AES veya DES) seçin
2. Ana şifrenizi belirleyin
3. "Kurulumu Tamamla" butonuna tıklayın

### Şifre Yönetimi

- **Yeni Şifre Ekleme:**

  - "Yeni Şifre Ekle" formunu doldurun
  - Başlık ve şifre alanları zorunludur
  - Kullanıcı adı ve e-posta isteğe bağlıdır
  - "Kaydet" butonuna tıklayın

- **Şifre Düzenleme:**

  - Mevcut bir şifre kaydının yanındaki "Düzenle" butonuna tıklayın
  - Bilgileri güncelleyin
  - "Güncelle" butonuna tıklayın

- **Şifre Silme:**
  - Silmek istediğiniz kaydın yanındaki "Sil" butonuna tıklayın
  - Onay verdikten sonra kayıt silinecektir

### Yedekleme

Uygulama üç farklı yedekleme seçeneği sunar:

- **Günlük Yedek:** Son 7 günün yedeğini saklar
- **Haftalık Yedek:** Son 4 haftanın yedeğini saklar
- **Aylık Yedek:** Son 12 ayın yedeğini saklar

## Teknik Detaylar

### Kullanılan Teknolojiler

- **Electron:** Masaüstü uygulama geliştirme framework'ü
- **Tailwind CSS:** UI tasarımı için kullanılan CSS framework'ü
- **CryptoJS:** Şifreleme işlemleri için kullanılan kütüphane

### Dosya Yapısı

- `main.js`: Electron ana işlem dosyası
- `index.html`: İlk kurulum ekranı
- `passwords.html`: Ana uygulama arayüzü
- `package.json`: Proje bağımlılıkları ve yapılandırması

### Güvenlik

- Şifreler yerel dosya sisteminde şifrelenmiş olarak saklanır
- Content Security Policy (CSP) ile güvenli kaynak kullanımı
- Ana şifre SHA-256 ile hash'lenerek saklanır

## Geliştirme

### Geliştirme Ortamını Başlatma

```bash
npm start
```

### Uygulama Derleme

```bash
npm run build
```

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır.
