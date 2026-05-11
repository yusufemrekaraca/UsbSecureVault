# Karaca's USB Vault

![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![WPF](https://img.shields.io/badge/WPF-Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![AES-GCM](https://img.shields.io/badge/crypto-AES--256--GCM-111827?style=for-the-badge)
![Portable](https://img.shields.io/badge/portable-single%20exe-16A34A?style=for-the-badge)

USB bellek üzerinde çalışan, dosya ve klasörleri yerel bir kasada saklayan Windows masaüstü uygulaması. Dosyalar rastgele adlarla tutulur, metadata şifrelenir, büyük dosyalar streaming olarak işlenir ve klasörler ihtiyaç oldukça açılabilen lazy explorer arayüzüyle gezilebilir.

> Bu proje kişisel/offline taşınabilir kasa ihtiyacı için tasarlanmıştır. Profesyonel adli inceleme, donanım seviyesinde saldırılar veya işletim sistemi cache izleri için mutlak güvenlik iddiası taşımaz.

## Öne Çıkanlar

- Tek dosya Windows exe olarak yayınlanır.
- Kasa, exe'nin bulunduğu dizinde `vault` klasörü altında tutulur.
- Master şifre isteğe bağlıdır.
- Her alan için ayrı AES-256 anahtarı kullanılır.
- Alan şifresi isteğe bağlıdır; istenirse çok kısa şifreler de kullanılabilir.
- Dosya içerikleri AES-GCM ile 4 MB parçalar halinde şifrelenir.
- Klasör yapısı korunur; dosya ve klasör adları şifreli manifestte saklanır.
- Lazy folder explorer sayesinde klasörün tamamı değil, sadece açılan dosya temp'e çözülür.
- Büyük dosyalar için hızlı `Boz` modu vardır.
- Dosya ekleme sırasında progress bar ile işlem durumu gösterilir.
- Uygulama kapanırken ve yeniden açılırken temp temizliği yapılır.
- Seçili alan veya tüm kasa güvenli silme/geri çıkarma seçenekleriyle yönetilebilir.

## Ekran Akışı

1. İlk açılışta kasa oluşturulur.
2. İstersen master şifre kullanılır, istenmezse giriş ekranı atlanır.
3. Bir veya daha fazla alan oluşturulur.
4. Her alan için şifre kullanımı ayrı ayrı seçilebilir.
5. Dosya veya klasör eklenirken `Şifrele` ya da `Boz` modu seçilir.
6. Klasör açıldığında uygulama içi explorer görünümü gelir.
7. Kullanıcı bir dosyayı açınca yalnızca o dosya temp'e çıkarılır, kapandığında kasaya geri yazılır.

## Saklama Modları

| Mod | Açıklama | Ne zaman kullanılır? |
| --- | --- | --- |
| `Şifrele` | İçerik AES-256-GCM ile streaming olarak şifrelenir. | Hassas dosyalar, normal güvenli saklama |
| `Boz` | İçerik kriptografik olarak şifrelenmez; dosya rastgele adla taşınır ve baş/son bölümü maskelenir. | Çok büyük ve düşük riskli dosyaları hızlı gizleme |
| `FolderTree` | Klasör ağacı manifest ve ayrı dosya kayıtlarıyla saklanır. | Klasörleri tek tek dosya açarak kullanma |

## Güvenlik Modeli

- Kullanıcı alanı oluşturulurken rastgele bir dosya anahtarı üretilir.
- Şifre kullanılıyorsa bu anahtar, şifreden türetilen anahtarla sarılır.
- Şifre kullanılmıyorsa alan otomatik açılacak şekilde saklanır; bu kullanım kolaylığı sağlar ama fiziksel erişimi olan kişiye karşı koruma düşer.
- Dosya adları, orijinal konum, boyut ve tarih bilgileri alan anahtarıyla şifrelenmiş metadata içinde tutulur.
- Açılan dosyalar geçici olarak `vault\temp` altında plain halde bulunabilir.
- Uygulama normal kapanış, session kapanışı, process exit ve yakalanan hata yollarında temp temizliği dener.

## Kurulum

Gereksinimler:

- Windows
- .NET 8 SDK

Derleme:

```powershell
dotnet build
```

Yayın alma:

```powershell
dotnet publish -c Release -o dist\single-file
```

Deneysel lazy folder exe adıyla yayın alma:

```powershell
dotnet publish -c Release -o dist\single-file -p:AssemblyName=UsbSecureVault-LazyFolder
```

Çıktı:

```text
dist\single-file\UsbSecureVault-LazyFolder.exe
```

Exe'yi USB kök dizinine koyup çalıştırın. Kasa verileri exe'nin yanında `vault` klasöründe oluşur.

## Kullanım Notları

- `Bu bilgisayara güven` seçeneği Belgeler klasörüne trust dosyası yazar ve o bilgisayarda master girişini atlar.
- Şifre kullan seçeneği kapalıysa ilgili master/alan parolası istenmez.
- Şifre minimum uzunluk kuralı yoktur; seçim kullanıcıya bırakılır.
- Büyük dosya ekleme iki ana aşamadan oluşur: kasaya yazma ve orijinali güvenli silme.
- Güvenli silme, dosya boyutu kadar tekrar yazma yaptığı için işlem süresini uzatabilir.

## Sınırlamalar

- Harici programlar açılan dosyalar için kendi cache, recent file veya autosave izlerini bırakabilir.
- USB/SSD wear leveling nedeniyle güvenli silme fiziksel hücre düzeyinde mutlak garanti vermez.
- `Boz` modu kriptografik güvenlik sağlamaz.
- Uygulama zorla öldürülürse veya güç kesilirse kapanış temizliği çalışamayabilir; kalan temp verileri sonraki açılışta temizlenir.
- Şifre unutulursa şifreli alanlar için kurtarma yoktur.

## Proje Yapısı

```text
UsbSecureVault/
├── App.xaml(.cs)              # Uygulama yaşam döngüsü, crash log, temp temizliği
├── MainWindow.xaml(.cs)       # Ana WPF arayüzü
├── FolderBrowserWindow.cs     # Lazy klasör gezgini
├── VaultStore.cs              # Kasa, metadata, dosya/klasör işlemleri
├── CryptoService.cs           # AES-GCM, KDF ve streaming crypto
├── DialogHelpers.cs           # Dialoglar
├── Models.cs                  # Kayıt ve view modelleri
└── Assets/                    # Logo varlıkları
```

## Lisans

Henüz lisans dosyası eklenmedi. Yayınlamadan önce kullanım amacına uygun bir lisans seçin.
