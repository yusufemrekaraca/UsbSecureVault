# USB Secure Vault

Windows için WPF tabanlı USB dosya kasası.

## Çıktı

Tek dosya exe:

```text
bin\Release\net8.0-windows\win-x64\publish\UsbSecureVault.exe
```

Bu dosyayı USB kök dizinine kopyalayıp çalıştırın. İlk açılışta `vault` klasörü ve ayar dosyaları exe'nin bulunduğu yerde oluşturulur.

## Davranış

- İlk açılışta master şifre ve hatırlatma belirlenir.
- Master girişten sonra alanlar oluşturulur.
- Her alanın ayrı parolası, ayrı rastgele AES-256 anahtarı vardır.
- Alan parolası AES anahtarı değildir; AES anahtarı alan parolasından türetilen anahtarla sarılıp saklanır.
- Dosya veya klasör eklerken `Şifrele` ya da `Boz` modu seçilir.
- Dosya eklenince seçilen dosyanın içeriği şifreli veriyle değiştirilir, sonra `vault\users\...\files` altına rastgele isimle taşınır.
- Klasör eklenince klasör ZIP paketi olarak şifrelenir, kasaya rastgele isimle taşınır ve orijinal klasör silinir.
- `Boz` modu büyük dosya ve klasörler için hızlıdır; içerik şifrelenmez, öğe rastgele ad ve uzantıyla kasaya taşınır. Uygulama bu kayıtları `Boz` olarak tanır.
- Dosya isimleri ve metadata alan açılmadan okunamaz.
- Çift tıklanan dosya `vault\temp` altına geçici çözülür, varsayılan uygulamayla açılır, uygulama kapanınca değişiklikler tekrar şifreli kasaya yazılır ve temp dosya silinmeye çalışılır.
- Çift tıklanan klasör `vault\temp` altına geçici açılır. İşiniz bitince uygulamadaki onay penceresinde Tamam'a basın; değişiklikler tekrar şifreli kasaya yazılır.
- Seçili alan silinirken içerikleri eski yerlerine geri koyma veya File Shredder ile kalıcı silme seçilebilir.
- Tüm kasa tek işlemle silinebilir; istenirse tüm alanlardaki içerikler eski yerlerine geri koyulur.
- Her uygulama açılışında `vault\temp` temizlenir.
- `Bu bilgisayara güven` düğmesi Belgeler altında bir güven dosyası oluşturur; o bilgisayarda master girişi atlanır.

## Sınırlar

- Dosya açıldığında plain kopya geçici olarak USB'deki `vault\temp` altında bulunur.
- Dosyayı açan harici program kendi cache, recent file veya autosave verisini bırakabilir.
- `Boz` modu kriptografik koruma değildir; profesyonel incelemeye karşı güvenlik sağlamaz, sadece hızlı gizleme/karmaşıklaştırma sunar.
- File Shredder dosyayı aynı uzunlukta üzerine yazarak siler ve ekstra disk alanı kullanmaz; USB/SSD wear leveling nedeniyle fiziksel hücre düzeyinde mutlak silme garantisi vermez.
- Parola unutulursa kurtarma yoktur.
