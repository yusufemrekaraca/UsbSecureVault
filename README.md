# USB Secure Vault

Windows icin WPF tabanli USB dosya kasasi.

## Cikti

Tek dosya exe:

```text
bin\Release\net8.0-windows\win-x64\publish\UsbSecureVault.exe
```

Bu dosyayi USB kok dizinine kopyalayip calistirin. Ilk acilista `vault` klasoru ve ayar dosyalari exe'nin bulundugu yerde olusturulur.

## Davranis

- Ilk acilista master sifre ve hatirlatma belirlenir.
- Master giristen sonra alanlar olusturulur.
- Her alanin ayri parolasi, ayri rastgele AES-256 anahtari vardir.
- Alan parolasi AES anahtari degildir; AES anahtari alan parolasindan turetilen anahtarla sarilip saklanir.
- Dosya eklenince secilen dosyanin icerigi sifreli veriyle degistirilir, sonra `vault\users\...\files` altina rastgele isimle tasinir.
- Klasor eklenince klasor ZIP paketi olarak sifrelenir, kasaya rastgele isimle tasinir ve orijinal klasor silinir.
- Dosya isimleri ve metadata alan acilmadan okunamaz.
- Cift tiklanan dosya `vault\temp` altina gecici cozulur, varsayilan uygulamayla acilir, uygulama kapaninca degisiklikler tekrar sifreli kasaya yazilir ve temp dosya silinmeye calisilir.
- Cift tiklanan klasor `vault\temp` altina gecici acilir. Isiniz bitince uygulamadaki onay penceresinde Tamam'a basin; degisiklikler tekrar sifreli kasaya yazilir.
- Her uygulama acilisinda `vault\temp` temizlenir.
- `Bu bilgisayara guven` dugmesi Belgeler altinda bir guven dosyasi olusturur; o bilgisayarda master girisi atlanir.

## Sinirlar

- Dosya acildiginda plain kopya gecici olarak USB'deki `vault\temp` altinda bulunur.
- Dosyayi acan harici program kendi cache, recent file veya autosave verisini birakabilir.
- Parola unutulursa kurtarma yoktur.
