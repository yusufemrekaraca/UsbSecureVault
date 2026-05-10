using Microsoft.Win32;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.IO;

namespace UsbSecureVault;

public partial class MainWindow : Window
{
    private readonly VaultStore _store = new();
    private List<UserRecord> _users = [];
    private UserRecord? _selectedUser;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += MainWindow_Loaded;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _store.EnsureFolders();
            _store.CleanTemp();

            if (!_store.IsInitialized)
            {
                ShowSetup();
                return;
            }

            _store.LoadConfig();
            if (_store.IsTrustedComputer())
            {
                ShowVault();
            }
            else
            {
                ShowMasterLogin();
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Başlatma hatası", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SetupButton_Click(object sender, RoutedEventArgs e)
    {
        if (SetupPasswordBox.Password.Length < 8)
        {
            MessageBox.Show(this, "Master şifre en az 8 karakter olmalı.", "Zayıf şifre", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (SetupPasswordBox.Password != SetupPasswordConfirmBox.Password)
        {
            MessageBox.Show(this, "Master şifreler eşleşmiyor.", "Hatalı giriş", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            _store.Initialize(SetupPasswordBox.Password, SetupHintBox.Text, SetupEmergencyInfoBox.Text);
            ClearPasswordBoxes();
            ShowVault();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Kurulum hatası", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void MasterLoginButton_Click(object sender, RoutedEventArgs e)
    {
        if (_store.VerifyMaster(MasterPasswordBox.Password))
        {
            MasterPasswordBox.Clear();
            ShowVault();
            return;
        }

        MessageBox.Show(this, "Master şifre hatalı.", "Giriş başarısız", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void EmergencyInfoButton_Click(object sender, RoutedEventArgs e)
    {
        var config = _store.Config ?? _store.LoadConfig();
        var emergencyInfo = DialogHelpers.PromptMultilineText(
            this,
            "Emergency Info",
            "USB bulunursa gösterilecek mesaj",
            config.EmergencyInfo);

        if (emergencyInfo is null)
        {
            return;
        }

        try
        {
            _store.UpdateEmergencyInfo(emergencyInfo);
            RefreshEmergencyInfoBanner();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Emergency info kaydedilemedi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void TrustButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _store.TrustThisComputer();
            MessageBox.Show(this, "Bu bilgisayar için güven dosyası Belgeler klasörüne oluşturuldu.", "Tamamlandı", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Güven dosyası oluşturulamadı", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void LogoutButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var user in _users)
        {
            if (user.UnlockedKey is not null)
            {
                CryptographicOperations.ZeroMemory(user.UnlockedKey);
                user.UnlockedKey = null;
            }
        }

        _selectedUser = null;
        FilesList.ItemsSource = null;
        UsersList.SelectedItem = null;
        if (_store.IsInitialized && _store.IsTrustedComputer())
        {
            ShowVault();
        }
        else if (_store.IsInitialized)
        {
            ShowMasterLogin();
        }
        else
        {
            ShowSetup();
        }
    }

    private void CreateUserButton_Click(object sender, RoutedEventArgs e)
    {
        var input = DialogHelpers.PromptCreateUser(this);
        if (input is null)
        {
            return;
        }

        try
        {
            if (_users.Any(user => string.Equals(user.Name, input.Name, StringComparison.CurrentCultureIgnoreCase)))
            {
                MessageBox.Show(this, "Bu isimde bir alan zaten var.", "Alan mevcut", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var user = _store.CreateUser(input.Name, input.Password, input.Hint);
            _users.Add(user);
            RefreshUsers();
            UsersList.SelectedItem = UsersList.Items.Cast<UserListItem>().First(item => item.Id == user.Id);
            LoadSelectedUserFiles();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Alan oluşturulamadı", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void UsersList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (UsersList.SelectedItem is not UserListItem item)
        {
            DeleteUserButton.IsEnabled = false;
            return;
        }

        _selectedUser = _users.FirstOrDefault(user => user.Id == item.Id);
        if (_selectedUser is null)
        {
            DeleteUserButton.IsEnabled = false;
            return;
        }

        if (_selectedUser.UnlockedKey is null)
        {
            var password = DialogHelpers.PromptPassword(this, $"{_selectedUser.Name} Girişi", "Alan şifresi", _selectedUser.PasswordHint);
            if (password is null)
            {
                UsersList.SelectedItem = null;
                return;
            }

            if (!_store.TryUnlockUser(_selectedUser, password, out var error))
            {
                MessageBox.Show(this, error, "Giriş başarısız", MessageBoxButton.OK, MessageBoxImage.Warning);
                UsersList.SelectedItem = null;
                return;
            }
        }

        DeleteUserButton.IsEnabled = true;
        LoadSelectedUserFiles();
    }

    private void DeleteUserButton_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedUser is null)
        {
            return;
        }

        var result = MessageBox.Show(
            this,
            $"'{_selectedUser.Name}' alanı silinsin mi?\n\nEvet: İçindekileri eski yerlerine geri koy ve alanı sil.\nHayır: İçindekileri File Shredder ile kalıcı sil.\nİptal: Vazgeç.",
            "Alanı sil",
            MessageBoxButton.YesNoCancel,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Cancel)
        {
            return;
        }

        var restoreContents = result == MessageBoxResult.Yes;
        if (restoreContents && !EnsureUserUnlocked(_selectedUser))
        {
            return;
        }

        try
        {
            var deletedUser = _selectedUser;
            _store.DeleteUser(deletedUser, restoreContents);
            if (deletedUser.UnlockedKey is not null)
            {
                CryptographicOperations.ZeroMemory(deletedUser.UnlockedKey);
                deletedUser.UnlockedKey = null;
            }

            _users.RemoveAll(user => user.Id == deletedUser.Id);
            _selectedUser = null;
            UsersList.SelectedItem = null;
            RefreshUsers();
            ResetFilePanel();
            MessageBox.Show(this, "Alan silindi.", "Tamamlandı", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Alan silinemedi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void AddFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedUser?.UnlockedKey is null)
        {
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "Şifrelenecek dosyayı seç",
            InitialDirectory = _store.AppRoot,
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var sourcePath = dialog.FileName;
        if (!IsAllowedSourcePath(sourcePath, out var validationMessage))
        {
            MessageBox.Show(this, validationMessage, "Geçersiz seçim", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            _store.AddFile(_selectedUser, sourcePath);
            LoadSelectedUserFiles();
            MessageBox.Show(this, "Dosya şifrelendi ve kasaya taşındı. Orijinal konumda plain dosya kalmadı.", "Tamamlandı", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Dosya eklenemedi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void AddFolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedUser?.UnlockedKey is null)
        {
            return;
        }

        var dialog = new OpenFolderDialog
        {
            Title = "Şifrelenecek klasörü seç",
            InitialDirectory = _store.AppRoot
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var sourcePath = dialog.FolderName;
        if (!IsAllowedSourcePath(sourcePath, out var validationMessage))
        {
            MessageBox.Show(this, validationMessage, "Geçersiz seçim", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            _store.AddFolder(_selectedUser, sourcePath);
            LoadSelectedUserFiles();
            MessageBox.Show(this, "Klasör şifrelendi ve kasaya taşındı. Orijinal konumda plain klasör kalmadı.", "Tamamlandı", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Klasör eklenemedi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void FilesList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (FilesList.SelectedItem is not FileListItem item || _selectedUser?.UnlockedKey is null)
        {
            return;
        }

        try
        {
            if (item.Metadata.IsFolder)
            {
                var tempFolder = _store.DecryptFolderToTemp(_selectedUser, item.Record);
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(tempFolder) { UseShellExecute = true });
                MessageBox.Show(this, "Klasördeki işiniz bitince Tamam'a basın. Değişiklikler tekrar şifreli kasaya yazılacak.", "Klasör açık", MessageBoxButton.OK, MessageBoxImage.Information);
                _store.SaveFolderBackAndClean(_selectedUser, item.Record, tempFolder);
                LoadSelectedUserFiles();
            }
            else
            {
                var tempPath = _store.DecryptToTemp(_selectedUser, item.Record);
                _store.OpenTempAndSaveAfterExit(_selectedUser, item.Record, tempPath, () =>
                {
                    Dispatcher.Invoke(LoadSelectedUserFiles);
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Dosya açılamadı", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void FilesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var hasUnlockedSelection = FilesList.SelectedItem is FileListItem && _selectedUser?.UnlockedKey is not null;
        RestoreFileButton.IsEnabled = hasUnlockedSelection;
        DeleteFileButton.IsEnabled = hasUnlockedSelection;
    }

    private void RestoreFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (FilesList.SelectedItem is not FileListItem item || _selectedUser?.UnlockedKey is null)
        {
            return;
        }

        var result = MessageBox.Show(
            this,
            $"{item.Name} kasadan çıkarılıp eski konumuna geri koyulsun mu?",
            "Eski yerine çıkar",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            var restoredPath = _store.RestoreToOriginalLocation(_selectedUser, item.Record);
            LoadSelectedUserFiles();
            MessageBox.Show(this, $"Geri koyuldu:\n{restoredPath}", "Tamamlandı", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Geri koyulamadı", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void DeleteFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (FilesList.SelectedItem is not FileListItem item || _selectedUser?.UnlockedKey is null)
        {
            return;
        }

        var result = MessageBox.Show(
            this,
            $"{item.Name} kasadan kalıcı olarak silinsin mi?",
            "Silme onayı",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            _store.DeleteFile(_selectedUser, item.Record);
            LoadSelectedUserFiles();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Dosya silinemedi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void DeleteVaultButton_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            this,
            "Tüm kasa silinsin mi?\n\nEvet: Tüm alanlardaki içerikleri eski yerlerine geri koy ve kasayı sil.\nHayır: Tüm kasayı File Shredder ile kalıcı sil.\nİptal: Vazgeç.",
            "Tüm kasayı sil",
            MessageBoxButton.YesNoCancel,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Cancel)
        {
            return;
        }

        var restoreContents = result == MessageBoxResult.Yes;
        if (restoreContents)
        {
            foreach (var user in _users)
            {
                if (!EnsureUserUnlocked(user))
                {
                    return;
                }
            }
        }

        try
        {
            _store.DeleteVault(_users, restoreContents);
            foreach (var user in _users)
            {
                if (user.UnlockedKey is not null)
                {
                    CryptographicOperations.ZeroMemory(user.UnlockedKey);
                    user.UnlockedKey = null;
                }
            }

            _users = [];
            _selectedUser = null;
            UsersList.SelectedItem = null;
            FilesList.ItemsSource = null;
            MessageBox.Show(this, "Kasa silindi.", "Tamamlandı", MessageBoxButton.OK, MessageBoxImage.Information);
            ShowSetup();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Kasa silinemedi", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void LockUserButton_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedUser?.UnlockedKey is not null)
        {
            CryptographicOperations.ZeroMemory(_selectedUser.UnlockedKey);
            _selectedUser.UnlockedKey = null;
        }

        _selectedUser = null;
        FilesList.ItemsSource = null;
        UsersList.SelectedItem = null;
        ResetFilePanel();
        SelectedUserTitle.Text = "Alan kilitlendi";
        SelectedUserSubtitle.Text = "Dosyaları görmek için alanı tekrar seçip şifre girin.";
    }

    private void ShowSetup()
    {
        SetupPanel.Visibility = Visibility.Visible;
        MasterLoginPanel.Visibility = Visibility.Collapsed;
        VaultPanel.Visibility = Visibility.Collapsed;
        EmergencyInfoButton.Visibility = Visibility.Collapsed;
        DeleteVaultButton.Visibility = Visibility.Collapsed;
        TrustButton.Visibility = Visibility.Collapsed;
        RefreshEmergencyInfoBanner();
        StatusText.Text = "İlk kurulum gerekiyor";
    }

    private void ShowMasterLogin()
    {
        var config = _store.Config ?? _store.LoadConfig();
        SetupPanel.Visibility = Visibility.Collapsed;
        MasterLoginPanel.Visibility = Visibility.Visible;
        VaultPanel.Visibility = Visibility.Collapsed;
        EmergencyInfoButton.Visibility = Visibility.Collapsed;
        DeleteVaultButton.Visibility = Visibility.Collapsed;
        TrustButton.Visibility = Visibility.Collapsed;
        RefreshEmergencyInfoBanner();
        MasterHintText.Text = string.IsNullOrWhiteSpace(config.MasterHint)
            ? "Bu USB kasasını açmak için master şifre gerekiyor."
            : $"Hatırlatma: {config.MasterHint}";
        StatusText.Text = "Master giriş bekleniyor";
    }

    private void ShowVault()
    {
        SetupPanel.Visibility = Visibility.Collapsed;
        MasterLoginPanel.Visibility = Visibility.Collapsed;
        VaultPanel.Visibility = Visibility.Visible;
        EmergencyInfoButton.Visibility = Visibility.Visible;
        DeleteVaultButton.Visibility = Visibility.Visible;
        TrustButton.Visibility = Visibility.Visible;
        HideEmergencyInfoBanner();
        StatusText.Text = $"Kasa konumu: {_store.VaultRoot}";
        _users = _store.LoadUsers();
        RefreshUsers();
        ResetFilePanel();
    }

    private void RefreshEmergencyInfoBanner()
    {
        var emergencyInfo = _store.Config?.EmergencyInfo;
        if (string.IsNullOrWhiteSpace(emergencyInfo))
        {
            EmergencyInfoBanner.Visibility = Visibility.Collapsed;
            EmergencyInfoText.Text = "";
            return;
        }

        EmergencyInfoText.Text = emergencyInfo.Trim();
        EmergencyInfoBanner.Visibility = Visibility.Visible;
    }

    private void HideEmergencyInfoBanner()
    {
        EmergencyInfoBanner.Visibility = Visibility.Collapsed;
        EmergencyInfoText.Text = "";
    }

    private void RefreshUsers()
    {
        UsersList.ItemsSource = null;
        UsersList.ItemsSource = _users.Select(user => new UserListItem { Id = user.Id, Name = user.Name }).ToList();
        DeleteUserButton.IsEnabled = _selectedUser is not null;
    }

    private void LoadSelectedUserFiles()
    {
        if (_selectedUser?.UnlockedKey is null)
        {
            ResetFilePanel();
            return;
        }

        var files = new List<FileListItem>();
        foreach (var record in _selectedUser.Files.OrderByDescending(file => file.AddedAt))
        {
            files.Add(new FileListItem
            {
                Record = record,
                Metadata = _store.ReadMetadata(_selectedUser, record)
            });
        }

        SelectedUserTitle.Text = _selectedUser.Name;
        SelectedUserSubtitle.Text = $"{files.Count} dosya";
        FilesList.ItemsSource = files;
        AddFileButton.IsEnabled = true;
        AddFolderButton.IsEnabled = true;
        RestoreFileButton.IsEnabled = FilesList.SelectedItem is FileListItem;
        DeleteFileButton.IsEnabled = FilesList.SelectedItem is FileListItem;
        LockUserButton.IsEnabled = true;
    }

    private void ResetFilePanel()
    {
        FilesList.ItemsSource = null;
        AddFileButton.IsEnabled = false;
        AddFolderButton.IsEnabled = false;
        RestoreFileButton.IsEnabled = false;
        DeleteFileButton.IsEnabled = false;
        LockUserButton.IsEnabled = false;
        DeleteUserButton.IsEnabled = _selectedUser is not null;
        SelectedUserTitle.Text = "Alan seçin";
        SelectedUserSubtitle.Text = "Dosyalar yalnızca alan şifresi girilince görünür.";
    }

    private bool EnsureUserUnlocked(UserRecord user)
    {
        if (user.UnlockedKey is not null)
        {
            return true;
        }

        var password = DialogHelpers.PromptPassword(this, $"{user.Name} Girişi", "Alan şifresi", user.PasswordHint);
        if (password is null)
        {
            return false;
        }

        if (_store.TryUnlockUser(user, password, out var error))
        {
            return true;
        }

        MessageBox.Show(this, error, "Giriş başarısız", MessageBoxButton.OK, MessageBoxImage.Warning);
        return false;
    }

    private void ClearPasswordBoxes()
    {
        SetupPasswordBox.Clear();
        SetupPasswordConfirmBox.Clear();
        SetupEmergencyInfoBox.Clear();
        MasterPasswordBox.Clear();
    }

    private static string EnsureTrailingSeparator(string path)
    {
        return path.EndsWith(Path.DirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;
    }

    private bool IsAllowedSourcePath(string sourcePath, out string message)
    {
        var fullSourcePath = Path.GetFullPath(sourcePath);
        var fullAppRoot = EnsureTrailingSeparator(Path.GetFullPath(_store.AppRoot));
        var fullVaultRoot = EnsureTrailingSeparator(Path.GetFullPath(_store.VaultRoot));

        if (!fullSourcePath.StartsWith(fullAppRoot, StringComparison.OrdinalIgnoreCase))
        {
            message = "Sadece uygulamanın bulunduğu USB içindeki dosya ve klasörler eklenebilir.";
            return false;
        }

        if (fullSourcePath.StartsWith(fullVaultRoot, StringComparison.OrdinalIgnoreCase))
        {
            message = "Kasa klasörünün içindeki öğeler tekrar eklenemez.";
            return false;
        }

        message = "";
        return true;
    }
}
