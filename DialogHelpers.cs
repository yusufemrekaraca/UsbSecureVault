using System.Windows;
using System.Windows.Controls;

namespace UsbSecureVault;

public static class DialogHelpers
{
    public static FileAddMode? PromptFileAddMode(Window owner, string itemName)
    {
        var window = new Window
        {
            Title = "Saklama yöntemi",
            Owner = owner,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Width = 460,
            SizeToContent = SizeToContent.Height,
            Background = System.Windows.Media.Brushes.White
        };

        var root = new StackPanel { Margin = new Thickness(18) };
        root.Children.Add(new TextBlock
        {
            Text = itemName,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 12)
        });
        root.Children.Add(new TextBlock
        {
            Text = "Şifrele: güçlü koruma, büyük dosyalarda daha yavaş.\nBoz: hızlı saklama, içerik şifrelenmez; sadece ad/uzantı gizlenir.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 18)
        });

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };

        var cancel = new Button { Content = "İptal", MinWidth = 82, Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 0, 8, 0) };
        var obfuscate = new Button { Content = "Boz", MinWidth = 82, Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 0, 8, 0) };
        var encrypt = new Button { Content = "Şifrele", MinWidth = 92, Padding = new Thickness(10, 6, 10, 6), IsDefault = true };

        cancel.Click += (_, _) => window.DialogResult = false;
        obfuscate.Click += (_, _) =>
        {
            window.Tag = FileAddMode.Obfuscate;
            window.DialogResult = true;
        };
        encrypt.Click += (_, _) =>
        {
            window.Tag = FileAddMode.Encrypt;
            window.DialogResult = true;
        };

        buttons.Children.Add(cancel);
        buttons.Children.Add(obfuscate);
        buttons.Children.Add(encrypt);
        root.Children.Add(buttons);
        window.Content = root;

        return window.ShowDialog() == true ? (FileAddMode?)window.Tag : null;
    }

    public static string? PromptText(Window owner, string title, string label)
    {
        var input = new TextBox { Margin = new Thickness(0, 4, 0, 14), Padding = new Thickness(8) };
        return ShowDialog(owner, title, label, input, () => input.Text.Trim());
    }

    public static string? PromptMultilineText(Window owner, string title, string label, string initialValue)
    {
        var input = new TextBox
        {
            Text = initialValue,
            Margin = new Thickness(0, 4, 0, 14),
            Padding = new Thickness(8),
            MinHeight = 120,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };

        return ShowDialog(owner, title, label, input, () => input.Text.Trim());
    }

    public static string? PromptPassword(Window owner, string title, string label, string hint)
    {
        var panel = new StackPanel();
        if (!string.IsNullOrWhiteSpace(hint))
        {
            panel.Children.Add(new TextBlock
            {
                Text = $"Hatırlatma: {hint}",
                TextWrapping = TextWrapping.Wrap,
                Foreground = System.Windows.Media.Brushes.DimGray,
                Margin = new Thickness(0, 0, 0, 10)
            });
        }

        var passwordBox = new PasswordBox { Margin = new Thickness(0, 4, 0, 14), Padding = new Thickness(8) };
        panel.Children.Add(new TextBlock { Text = label });
        panel.Children.Add(passwordBox);
        return ShowDialog(owner, title, "", panel, () => passwordBox.Password);
    }

    public static CreateUserResult? PromptCreateUser(Window owner)
    {
        var name = new TextBox { Margin = new Thickness(0, 4, 0, 10), Padding = new Thickness(8) };
        var password = new PasswordBox { Margin = new Thickness(0, 4, 0, 10), Padding = new Thickness(8) };
        var confirm = new PasswordBox { Margin = new Thickness(0, 4, 0, 10), Padding = new Thickness(8) };
        var hint = new TextBox { Margin = new Thickness(0, 4, 0, 14), Padding = new Thickness(8) };

        var panel = new StackPanel();
        panel.Children.Add(new TextBlock { Text = "Alan adı" });
        panel.Children.Add(name);
        panel.Children.Add(new TextBlock { Text = "Alan şifresi" });
        panel.Children.Add(password);
        panel.Children.Add(new TextBlock { Text = "Alan şifresi tekrar" });
        panel.Children.Add(confirm);
        panel.Children.Add(new TextBlock { Text = "Hatırlatma" });
        panel.Children.Add(hint);

        var result = ShowDialog(owner, "Yeni Alan Oluştur", "", panel, () =>
        {
            if (string.IsNullOrWhiteSpace(name.Text))
            {
                MessageBox.Show(owner, "Alan adı boş olamaz.", "Eksik bilgi", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            if (password.Password.Length < 8)
            {
                MessageBox.Show(owner, "Alan şifresi en az 8 karakter olmalı.", "Zayıf şifre", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            if (password.Password != confirm.Password)
            {
                MessageBox.Show(owner, "Şifreler eşleşmiyor.", "Hatalı giriş", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            return new CreateUserResult(name.Text.Trim(), password.Password, hint.Text.Trim());
        });

        return result;
    }

    private static T? ShowDialog<T>(Window owner, string title, string label, UIElement input, Func<T?> getValue)
    {
        var window = new Window
        {
            Title = title,
            Owner = owner,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            Width = 390,
            SizeToContent = SizeToContent.Height,
            Background = System.Windows.Media.Brushes.White
        };

        var root = new StackPanel { Margin = new Thickness(18) };
        if (!string.IsNullOrWhiteSpace(label))
        {
            root.Children.Add(new TextBlock { Text = label });
        }

        root.Children.Add(input);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        var cancel = new Button { Content = "İptal", MinWidth = 82, Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 0, 8, 0) };
        var ok = new Button { Content = "Tamam", MinWidth = 82, Padding = new Thickness(10, 6, 10, 6), IsDefault = true };
        cancel.Click += (_, _) => window.DialogResult = false;
        ok.Click += (_, _) =>
        {
            var value = getValue();
            if (value is null)
            {
                return;
            }

            window.Tag = value;
            window.DialogResult = true;
        };
        buttons.Children.Add(cancel);
        buttons.Children.Add(ok);
        root.Children.Add(buttons);
        window.Content = root;

        return window.ShowDialog() == true ? (T?)window.Tag : default;
    }
}

public enum FileAddMode
{
    Encrypt,
    Obfuscate
}

public sealed record CreateUserResult(string Name, string Password, string Hint);
