using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

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
            MaxHeight = SystemParameters.WorkArea.Height * 0.85,
            Background = Brushes.White
        };

        var root = CreateDialogRoot();
        var content = new StackPanel();
        content.Children.Add(new TextBlock
        {
            Text = itemName,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.Black,
            Margin = new Thickness(0, 0, 0, 12)
        });
        content.Children.Add(new TextBlock
        {
            Text = "Şifrele: güçlü koruma, büyük dosyalarda daha yavaş.\nBoz: hızlı saklama, içerik şifrelenmez; sadece ad/uzantı gizlenir.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = Brushes.Black,
            Margin = new Thickness(0, 0, 0, 18)
        });
        root.Children.Add(new ScrollViewer
        {
            Content = content,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        });

        var buttons = CreateButtonBar();
        Grid.SetRow(buttons, 1);
        var cancel = CreateDialogButton("İptal");
        var obfuscate = CreateDialogButton("Boz");
        var encrypt = CreateDialogButton("Şifrele", true);

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
                Foreground = Brushes.DimGray,
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
        var usePassword = new CheckBox
        {
            Content = "Şifre kullan",
            IsChecked = true,
            Foreground = Brushes.Black,
            Margin = new Thickness(0, 0, 0, 10)
        };
        var password = new PasswordBox { Margin = new Thickness(0, 4, 0, 10), Padding = new Thickness(8) };
        var confirm = new PasswordBox { Margin = new Thickness(0, 4, 0, 10), Padding = new Thickness(8) };
        var hint = new TextBox { Margin = new Thickness(0, 4, 0, 14), Padding = new Thickness(8) };
        usePassword.Click += (_, _) =>
        {
            var enabled = usePassword.IsChecked == true;
            password.IsEnabled = enabled;
            confirm.IsEnabled = enabled;
            hint.IsEnabled = enabled;
            if (!enabled)
            {
                password.Clear();
                confirm.Clear();
                hint.Clear();
            }
        };

        var panel = new StackPanel();
        panel.Children.Add(CreateDialogLabel("Alan adı"));
        panel.Children.Add(name);
        panel.Children.Add(usePassword);
        panel.Children.Add(CreateDialogLabel("Alan şifresi"));
        panel.Children.Add(password);
        panel.Children.Add(CreateDialogLabel("Alan şifresi tekrar"));
        panel.Children.Add(confirm);
        panel.Children.Add(CreateDialogLabel("Hatırlatma"));
        panel.Children.Add(hint);

        var result = ShowDialog(owner, "Yeni Alan Oluştur", "", panel, () =>
        {
            if (string.IsNullOrWhiteSpace(name.Text))
            {
                MessageBox.Show(owner, "Alan adı boş olamaz.", "Eksik bilgi", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            var passwordEnabled = usePassword.IsChecked == true;
            if (passwordEnabled && password.Password != confirm.Password)
            {
                MessageBox.Show(owner, "Şifreler eşleşmiyor.", "Hatalı giriş", MessageBoxButton.OK, MessageBoxImage.Warning);
                return null;
            }

            return new CreateUserResult(name.Text.Trim(), passwordEnabled, password.Password, hint.Text.Trim());
        });

        return result;
    }

    public static FolderImportPlan? PromptFolderImportPlan(Window owner, string sourcePath)
    {
        var rootPlan = BuildImportPlan(sourcePath);
        var current = rootPlan;
        var stack = new Stack<FolderImportPlan>();
        var backgroundBrush = new SolidColorBrush(Color.FromRgb(9, 9, 11));
        var panelBrush = new SolidColorBrush(Color.FromRgb(24, 24, 27));
        var panelAltBrush = new SolidColorBrush(Color.FromRgb(17, 17, 19));
        var borderBrush = new SolidColorBrush(Color.FromRgb(63, 63, 70));
        var primaryTextBrush = new SolidColorBrush(Color.FromRgb(244, 244, 245));
        var secondaryTextBrush = new SolidColorBrush(Color.FromRgb(161, 161, 170));
        var accentBrush = new SolidColorBrush(Color.FromRgb(127, 29, 29));

        var window = new Window
        {
            Title = "Klasörü Kasaya Al",
            Owner = owner,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Width = 760,
            Height = 520,
            MinWidth = 640,
            MinHeight = 420,
            Background = backgroundBrush
        };

        var root = new Grid
        {
            Margin = new Thickness(18),
            Background = backgroundBrush
        };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var header = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };
        var backButton = CreateDialogButton("Geri");
        backButton.IsEnabled = false;
        DockPanel.SetDock(backButton, Dock.Left);
        header.Children.Add(backButton);

        var pathText = new TextBlock
        {
            Foreground = primaryTextBrush,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(10, 0, 0, 0)
        };
        header.Children.Add(pathText);
        root.Children.Add(header);

        var list = new ListBox
        {
            BorderBrush = borderBrush,
            Background = panelAltBrush,
            Foreground = primaryTextBrush
        };
        Grid.SetRow(list, 1);
        root.Children.Add(list);

        var buttons = CreateButtonBar();
        Grid.SetRow(buttons, 2);
        var cancel = CreateDialogButton("İptal");
        var ok = CreateDialogButton("Kasaya Al", true);
        buttons.Children.Add(cancel);
        buttons.Children.Add(ok);
        root.Children.Add(buttons);

        void Refresh()
        {
            pathText.Text = current == rootPlan ? current.Name : $"{rootPlan.Name}\\{GetPlanRelativePath(rootPlan, current)}";
            backButton.IsEnabled = stack.Count > 0;
            list.Items.Clear();

            foreach (var child in current.Children.OrderBy(item => item.IsFolder).ThenBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                var row = new Grid
                {
                    Margin = new Thickness(6),
                    Tag = child,
                    Background = panelBrush
                };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var nameText = new TextBlock
                {
                    Text = child.IsFolder ? $"[Klasör] {child.Name}" : child.Name,
                    Foreground = primaryTextBrush,
                    VerticalAlignment = VerticalAlignment.Center,
                    TextWrapping = TextWrapping.Wrap
                };
                row.Children.Add(nameText);

                if (child.IsFolder)
                {
                    var openText = new TextBlock
                    {
                        Text = "Çift tıkla",
                        Foreground = secondaryTextBrush,
                        VerticalAlignment = VerticalAlignment.Center,
                        Margin = new Thickness(12, 0, 12, 0)
                    };
                    Grid.SetColumn(openText, 1);
                    row.Children.Add(openText);
                }

                var mode = new ComboBox
                {
                    Width = 120,
                    Margin = new Thickness(12, 0, 0, 0),
                    SelectedValuePath = "Tag",
                    Foreground = Brushes.White,
                    Background = accentBrush,
                    BorderBrush = accentBrush
                };
                mode.Items.Add(new ComboBoxItem { Content = "Şifrele", Tag = FileAddMode.Encrypt, Background = panelBrush, Foreground = primaryTextBrush });
                mode.Items.Add(new ComboBoxItem { Content = "Boz", Tag = FileAddMode.Obfuscate, Background = panelBrush, Foreground = primaryTextBrush });
                mode.SelectedValue = child.Mode;
                mode.SelectionChanged += (_, _) =>
                {
                    if (mode.SelectedValue is FileAddMode selectedMode)
                    {
                        SetModeRecursive(child, selectedMode);
                    }
                };
                Grid.SetColumn(mode, 2);
                row.Children.Add(mode);

                list.Items.Add(new ListBoxItem
                {
                    Content = row,
                    Background = panelBrush,
                    Foreground = primaryTextBrush,
                    BorderBrush = borderBrush,
                    Padding = new Thickness(2),
                    Margin = new Thickness(0, 0, 0, 6)
                });
            }
        }

        backButton.Click += (_, _) =>
        {
            if (stack.TryPop(out var previous))
            {
                current = previous;
                Refresh();
            }
        };

        list.MouseDoubleClick += (_, _) =>
        {
            if (list.SelectedItem is ListBoxItem { Content: Grid { Tag: FolderImportPlan { IsFolder: true } folder } })
            {
                stack.Push(current);
                current = folder;
                Refresh();
            }
        };

        cancel.Click += (_, _) => window.DialogResult = false;
        ok.Click += (_, _) =>
        {
            window.Tag = rootPlan;
            window.DialogResult = true;
        };

        window.Content = root;
        Refresh();
        return window.ShowDialog() == true ? (FolderImportPlan?)window.Tag : null;
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
            MaxHeight = SystemParameters.WorkArea.Height * 0.85,
            Background = Brushes.White
        };

        var root = CreateDialogRoot();
        var content = new StackPanel();
        if (!string.IsNullOrWhiteSpace(label))
        {
            content.Children.Add(CreateDialogLabel(label));
        }

        content.Children.Add(input);
        ApplyDialogColors(input);
        root.Children.Add(new ScrollViewer
        {
            Content = content,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        });

        var buttons = CreateButtonBar();
        Grid.SetRow(buttons, 1);
        var cancel = CreateDialogButton("İptal");
        var ok = CreateDialogButton("Tamam", true);
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

    private static Grid CreateDialogRoot()
    {
        var root = new Grid { Margin = new Thickness(18) };
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        return root;
    }

    private static StackPanel CreateButtonBar()
    {
        return new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 14, 0, 0)
        };
    }

    private static Button CreateDialogButton(string text, bool isDefault = false)
    {
        return new Button
        {
            Content = text,
            MinWidth = 82,
            MinHeight = 34,
            Padding = new Thickness(12, 7, 12, 7),
            Margin = new Thickness(0, 0, 8, 0),
            Background = isDefault ? new SolidColorBrush(Color.FromRgb(127, 29, 29)) : new SolidColorBrush(Color.FromRgb(39, 39, 42)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(63, 63, 70)),
            Foreground = Brushes.White,
            IsDefault = isDefault
        };
    }

    private static TextBlock CreateDialogLabel(string text)
    {
        return new TextBlock
        {
            Text = text,
            Foreground = Brushes.Black,
            Margin = new Thickness(0, 0, 0, 2)
        };
    }

    private static void ApplyDialogColors(UIElement element)
    {
        if (element is TextBlock text)
        {
            text.Foreground = Brushes.Black;
        }

        if (element is Panel panel)
        {
            foreach (UIElement child in panel.Children)
            {
                ApplyDialogColors(child);
            }
        }
    }

    private static FolderImportPlan BuildImportPlan(string sourcePath)
    {
        var directory = new DirectoryInfo(sourcePath);
        var plan = new FolderImportPlan
        {
            SourcePath = sourcePath,
            Name = directory.Name,
            IsFolder = true
        };

        foreach (var file in Directory.EnumerateFiles(sourcePath))
        {
            plan.Children.Add(new FolderImportPlan
            {
                SourcePath = file,
                Name = Path.GetFileName(file),
                IsFolder = false
            });
        }

        foreach (var childDirectory in Directory.EnumerateDirectories(sourcePath))
        {
            plan.Children.Add(BuildImportPlan(childDirectory));
        }

        return plan;
    }

    private static void SetModeRecursive(FolderImportPlan plan, FileAddMode mode)
    {
        plan.Mode = mode;
        foreach (var child in plan.Children)
        {
            SetModeRecursive(child, mode);
        }
    }

    private static string GetPlanRelativePath(FolderImportPlan root, FolderImportPlan target)
    {
        var path = new List<string>();
        return FindPath(root, target, path) ? string.Join("\\", path) : target.Name;
    }

    private static bool FindPath(FolderImportPlan current, FolderImportPlan target, List<string> path)
    {
        foreach (var child in current.Children.Where(child => child.IsFolder))
        {
            path.Add(child.Name);
            if (ReferenceEquals(child, target) || FindPath(child, target, path))
            {
                return true;
            }

            path.RemoveAt(path.Count - 1);
        }

        return false;
    }
}

public enum FileAddMode
{
    Encrypt,
    Obfuscate
}

public sealed record CreateUserResult(string Name, bool UsePassword, string Password, string Hint);
