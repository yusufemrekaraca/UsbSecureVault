using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace UsbSecureVault;

public sealed class FolderBrowserWindow : Window
{
    private readonly VaultStore _store;
    private readonly UserRecord _user;
    private readonly FileRecord _record;
    private readonly Action? _afterFileSaved;
    private readonly Stack<string> _backStack = [];
    private string _currentPath = "";

    private readonly TextBlock _pathText = new();
    private readonly TextBlock _statusText = new();
    private readonly Button _backButton = new();
    private readonly ListView _itemsList = new();

    public FolderBrowserWindow(Window owner, VaultStore store, UserRecord user, FileRecord record, string title, Action? afterFileSaved = null)
    {
        _store = store;
        _user = user;
        _record = record;
        _afterFileSaved = afterFileSaved;

        Title = title;
        Owner = owner;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Width = 860;
        Height = 560;
        MinWidth = 720;
        MinHeight = 420;
        Background = Brush("#09090B");
        Content = BuildContent(title);
        RefreshItems();
    }

    private UIElement BuildContent(string title)
    {
        var root = new Grid { Margin = new Thickness(18) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var header = new DockPanel { Margin = new Thickness(0, 0, 0, 12) };
        _backButton.Content = "Geri";
        _backButton.MinWidth = 82;
        _backButton.MinHeight = 34;
        _backButton.Margin = new Thickness(0, 0, 10, 0);
        _backButton.Click += (_, _) => GoBack();
        DockPanel.SetDock(_backButton, Dock.Left);
        header.Children.Add(_backButton);

        var headerText = new StackPanel();
        headerText.Children.Add(new TextBlock
        {
            Text = title,
            Foreground = Brushes.White,
            FontSize = 18,
            FontWeight = FontWeights.SemiBold
        });
        _pathText.Foreground = Brush("#A1A1AA");
        _pathText.TextWrapping = TextWrapping.Wrap;
        _pathText.Margin = new Thickness(0, 4, 0, 0);
        headerText.Children.Add(_pathText);
        header.Children.Add(headerText);
        root.Children.Add(header);

        _itemsList.Background = Brush("#111113");
        _itemsList.Foreground = Brushes.White;
        _itemsList.BorderBrush = Brush("#3F3F46");
        _itemsList.MouseDoubleClick += (_, _) => OpenSelectedItem();
        _itemsList.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter)
            {
                OpenSelectedItem();
            }
        };
        _itemsList.View = new GridView
        {
            Columns =
            {
                new GridViewColumn { Header = "Ad", DisplayMemberBinding = new System.Windows.Data.Binding(nameof(VaultFolderItem.Name)), Width = 420 },
                new GridViewColumn { Header = "Tip", DisplayMemberBinding = new System.Windows.Data.Binding(nameof(VaultFolderItem.TypeText)), Width = 100 },
                new GridViewColumn { Header = "Boyut", DisplayMemberBinding = new System.Windows.Data.Binding(nameof(VaultFolderItem.SizeText)), Width = 120 },
                new GridViewColumn { Header = "Değişme", DisplayMemberBinding = new System.Windows.Data.Binding(nameof(VaultFolderItem.ModifiedText)), Width = 170 }
            }
        };
        Grid.SetRow(_itemsList, 1);
        root.Children.Add(_itemsList);

        var footer = new DockPanel { Margin = new Thickness(0, 12, 0, 0) };
        var openButton = new Button
        {
            Content = "Aç",
            MinWidth = 96,
            MinHeight = 34,
            Background = Brush("#7F1D1D"),
            Foreground = Brushes.White,
            BorderBrush = Brush("#991B1B")
        };
        openButton.Click += (_, _) => OpenSelectedItem();
        DockPanel.SetDock(openButton, Dock.Right);
        footer.Children.Add(openButton);

        _statusText.Foreground = Brush("#A1A1AA");
        _statusText.VerticalAlignment = VerticalAlignment.Center;
        footer.Children.Add(_statusText);
        Grid.SetRow(footer, 2);
        root.Children.Add(footer);

        return root;
    }

    private void RefreshItems()
    {
        var items = _store.ListFolderItems(_user, _record, _currentPath);
        _itemsList.ItemsSource = items;
        _backButton.IsEnabled = _backStack.Count > 0;
        _pathText.Text = string.IsNullOrWhiteSpace(_currentPath) ? "\\" : $"\\{_currentPath}";
        _statusText.Text = $"{items.Count} öğe";
    }

    private void OpenSelectedItem()
    {
        if (_itemsList.SelectedItem is not VaultFolderItem item)
        {
            return;
        }

        if (item.IsFolder)
        {
            _backStack.Push(_currentPath);
            _currentPath = item.RelativePath;
            RefreshItems();
            return;
        }

        try
        {
            _statusText.Text = $"{item.Name} temp'e açılıyor...";
            _store.OpenFolderTreeFileAndSaveAfterExit(_user, _record, item.RelativePath, () =>
            {
                Dispatcher.Invoke(() =>
                {
                    RefreshItems();
                    _statusText.Text = $"{item.Name} kapandı ve kasaya geri yazıldı.";
                    _afterFileSaved?.Invoke();
                });
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Dosya açılamadı", MessageBoxButton.OK, MessageBoxImage.Error);
            RefreshItems();
        }
    }

    private void GoBack()
    {
        if (!_backStack.TryPop(out var previous))
        {
            return;
        }

        _currentPath = previous;
        RefreshItems();
    }

    private static SolidColorBrush Brush(string color)
    {
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
    }
}
