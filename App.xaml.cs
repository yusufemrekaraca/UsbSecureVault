using ModernWpf;

namespace UsbSecureVault;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        ThemeManager.Current.ApplicationTheme = ApplicationTheme.Dark;
        base.OnStartup(e);
    }
}
