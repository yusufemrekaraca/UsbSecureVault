using ModernWpf;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace UsbSecureVault;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        DispatcherUnhandledException += App_DispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
        AppDomain.CurrentDomain.ProcessExit += CurrentDomain_ProcessExit;
        TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
        SessionEnding += App_SessionEnding;

        ThemeManager.Current.ApplicationTheme = ApplicationTheme.Dark;
        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        CleanVaultTemp();
        base.OnExit(e);
    }

    private static void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        WriteCrashLog("DispatcherUnhandledException", e.Exception);
        MessageBox.Show(e.Exception.Message, "Beklenmeyen hata", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }

    private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        WriteCrashLog("UnhandledException", e.ExceptionObject as Exception);
        CleanVaultTemp();
    }

    private static void CurrentDomain_ProcessExit(object? sender, EventArgs e)
    {
        CleanVaultTemp();
    }

    private static void App_SessionEnding(object sender, SessionEndingCancelEventArgs e)
    {
        CleanVaultTemp();
    }

    private static void TaskScheduler_UnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        WriteCrashLog("UnobservedTaskException", e.Exception);
        e.SetObserved();
    }

    private static void WriteCrashLog(string source, Exception? exception)
    {
        try
        {
            var root = Path.GetFullPath(AppContext.BaseDirectory);
            var logDirectory = Path.Combine(root, "vault", "logs");
            Directory.CreateDirectory(logDirectory);
            var logPath = Path.Combine(logDirectory, "crash.log");
            File.AppendAllText(
                logPath,
                $"[{DateTimeOffset.Now:O}] {source}{Environment.NewLine}{exception}{Environment.NewLine}{Environment.NewLine}");
        }
        catch
        {
        }
    }

    private static void CleanVaultTemp()
    {
        try
        {
            new VaultStore().CleanTemp();
        }
        catch
        {
        }
    }
}
