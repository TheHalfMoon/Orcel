// #288: the smallest WPF window, compiled exactly like Orcel.Desktop.exe
// (same compiler, framework and flags) and opened at the same size, as the
// memory baseline on the same machine. Test-only; never packaged.
using System;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;

internal static class MinimalWindowProgram
{
    [STAThread]
    private static void Main()
    {
        Window window = new Window
        {
            Title = "Minimal WPF baseline",
            Width = 1060,
            Height = 700,
            Content = new TextBlock { Text = "Baseline", Margin = new Thickness(24) },
        };
        AutomationProperties.SetAutomationId(window, "BaselineWindow");
        new Application().Run(window);
    }
}
