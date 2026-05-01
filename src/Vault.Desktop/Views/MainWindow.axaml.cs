using Avalonia.Controls;
using Vault.Desktop.ViewModels;

namespace Vault.Desktop.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        // Wire user activity to idle detector. Any pointer/keyboard input
        // anywhere in the window resets the idle timer. We use the typed
        // events to avoid generic AddHandler signature gymnastics.
        PointerMoved += (_, _) => NoteActivity();
        PointerPressed += (_, _) => NoteActivity();
        KeyDown += (_, _) => NoteActivity();
    }

    private void NoteActivity()
    {
        if (DataContext is ShellViewModel shell) shell.NoteUserActivity();
    }
}
