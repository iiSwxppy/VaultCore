using System.Globalization;
using Avalonia.Data.Converters;

namespace Vault.Desktop.ViewModels;

public sealed class EditOrAddConverter : IValueConverter
{
    public static readonly EditOrAddConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var isEdit = value is true;
        return isEdit ? "Edit" : "Add";
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
