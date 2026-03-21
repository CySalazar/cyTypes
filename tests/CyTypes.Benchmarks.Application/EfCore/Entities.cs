using CyTypes.Primitives;

namespace CyTypes.Benchmarks.Application.EfCore;

public class EncryptedOrder
{
    public int Id { get; set; }
    public CyString Name { get; set; } = null!;
    public CyInt Quantity { get; set; } = null!;
    public CyDecimal Price { get; set; } = null!;
    public CyDateTime OrderDate { get; set; } = null!;
}

public class PlainOrder
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public int Quantity { get; set; }
    public decimal Price { get; set; }
    public DateTime OrderDate { get; set; }
}
