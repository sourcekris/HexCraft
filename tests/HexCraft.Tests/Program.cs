using System;
using System.Linq;
using System.Reflection;
using Xunit;

namespace HexCraft.Tests;

public static class Program
{
    public static int Main()
    {
        int passed = 0;
        int failed = 0;

        var testClasses = Assembly.GetExecutingAssembly()
            .GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract);

        foreach (var type in testClasses)
        {
            var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                .Where(m => m.GetCustomAttribute<FactAttribute>() is not null);

            foreach (var method in methods)
            {
                string name = $"{type.Name}.{method.Name}";
                try
                {
                    object? instance = Activator.CreateInstance(type);
                    method.Invoke(instance, null);
                    if (instance is IDisposable d) d.Dispose();
                    Console.WriteLine($"[PASS] {name}");
                    passed++;
                }
                catch (TargetInvocationException ex)
                {
                    Console.WriteLine($"[FAIL] {name}: {ex.InnerException?.Message ?? ex.Message}");
                    failed++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[FAIL] {name}: {ex.Message}");
                    failed++;
                }
            }
        }

        Console.WriteLine($"\nSummary: {passed} passed, {failed} failed.");
        return failed == 0 ? 0 : 1;
    }
}

