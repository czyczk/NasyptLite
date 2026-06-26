using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

#nullable enable

namespace NasyptLite.SourceGen;

[Generator]
public class NasyptDecryptGenerator : IIncrementalGenerator
{
    private const string NasyptDecryptAttr = "NasyptLite.NasyptDecrypt";
    private const string EncryptedAttr = "NasyptLite.Encrypted";

    private static readonly HashSet<string> ValidAlgorithms = new()
    {
        "PBEWithHMACSHA512AndAES_256",
        "PBEWithHMACSM3AndSM4_GCM",
        "PBEWithHMACSM3AndSM4_CBC"
    };

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var classDeclarations = context.SyntaxProvider
            .CreateSyntaxProvider(
                predicate: IsCandidateClass,
                transform: TransformClass)
            .Where(c => c is not null)
            .Select((c, _) => c!);

        context.RegisterSourceOutput(classDeclarations, GenerateSource);
    }

    private static bool IsCandidateClass(SyntaxNode node, CancellationToken _)
    {
        if (node is not ClassDeclarationSyntax { AttributeLists.Count: > 0 } classDecl)
            return false;

        return classDecl.Parent is not ClassDeclarationSyntax;
    }

    private static ClassInfo? TransformClass(GeneratorSyntaxContext context, CancellationToken ct)
    {
        var classDecl = (ClassDeclarationSyntax)context.Node;

        if (!classDecl.Modifiers.Any(SyntaxKind.PartialKeyword))
            return null;

        if (classDecl.TypeParameterList is not null)
            return null;

        var symbol = context.SemanticModel.GetDeclaredSymbol(classDecl, ct);
        if (symbol is not INamedTypeSymbol classSymbol)
            return null;

        if (!HasAttributeByName(classSymbol, NasyptDecryptAttr))
            return null;

        var encryptedProperties = new List<PropInfo>();
        foreach (var member in classSymbol.GetMembers())
        {
            if (member is not IPropertySymbol prop)
                continue;

            if (prop.SetMethod is null)
                continue;

            var encryptedAttr = GetAttribute(prop, EncryptedAttr);
            if (encryptedAttr is null)
                continue;

            if (!IsStringType(prop.Type))
                continue;

            var algorithm = GetNamedArgument(encryptedAttr, "Algorithm");

            encryptedProperties.Add(new PropInfo(
                prop.Name,
                IsNullableString(prop.Type),
                algorithm));
        }

        if (encryptedProperties.Count == 0)
            return null;

        var accessibility = classSymbol.DeclaredAccessibility switch
        {
            Accessibility.Public => "public",
            Accessibility.Internal => "internal",
            _ => "public"
        };

        var isGlobalNamespace = classSymbol.ContainingNamespace.IsGlobalNamespace;
        var ns = isGlobalNamespace ? null : classSymbol.ContainingNamespace.ToDisplayString();

        return new ClassInfo(
            classSymbol.Name,
            ns,
            accessibility,
            encryptedProperties);
    }

    private static AttributeData? GetAttribute(ISymbol symbol, string attributeName)
    {
        foreach (var attr in symbol.GetAttributes())
        {
            if (attr.AttributeClass is { } attrClass)
            {
                var name = attrClass.Name;
                if (name == attributeName || name == attributeName + "Attribute")
                    return attr;

                var fullName = attrClass.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
                fullName = fullName.Replace("Attribute", "");
                if (fullName == "global::" + attributeName || fullName.EndsWith("." + attributeName))
                    return attr;
            }
        }
        return null;
    }

    private static bool HasAttributeByName(ISymbol symbol, string attributeName)
    {
        return GetAttribute(symbol, attributeName) is not null;
    }

    private static string? GetNamedArgument(AttributeData attr, string argumentName)
    {
        foreach (var arg in attr.NamedArguments)
        {
            if (arg.Key == argumentName && arg.Value.Value is string s && s.Length > 0)
                return s;
        }
        return null;
    }

    private static bool IsStringType(ITypeSymbol type)
    {
        if (type.SpecialType == SpecialType.System_String)
            return true;

        if (type is INamedTypeSymbol { IsGenericType: true } named
            && named.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T
            && named.TypeArguments.Length == 1
            && named.TypeArguments[0].SpecialType == SpecialType.System_String)
            return true;

        return false;
    }

    private static bool IsNullableString(ITypeSymbol type)
    {
        if (type.NullableAnnotation == NullableAnnotation.Annotated)
            return true;

        if (type is INamedTypeSymbol { IsGenericType: true } named
            && named.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T
            && named.TypeArguments.Length == 1
            && named.TypeArguments[0].SpecialType == SpecialType.System_String)
            return true;

        return false;
    }

    private static void GenerateSource(SourceProductionContext context, ClassInfo? classInfo)
    {
        if (classInfo is null)
            return;
        var sb = new StringBuilder();
        sb.AppendLine("using NasyptLite;");
        sb.AppendLine();

        if (classInfo.Namespace is not null)
        {
            sb.AppendLine($"namespace {classInfo.Namespace};");
            sb.AppendLine();
        }

        sb.AppendLine($"{classInfo.Accessibility} partial class {classInfo.Name} : System.IDisposable");
        sb.AppendLine("{");
        sb.AppendLine("    private bool _disposed;");
        sb.AppendLine();
        void EmitDecryptBody(string algorithmExpr, bool isStringAlgo)
        {
            foreach (var prop in classInfo.Properties)
            {
                var nullGuard = prop.IsNullable ? $"{prop.Name} is not null && " : "";
                sb.AppendLine($"        if ({nullGuard}Nasypt.IsEncValue({prop.Name}))");

                if (isStringAlgo)
                {
                    if (prop.Algorithm is not null)
                    {
                        var alg = FormatAlgorithm(prop.Algorithm);
                        sb.AppendLine($"            {prop.Name} = Nasypt.DecryptEncWith({alg}, {prop.Name}, password);");
                    }
                    else
                    {
                        sb.AppendLine($"            {prop.Name} = Nasypt.DecryptEnc({prop.Name}, password);");
                    }
                }
                else
                {
                    sb.AppendLine($"            {prop.Name} = Nasypt.DecryptEncWith({algorithmExpr}, {prop.Name}, password);");
                }
            }
        }

        sb.AppendLine("    public void DecryptEncFields(string password)");
        sb.AppendLine("    {");
        EmitDecryptBody(algorithmExpr: "", isStringAlgo: true);
        sb.AppendLine("    }");
        sb.AppendLine();
        sb.AppendLine("    public void DecryptEncFieldsWithAlgorithm(Algorithm algorithm, string password)");
        sb.AppendLine("    {");
        EmitDecryptBody(algorithmExpr: "algorithm", isStringAlgo: false);
        sb.AppendLine("    }");
        sb.AppendLine();
        sb.AppendLine("    public void ClearSensitiveFields()");
        sb.AppendLine("    {");
        foreach (var prop in classInfo.Properties)
        {
            if (prop.IsNullable)
                sb.AppendLine($"        {prop.Name} = Nasypt.ClearOptionString({prop.Name});");
            else
                sb.AppendLine($"        {prop.Name} = Nasypt.ClearString({prop.Name});");
        }
        sb.AppendLine("    }");
        sb.AppendLine();
        sb.AppendLine("    public void Dispose()");
        sb.AppendLine("    {");
        sb.AppendLine("        if (_disposed) return;");
        sb.AppendLine("        ClearSensitiveFields();");
        sb.AppendLine("        _disposed = true;");
        sb.AppendLine("        System.GC.SuppressFinalize(this);");
        sb.AppendLine("    }");
        sb.AppendLine("}");

        var hint = classInfo.Namespace is not null
            ? $"{classInfo.Namespace}.{classInfo.Name}.g.cs"
            : $"{classInfo.Name}.g.cs";
        context.AddSource(hint, SourceText.From(sb.ToString(), Encoding.UTF8));
    }

    private static string FormatAlgorithm(string algorithm)
    {
        if (ValidAlgorithms.Contains(algorithm))
            return $"Algorithm.{algorithm}";

        return algorithm;
    }

    private sealed class ClassInfo
    {
        public string Name { get; }
        public string? Namespace { get; }
        public string Accessibility { get; }
        public List<PropInfo> Properties { get; }

        public ClassInfo(string name, string? ns, string accessibility, List<PropInfo> properties)
        {
            Name = name;
            Namespace = ns;
            Accessibility = accessibility;
            Properties = properties;
        }
    }

    private sealed class PropInfo
    {
        public string Name { get; }
        public bool IsNullable { get; }
        public string? Algorithm { get; }

        public PropInfo(string name, bool isNullable, string? algorithm)
        {
            Name = name;
            IsNullable = isNullable;
            Algorithm = algorithm;
        }
    }
}
