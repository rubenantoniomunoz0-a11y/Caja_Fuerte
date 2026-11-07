using System.Security.Cryptography;

namespace CajaFuerte;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            // Comprobamos que el usuario ha pasado al menos 4 argumentos
            // (comando, fichero entrada, fichero salida, contraseña)
            if (args.Length < 4)
            {
                ShowUsage();
                return 1;
            }

            string command    = args[0].ToLowerInvariant(); // "cifrar" o "descifrar"
            string inputPath  = args[1];
            string outputPath = args[2];
            string password   = args[3];

            if (string.IsNullOrEmpty(password))
            {
                Console.Error.WriteLine("[ERROR] La contraseña no puede estar vacía.");
                return 1;
            }
             if (command == "cifrar")
            {
                CajaFuerteService.EncryptFile(inputPath, outputPath, password);
                Console.WriteLine($"[OK] Fichero cifrado correctamente: {outputPath}");
                return 0;
            }
            else if (command == "descifrar")
            {
                CajaFuerteService.DecryptFile(inputPath, outputPath, password);
                Console.WriteLine($"[OK] Fichero descifrado correctamente: {outputPath}");
                return 0;
            }
            else
            {
                Console.Error.WriteLine($"[ERROR] Comando desconocido: '{command}'.");
                ShowUsage();
                return 1;
            }
        }
        catch (CryptographicException ex)
        {
            // AQUÍ CAE LA DETECCIÓN DE MANIPULACIÓN
            Console.Error.WriteLine(
                "[ERROR] Fallo criptográfico: el fichero ha sido manipulado " +
                "o la contraseña es incorrecta.");
            Console.Error.WriteLine($"        Detalle: {ex.Message}");
            return 2; 
        }
        catch (FileNotFoundException)
        {
            Console.Error.WriteLine("[ERROR] El fichero de entrada no existe.");
            return 3;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ERROR] {ex.Message}");
            return 4;
        }
    }

    private static void ShowUsage()
    {
        Console.WriteLine("Uso:");
        Console.WriteLine("  CajaFuerte cifrar    <fichero_entrada.txt> <fichero_salida.caja> <contraseña>");
        Console.WriteLine("  CajaFuerte descifrar <fichero_entrada.caja> <fichero_salida.txt> <contraseña>");
    }
}