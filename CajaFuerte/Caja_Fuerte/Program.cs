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