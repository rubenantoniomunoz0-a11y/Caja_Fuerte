# CajaFuerte

Aplicación de consola en C# para cifrar y descifrar archivos de texto.

## Uso
dotnet run -- cifrar <fichero_entrada.txt> <fichero_salida.caja> <contraseña>
dotnet run -- descifrar <fichero_entrada.caja> <fichero_salida.txt> <contraseña>

## Seguridad
- Algoritmo AES-256 en modo GCM (cifrado autenticado).
- Derivación de clave PBKDF2 con SHA-256 y 600.000 iteraciones.
- Uso de RandomNumberGenerator para salts y nonces.