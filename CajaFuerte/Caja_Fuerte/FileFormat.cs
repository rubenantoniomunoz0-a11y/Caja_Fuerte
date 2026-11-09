namespace CajaFuerte;

/// <summary>
/// Define la estructura binaria, offsets de lectura/escritura 
/// y parámetros criptográficos del formato de archivo cifrado (.cf).
/// </summary>
internal static class FileFormat
{
	// Cabecera única (Magic Bytes) para identificar que el archivo fue generado por esta aplicación ("CF01" en ASCII)
	public static readonly byte[] Magic = { 0x43, 0x46, 0x30, 0x31 }; // "CF01"

	// Versión del esquema del archivo (permite futura compatibilidad si cambia la estructura)
	public const byte Version = 0x01;

	// --- Tamaños de los bloques de metadatos (en bytes) ---
	public const int MagicSize = 4;  // Tamaño del identificador de archivo ("CF01" = 4 bytes)
	public const int VersionSize = 1;  // Tamaño del campo de versión (1 byte)
	public const int SaltSize = 16; // Tamaño del Salt de PBKDF2 para la derivación de clave (128 bits)
	public const int NonceSize = 12; // Tamaño del IV/Nonce requerido por AES-GCM (96 bits recomendados por NIST)
	public const int TagSize = 16; // Tamaño del Tag de autenticación generado por AES-GCM (128 bits)

	// --- Parámetros de seguridad criptográfica ---
	public const int KeySize = 32;      // Tamaño de clave simétrica: 32 bytes (256 bits para AES-256)
	public const int Pbkdf2Iterations = 600_000; // Número de iteraciones PBKDF2 (mitiga ataques de fuerza bruta)

	// --- Posiciones exactas (offsets) de cada bloque en el encabezado del archivo ---
	public const int OffsetMagic = 0;                            // Byte 0: Inicio del identificador
	public const int OffsetVersion = OffsetMagic + MagicSize;      // Byte 4: Inicio del byte de versión
	public const int OffsetSalt = OffsetVersion + VersionSize;  // Byte 5: Inicio del Salt de PBKDF2
	public const int OffsetNonce = OffsetSalt + SaltSize;        // Byte 21: Inicio del Nonce de AES-GCM
	public const int OffsetTag = OffsetNonce + NonceSize;      // Byte 33: Inicio del Tag de autenticación
	public const int OffsetCipher = OffsetTag + TagSize;          // Byte 49: Inicio de los datos cifrados (Payload)

	// --- Tamaño total del encabezado ---
	// Suma de todos los metadatos. Indica dónde termina la cabecera y comienzan los datos cifrados.
	public const int HeaderSize = OffsetCipher; // 49 bytes en total
} 