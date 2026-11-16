# Titan Log Guard

Analizador CLI educativo para detectar patrones simples en logs sintéticos de autenticación. Agrupa intentos fallidos por usuario e IP, aplica umbrales configurables y exporta hallazgos JSON con evidencia de línea.

## Ejecutar

Requiere Python 3.10 o superior, sin dependencias externas.

```powershell
python log_guard.py examples/auth.log --fail-threshold 3 --output findings.json
```

Usa solo datos de ejemplo. No envíes logs reales que contengan credenciales, datos personales o información de clientes.

## Reglas

- `LG001`: al menos N fallos desde una misma IP dentro del archivo.
- `LG002`: al menos N fallos para un usuario dentro del archivo.
- El reporte contiene regla, conteo, claves resumidas y líneas de evidencia; no intenta atribuir intención ni identificar personas.

Formato esperado por línea: `timestamp level=... user=... ip=... event=...`. Las líneas que no coincidan se cuentan como omitidas.

## Licencia

MIT.
