# Prueba de clifr en producción

[English](clifr-trial.md)

`clifr-trial` reúne la evidencia que muestra si clifr puede funcionar en un
servidor de producción real: cuánto cuesta, si se mantiene en marcha y si lo
que graba es correcto. Se instala una vez y se deja funcionando de 2 a 4
semanas. Al final genera un único informe anonimizado `.tar.gz`, con un
`SUMMARY.txt` que termina en **PASSED** (aprobada), **FAILED** (fallida) o
**INCOMPLETE** (incompleta).

Es un solo archivo, `bench/clifr-trial`, en este repositorio.

## Por qué un script que funciona durante semanas

clifrd guarda solo las últimas 72 horas, así que una comprobación hecha al
final no podría ver las primeras semanas. `clifr-trial` toma una pequeña
muestra cada hora (un temporizador de systemd) y al final escribe el informe a
partir de esas muestras.

Solo lee. La única excepción es el simulacro, que usted inicia (ver más
abajo), y es inofensivo.

## Requisitos

- clifrd y clifr instalados (los paquetes `clifrd` y `clifr`) y en marcha.
- root, systemd.
- Python 3.6 o posterior. En RHEL 8 basta con el `/usr/libexec/platform-python`
  del sistema: no hay que instalar nada.

## Pasos

Ejecute todos los comandos como root.

```sh
# 1. Descargar el script e iniciar la prueba
curl -O https://raw.githubusercontent.com/jlruedab/clifr/master/bench/clifr-trial
sudo sh clifr-trial start

# 2. Una vez, en un día normal: el simulacro
sudo clifr-trial drill

# 3. De vez en cuando: cómo va
sudo clifr-trial status

# 4. Pasadas 2 a 4 semanas: el informe que hay que devolver
sudo clifr-trial report
```

`start` copia el script a `/usr/local/sbin/clifr-trial`, así que el archivo
descargado se puede borrar. Instala el temporizador `clifr-trial.timer`,
anota los datos del servidor y toma la primera muestra (uno o dos minutos).

Durante la prueba, por favor responda las preguntas de
`/var/lib/clifr-trial/QUESTIONS.txt` (tipo de carga, si notó algún efecto, si
clifr respondió una pregunta real, si lo mantendría). El archivo va en el
informe. Puede responder en español.

Para que la prueba sea completa, mientras funciona el servidor debería pasar
por:

- un reinicio,
- una actualización del kernel o del sistema operativo,
- una actualización de clifrd (un paquete más nuevo, si se publica uno).

Déjelo a su mantenimiento habitual. El informe dice cuáles ocurrieron.

## Qué se recoge

**Cada hora** (el temporizador, con baja prioridad: `Nice=19`, E/S en reposo,
2 GB de memoria como máximo):

- clifrd: CPU usada, memoria (actual y máxima), reinicios, y si está en
  marcha;
- la grabación: tamaño en disco y número de archivos, espacio libre;
- el servidor: uso de CPU, carga, memoria disponible, presión (PSI) si el
  kernel la ofrece;
- el arranque, el kernel y la versión de clifrd, para ver reinicios,
  actualizaciones del sistema y de clifrd;
- el journal de clifrd.

**Cada 6 horas, una comprobación de exactitud:** el script guarda lo que
muestran en ese momento los `ps`, `ss` y `mount` reales. Diez minutos o más
después pide a clifr que reconstruya ese mismo momento y compara ambos:
procesos, sockets en escucha, conexiones TCP establecidas y montajes.

**Cada día:** `clifr info` (coste, pérdidas, eventos de guarda),
`clifr verify --integrity` (ningún archivo de datos dañado) y los eventos de
guarda, huecos y muestras omitidas.

Todo se guarda en `/var/lib/clifr-trial` (solo root).

## El simulacro

`sudo clifr-trial drill` genera unos cuantos eventos planificados a una hora
conocida, para que el informe pueda mostrar que clifr los grabó. Funciona en
segundo plano unos 11 minutos y no toca ninguna aplicación:

- un trabajo corto (`sleep 2`, código de salida 3);
- una conexión TCP consigo mismo en 127.0.0.1 (un socket en escucha y una
  conexión);
- un archivo abierto mientras dura;
- un tmpfs de 1 MiB montado en `/run/clifr-trial-drill`, desmontado al final.

Si ni siquiera ese montaje es aceptable: `sudo clifr-trial drill --no-mount`.

Un día después, la muestra horaria pregunta a clifr por cada evento, como
haría usted durante un incidente, y anota si encontró cada uno. Esa
comprobación debe hacerse dentro de las 72 horas que guarda clifrd, y el
temporizador la hace solo.

No hay ninguna muerte por falta de memoria (OOM) ni nada que use mucha CPU,
memoria o disco.

## El informe

`sudo clifr-trial report` hace las comprobaciones una vez más y escribe
`clifr-trial-AAAAMMDD-HHMM.tar.gz` en el directorio actual (`--out DIR` para
otro). Contiene:

| Archivo | Contenido |
|---|---|
| `SUMMARY.txt` | los veredictos, el coste por día, el último `clifr info`, los eventos de guarda, el resumen del journal, los simulacros |
| `hourly.csv` | las muestras horarias (números) |
| `accuracy.csv` | las comprobaciones de exactitud (recuentos: coincidencias, faltantes, sobrantes) |
| `daily.jsonl` | las comprobaciones diarias |
| `drills.jsonl` | los simulacros y sus resultados (encontrado / no encontrado) |
| `baseline.json` | el servidor: distribución, kernel, CPUs, memoria, otros agentes en marcha, programas eBPF |
| `journal-summary.txt` | el journal de clifrd: solo tipos de línea y recuentos |
| `doctor.txt` | `clifrd doctor`: lo que admite el kernel |
| `QUESTIONS.txt` | sus respuestas |

El informe está en inglés.

### Veredictos

| Veredicto | Se aprueba cuando |
|---|---|
| duration (duración) | 14 días o más |
| evidence coverage (cobertura) | al menos el 90% de las horas tienen muestra |
| no unplanned clifrd stop (ninguna parada imprevista) | ningún fallo, muerte por OOM o error en el journal |
| clifrd running at every sample (en marcha en cada muestra) | nunca se encontró parado |
| reboot / kernel or OS update / clifrd upgrade (reinicio / actualización del sistema / de clifrd) | ocurrió durante la prueba |
| CPU within 2% of one core (CPU) | 2% de un núcleo como máximo, de media y cada día |
| memory below the unit's limit (memoria) | el máximo de RSS de clifrd por debajo del 90% de `MemoryMax` (768 MiB), y ningún OOM kill. El máximo del cgroup se muestra pero no se juzga: incluye la caché de páginas (los archivos de datos), que en un servidor ocupado llega al límite y el kernel la libera ahí |
| disk within max_size (disco) | la grabación no pasó de `max_size` (2 GB) |
| retention (retención) | la grabación guarda las 72 horas configuradas, no más |
| no lost events (ningún evento perdido) | ninguna fuente perdió eventos |
| gaps only at reboots and upgrades (huecos) | ningún hueco sin explicar en la grabación |
| integrity of the data files (integridad) | ningún archivo dañado |
| accuracy spot checks (exactitud) | procesos y montajes: al menos 99,5% de coincidencia; sockets en escucha: como mucho 1 (o el 1%) distinto; conexiones: al menos 95% |
| drill reconstructed a day later (simulacro) | se encontraron todos los eventos del simulacro |

**PASS** (aprobado) y **FAIL** (fallido) son resultados. **NOT MET** (no
cubierto) significa que la prueba no lo cubrió (por ejemplo, no hubo ningún
reinicio), y **NO DATA** que no se recogió nada para ese veredicto. El resumen
dice **PASSED** solo si se aprueban todos los veredictos, **FAILED** si falla
uno, e **INCOMPLETE** en los demás casos.

## Privacidad

El informe contiene solo números, veredictos y las propias palabras de clifr.
No incluye nombre de host, direcciones IP o MAC, identificador de máquina o
de arranque, nombres de usuario, líneas de comando, rutas, puertos ni zona
horaria.

- En las tablas del informe no se guarda nada que identifique el servidor:
  las comprobaciones de exactitud y los simulacros guardan recuentos y
  encontrado / no encontrado, nunca nombres de procesos ni direcciones.
- Cada archivo pasa por un sanitizador. Sustituye los nombres del host, todas
  las direcciones IP y MAC, los identificadores de máquina y de arranque, los
  nombres de usuario de `/etc/passwd`, las direcciones de correo y los valores
  del tipo `password=…`. Las horas están en UTC.
- En las líneas de texto libre (el journal, los mensajes de error) solo quedan
  las palabras que aparecen en los propios programas de clifr. Las rutas, el
  texto entre comillas, los números y cualquier otra palabra (nombres de
  procesos, usuarios y montajes) se sustituyen por `PATH`, `Q`, `N` o `X`.
- Un último escaneo vuelve a buscar todo lo anterior. Si aún queda algo, el
  informe **no se escribe**, y el mensaje dice solo el tipo de dato, no el
  dato.

`QUESTIONS.txt` es su propio texto: también se sanitiza, pero reléalo antes
de enviarlo. Siempre puede mirar el contenido del informe antes:

```sh
tar -xzf clifr-trial-*.tar.gz
```

Los detalles de cualquier diferencia de exactitud (qué proceso, qué
dirección) se quedan en el servidor, en
`/var/lib/clifr-trial/accuracy-details.jsonl`, para que usted los consulte.
No se envía nada a ningún sitio: el informe lo envía usted.

## Desinstalar

```sh
sudo clifr-trial stop              # quita el temporizador; los datos recogidos se quedan
sudo rm -r /var/lib/clifr-trial    # una vez enviado el informe
sudo rm /usr/local/sbin/clifr-trial
```

`clifr-trial` no cambia clifrd ni su configuración: al quitarlo, clifr queda
como estaba.

## Limitaciones conocidas

- No hay línea base de antes de instalar clifrd. `QUESTIONS.txt` pide los
  números de su monitorización de la semana anterior, si los tiene.
- En RHEL 8, clifrd necesita `CAP_SYS_ADMIN` para eBPF; sin ella, graba los
  eventos de procesos con el conector de procesos del kernel (proc
  connector). El informe muestra qué modo se usó.
- Las comprobaciones de exactitud comparan un momento, no toda la prueba:
  unas 4 al día, unas 100 en 4 semanas.
