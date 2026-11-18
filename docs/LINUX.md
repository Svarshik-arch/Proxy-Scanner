# Запуск на Linux

Готовые файлы — в папке [`release`](../release): `proxy-scanner`, `masscan` и скрипт запуска
`proxy-scanner.sh`. Положите их в одну папку.

Требования: x86_64, glibc 2.35 или новее (Ubuntu 22.04+, Debian 12+, Astra Linux 1.8+,
RHEL/Alma/Rocky 10 и т. п.), графический сеанс X11 или Wayland.

## Быстрый запуск (скрипт)

```bash
chmod +x proxy-scanner masscan proxy-scanner.sh
```

```bash
./proxy-scanner.sh
```

Скрипт сам выполняет все шаги, описанные ниже:

1. поднимает лимит открытых файлов до 65535 (или до максимума, разрешённого системой);
2. проверяет libpcap и, если её нет, устанавливает пакетным менеджером
   (`apt` / `dnf` / `yum` / `zypper`); в закрытом контуре без репозитория выдаст предупреждение —
   режим TCP-connect при этом работает;
3. разрешает root выводить окно на ваш экран (`xhost +si:localuser:root`);
4. перезапускает программу через `sudo`, передав переменные экрана (`DISPLAY`, `XAUTHORITY`);
5. после закрытия программы отзывает доступ root к экрану.

Режимы скрипта:

| Команда | Что делает |
|---|---|
| `./proxy-scanner.sh` | запуск от root (по умолчанию) |
| `./proxy-scanner.sh --caps` | интерфейс от обычного пользователя, права на «сырые» сокеты получает только `masscan` (`setcap`) — безопаснее |
| `./proxy-scanner.sh --user` | обычный пользователь без прав для masscan (только TCP-connect) |
| `./proxy-scanner.sh --no-install` | не устанавливать libpcap автоматически |
| `./proxy-scanner.sh --renderer glow` | любые другие аргументы передаются программе (здесь — OpenGL вместо wgpu) |

Если вы уже вошли в графический сеанс как root, скрипт просто запускает программу.

## Ручной запуск от root

Зачем: masscan отправляет пакеты напрямую через libpcap, для этого нужны права root
(или `CAP_NET_RAW`). Режиму TCP-connect root не нужен.

По умолчанию root не может открыть окно на экране вашего пользователя, поэтому
`sudo ./proxy-scanner` падает с ошибкой вида «cannot open display». Порядок действий:

1. Разрешить root доступ к экрану (от вашего пользователя, без sudo):

   ```bash
   xhost +si:localuser:root
   ```

2. Запустить программу с переменными экрана:

   ```bash
   sudo --preserve-env=DISPLAY,XAUTHORITY ./proxy-scanner
   ```

3. После работы отозвать доступ:

   ```bash
   xhost -si:localuser:root
   ```

На Wayland (GNOME, KDE) это тоже работает — окно открывается через XWayland.
Если нет `xhost`: пакет `x11-xserver-utils` (Debian/Ubuntu/Astra) или `xhost` (RHEL-подобные).

### Без запуска интерфейса от root

Права можно выдать только masscan, а программу запускать обычным пользователем:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./masscan
```

```bash
./proxy-scanner
```

Индикатор в шапке покажет «обычный пользователь», но masscan запустится с нужными правами.

## libpcap

Нужна только для режима masscan.

Debian / Ubuntu / Astra Linux:

```bash
sudo apt install libpcap0.8
```

RHEL / Alma / Rocky / РЕД ОС:

```bash
sudo dnf install libpcap
```

В закрытом контуре пакет можно заранее скачать на машине с доступом к репозиторию
(`apt download libpcap0.8`, `dnf download libpcap`) и установить локально
(`sudo dpkg -i libpcap0.8_*.deb`, `sudo rpm -i libpcap-*.rpm`).

## Лимит открытых файлов

Каждое одновременное подключение в режиме TCP-connect — открытый файл. Стандартный лимит
обычно 1024; при большем числе подключений появятся ошибки «Too many open files».
Скрипт поднимает лимит сам. Вручную — в той же оболочке, из которой запускается программа:

```bash
sudo -s
```

```bash
ulimit -n 65535
```

```bash
./proxy-scanner
```

## Если окно не открывается

- Запустите из терминала и посмотрите текст ошибки.
- Проблемы с видеодрайвером: `./proxy-scanner.sh --renderer glow`.
- Ошибка «cannot open display» при запуске от root — не выполнен шаг с `xhost`
  или не переданы переменные `DISPLAY` / `XAUTHORITY`.

Параметры для максимальной скорости сканирования — в [TUNING.md](TUNING.md).
