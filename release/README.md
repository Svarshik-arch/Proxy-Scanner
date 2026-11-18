# Готовые программы

| Файл | ОС | Назначение |
|---|---|---|
| `proxy-scanner.exe` | Windows 10/11 x64 | Proxy Scanner — сама программа |
| `masscan64.exe` | Windows 10/11 x64 | Внешний сканер для режима «masscan» |
| `proxy-scanner` | Linux x86_64 | Proxy Scanner — сама программа |
| `masscan` | Linux x86_64 | Внешний сканер для режима «masscan» |
| `proxy-scanner.sh` | Linux | Скрипт запуска: лимиты, libpcap, root и доступ к экрану |

Скачайте программу и (при необходимости) masscan для своей ОС в одну папку —
Proxy Scanner найдёт masscan рядом с собой. Режим «TCP-connect» работает и без masscan.

Файл сессии `proxy-scanner-session.json` создаётся рядом с программой; его можно
перенести на другой ПК (в том числе между Windows и Linux) и продолжить сканирование.

## Windows

- Работает без установки и без интернета, библиотеки вшиты (статический CRT).
- Для режима «masscan» нужны [Npcap](https://npcap.com/) и запуск от имени администратора
  (в программе есть кнопка перезапуска с повышением прав).

## Linux

- Нужна glibc 2.35 или новее (Ubuntu 22.04+, Debian 12+, RHEL/Alma/Rocky 10, Astra Linux 1.8+ и т. п.)
  и графический сеанс X11 или Wayland.
- Скачайте `proxy-scanner`, `masscan` и `proxy-scanner.sh` в одну папку и запустите скрипт:

  ```bash
  chmod +x proxy-scanner masscan proxy-scanner.sh
  ```

  ```bash
  ./proxy-scanner.sh
  ```

  Скрипт поднимает лимит открытых файлов, проверяет и при необходимости ставит libpcap,
  разрешает root открыть окно на вашем экране, запускает программу через `sudo` и после
  выхода отзывает доступ. Вариант без root для интерфейса: `./proxy-scanner.sh --caps`
  (права получает только masscan).
- Подробно, в том числе ручной запуск: [docs/LINUX.md](../docs/LINUX.md).
  Параметры для максимальной скорости: [docs/TUNING.md](../docs/TUNING.md).

## Происхождение

Все файлы собраны в GitHub Actions (`.github/workflows/build.yml`).

| Файл | Исходники | Сборка | SHA-256 |
|---|---|---|---|
| `proxy-scanner.exe` | этот репозиторий, коммит `b61c2a9` | `cargo build --release --target x86_64-pc-windows-msvc`, `+crt-static` | `b0ffe7d70a1c2550c061d9077c419b91aebe3d2d5fcc39c042ff256f06cd906c` |
| `proxy-scanner` | этот репозиторий, коммит `b61c2a9` | `cargo build --release --target x86_64-unknown-linux-gnu`, Ubuntu 22.04 | `a50814f517aa119afa06284a8a9b254dda2ce1bbb9c3e0f8a462d6c6905978d4` |
| `masscan64.exe` | masscan 1.3.2, коммит `06902c40d149` | MSVC `/O2 /MT` | `20af5c993dd2cf5db34945dad063d440ad124cbe92de2a3bed970122371e602e` |
| `masscan` | masscan 1.3.2, коммит `06902c40d149` | `make`, Ubuntu 22.04 | `a1402e717a1bad5b6710dfcf2dc49b8c6501de03ede4e04a421452fdabf0a4ce` |

masscan — [github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan),
тег `1.3.2`, коммит `06902c40d1494881c17b7968ef530e1d6bbd320c` (сверяется при сборке).
Для Windows в исходники внесено одно изменение: в `src/string_s.h` условие
`(_MSC_VER == 1900)` заменено на `(_MSC_VER >= 1900)`, чтобы код собирался современным MSVC.
Для Linux исходники не менялись. masscan распространяется по GNU AGPL v3 (см. `masscan-LICENSE`).

## Проверка файлов

Windows (PowerShell):

```powershell
Get-FileHash .\proxy-scanner.exe, .\masscan64.exe -Algorithm SHA256
```

Linux:

```bash
sha256sum proxy-scanner masscan
```

Значения должны совпасть с приведёнными в таблице.

Файлы в этой папке не обновляются автоматически: после изменений в коде свежая сборка
появляется в артефактах GitHub Actions, а сюда её нужно положить отдельно.
