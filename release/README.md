# Готовые программы

Скачайте оба файла в одну папку на рабочей станции (Windows 10/11 x64):

| Файл | Назначение |
|---|---|
| `proxy-scanner.exe` | Proxy Scanner — сама программа. Работает без установки и без интернета. |
| `masscan64.exe` | Внешний сканер для режима «masscan». Нужен только в этом режиме. |

Режим «TCP-connect» работает только с `proxy-scanner.exe`.
Для режима «masscan» дополнительно нужны установленный [Npcap](https://npcap.com/)
и запуск программы от имени администратора.

## proxy-scanner.exe

| | |
|---|---|
| Исходники | этот репозиторий, коммит `36e095a` |
| Сборка | GitHub Actions, задача `windows` в `.github/workflows/build.yml`, `cargo build --release --target x86_64-pc-windows-msvc`, статический CRT (`+crt-static`) |
| SHA-256 | `36a4715a96b03a6e832563e389696c7a4472be95e6aa46677357b9609dd52f62` |

## masscan64.exe

Сборка [masscan](https://github.com/robertdavidgraham/masscan) для Windows x64.

| | |
|---|---|
| Исходники | https://github.com/robertdavidgraham/masscan, тег `1.3.2` |
| Коммит | `06902c40d1494881c17b7968ef530e1d6bbd320c` (сверяется при сборке) |
| Сборка | GitHub Actions, задача `masscan` в `.github/workflows/build.yml`, MSVC, `/O2 /MT` (статический CRT) |
| Изменения в исходниках | одно: в `src/string_s.h` условие `(_MSC_VER == 1900)` заменено на `(_MSC_VER >= 1900)`, чтобы код собирался современным MSVC |
| SHA-256 | `2977f07406a84623685f264e8020b6c86cd0b5fbf1605cc4ccd4b960899f7b1d` |

masscan распространяется по GNU AGPL v3 (см. `masscan-LICENSE`). Исходный код
соответствует указанному коммиту с изменением, описанным выше.

## Проверка файлов

```powershell
Get-FileHash .\proxy-scanner.exe, .\masscan64.exe -Algorithm SHA256
```

Значения должны совпасть с приведёнными выше.

Файлы в этой папке не обновляются автоматически: после изменений в коде свежая
сборка появляется в артефактах GitHub Actions, а сюда её нужно положить отдельно.
