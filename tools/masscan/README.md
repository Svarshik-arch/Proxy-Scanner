# masscan64.exe

Сборка [masscan](https://github.com/robertdavidgraham/masscan) для Windows x64,
используется программой Proxy Scanner в режиме «masscan».

Использование: положите `masscan64.exe` в одну папку с `proxy-scanner.exe`
(или укажите путь в программе). На рабочей станции нужны установленный
[Npcap](https://npcap.com/) и запуск от имени администратора.

## Происхождение

| | |
|---|---|
| Исходники | https://github.com/robertdavidgraham/masscan, тег `1.3.2` |
| Коммит | `06902c40d1494881c17b7968ef530e1d6bbd320c` (сверяется при сборке) |
| Сборка | GitHub Actions, задача `masscan` в `.github/workflows/build.yml`, MSVC, `/O2 /MT` (статический CRT) |
| Изменения в исходниках | одно: в `src/string_s.h` условие `(_MSC_VER == 1900)` заменено на `(_MSC_VER >= 1900)`, чтобы код собирался современным MSVC |
| SHA-256 `masscan64.exe` | `2977f07406a84623685f264e8020b6c86cd0b5fbf1605cc4ccd4b960899f7b1d` |

## Лицензия

masscan распространяется по GNU AGPL v3 (см. `LICENSE`). Исходный код
соответствует указанному коммиту с изменением, описанным выше.
