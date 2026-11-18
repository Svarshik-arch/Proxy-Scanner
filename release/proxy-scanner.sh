#!/usr/bin/env bash
# Запуск Proxy Scanner на Linux со всеми подготовительными шагами:
#   * поднимает лимит открытых файлов (нужно для TCP-connect с 1000+ подключений);
#   * проверяет libpcap (нужна masscan) и при отсутствии предлагает установить её;
#   * разрешает root выводить окно на экран текущего пользователя (xhost)
#     и перезапускает программу через sudo, передавая переменные экрана;
#   * после выхода из программы отзывает разрешение xhost.
#
# Использование (положите скрипт рядом с proxy-scanner и masscan):
#   ./proxy-scanner.sh                 # запуск от root (по умолчанию)
#   ./proxy-scanner.sh --caps          # без root: права выдаются только masscan (setcap)
#   ./proxy-scanner.sh --user          # обычный пользователь, без masscan-прав
#   ./proxy-scanner.sh --no-install    # не устанавливать libpcap автоматически
#   ./proxy-scanner.sh --renderer glow # остальные аргументы передаются программе

set -u

DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
APP="$DIR/proxy-scanner"
MASSCAN="$DIR/masscan"
NOFILE=65535

MODE="root"
INSTALL=1
APP_ARGS=()
for a in "$@"; do
    case "$a" in
        --caps) MODE="caps" ;;
        --user) MODE="user" ;;
        --no-install) INSTALL=0 ;;
        --as-root) MODE="as-root" ;;
        -h|--help)
            sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) APP_ARGS+=("$a") ;;
    esac
done

say()  { printf '\033[1;36m[proxy-scanner]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[proxy-scanner]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[proxy-scanner]\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "$APP" ] || die "не найден $APP — положите скрипт рядом с программой"
[ -x "$APP" ] || chmod +x "$APP" 2>/dev/null || die "не удалось сделать $APP исполняемым"
[ -f "$MASSCAN" ] && [ ! -x "$MASSCAN" ] && chmod +x "$MASSCAN" 2>/dev/null

is_root() { [ "$(id -u)" -eq 0 ]; }

# Запуск команды с правами root (сам скрипт может быть уже под root).
as_root() {
    if is_root; then "$@"; else sudo "$@"; fi
}

raise_nofile() {
    local hard
    hard="$(ulimit -Hn)"
    if [ "$hard" != "unlimited" ] && [ "$hard" -lt "$NOFILE" ]; then
        if is_root; then
            ulimit -Hn "$NOFILE" 2>/dev/null && hard="$NOFILE"
        fi
    fi
    local want="$NOFILE"
    [ "$hard" != "unlimited" ] && [ "$hard" -lt "$want" ] && want="$hard"
    if ulimit -Sn "$want" 2>/dev/null; then
        say "лимит открытых файлов: $(ulimit -Sn)"
    else
        warn "не удалось поднять лимит открытых файлов (сейчас $(ulimit -Sn)); \
в режиме TCP-connect ставьте не больше $(( $(ulimit -Sn) - 100 )) подключений"
    fi
}

have_libpcap() {
    ldconfig -p 2>/dev/null | grep -q 'libpcap\.so' && return 0
    local d
    for d in /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu /usr/lib64 /lib64 /usr/lib /usr/local/lib; do
        compgen -G "$d/libpcap.so*" >/dev/null 2>&1 && return 0
    done
    return 1
}

install_libpcap() {
    if command -v apt-get >/dev/null 2>&1; then
        as_root apt-get install -y -qq libpcap0.8 || as_root apt-get install -y -qq libpcap0.8t64
    elif command -v dnf >/dev/null 2>&1; then
        as_root dnf install -y -q libpcap
    elif command -v yum >/dev/null 2>&1; then
        as_root yum install -y -q libpcap
    elif command -v zypper >/dev/null 2>&1; then
        as_root zypper --non-interactive install libpcap1
    else
        return 1
    fi
}

check_libpcap() {
    if have_libpcap; then
        say "libpcap найдена"
        return
    fi
    if [ "$INSTALL" -eq 1 ]; then
        say "libpcap не найдена — устанавливаю (нужна для режима masscan)"
        if install_libpcap && have_libpcap; then
            say "libpcap установлена"
            return
        fi
    fi
    warn "libpcap не установлена: режим masscan работать не будет, TCP-connect работает"
    warn "установите вручную: apt install libpcap0.8 (Debian/Ubuntu/Astra) или dnf install libpcap"
}

run_app() {
    say "запуск: $APP ${APP_ARGS[*]:-}"
    "$APP" ${APP_ARGS[@]+"${APP_ARGS[@]}"}
}

case "$MODE" in
    as-root)
        # Вторая стадия: мы уже под root (вызваны из этого же скрипта через sudo).
        raise_nofile
        check_libpcap
        run_app
        exit $?
        ;;

    user)
        raise_nofile
        check_libpcap
        run_app
        exit $?
        ;;

    caps)
        # Права на «сырые» сокеты получает только masscan, интерфейс — от пользователя.
        check_libpcap
        if [ -f "$MASSCAN" ]; then
            command -v setcap >/dev/null 2>&1 || die "нет утилиты setcap (пакет libcap2-bin / libcap)"
            if ! getcap "$MASSCAN" 2>/dev/null | grep -q cap_net_raw; then
                say "выдаю masscan права cap_net_raw,cap_net_admin (потребуется пароль sudo)"
                as_root setcap cap_net_raw,cap_net_admin=eip "$MASSCAN" \
                    || warn "setcap не удался (файловая система без поддержки capabilities?)"
            fi
        else
            warn "masscan не найден рядом с программой — режим masscan будет недоступен"
        fi
        raise_nofile
        run_app
        exit $?
        ;;

    root)
        if is_root; then
            raise_nofile
            check_libpcap
            run_app
            exit $?
        fi
        command -v sudo >/dev/null 2>&1 || die "нет sudo: войдите как root или запустите с --caps"

        # Разрешаем root выводить окно на наш экран (X11 и XWayland).
        GRANTED=0
        if [ -n "${DISPLAY:-}" ]; then
            if command -v xhost >/dev/null 2>&1; then
                if xhost +si:localuser:root >/dev/null 2>&1; then
                    GRANTED=1
                    say "root временно получил доступ к экрану $DISPLAY"
                fi
            else
                warn "нет утилиты xhost (пакет x11-xserver-utils / xhost) — окно от root может не открыться"
            fi
        else
            warn "переменная DISPLAY не задана — запускайте скрипт из графического сеанса"
        fi
        revoke() {
            if [ "$GRANTED" -eq 1 ]; then
                xhost -si:localuser:root >/dev/null 2>&1 && say "доступ root к экрану отозван"
            fi
        }
        trap revoke EXIT INT TERM

        sudo --preserve-env=DISPLAY,XAUTHORITY,LANG,LC_ALL \
            "$(readlink -f "$0")" --as-root \
            $([ "$INSTALL" -eq 0 ] && echo --no-install) \
            ${APP_ARGS[@]+"${APP_ARGS[@]}"}
        exit $?
        ;;
esac
