#!/usr/bin/env bash
set -eu

install_hint() {
    printf '\nДля запуска нужен Python 3.9 или новее.\n' >&2
    if command -v apt-get >/dev/null 2>&1; then
        printf 'Ubuntu/Debian:\n  sudo apt-get update\n  sudo apt-get install -y python3 python3-apt\n' >&2
    elif command -v dnf >/dev/null 2>&1; then
        printf 'Fedora/RHEL:\n  sudo dnf install python3\n' >&2
    elif command -v yum >/dev/null 2>&1; then
        printf 'RHEL/CentOS:\n  sudo yum install python3\n' >&2
    elif command -v apk >/dev/null 2>&1; then
        printf 'Alpine (от root):\n  apk add python3 bash\n' >&2
    elif command -v pacman >/dev/null 2>&1; then
        printf 'Arch:\n  sudo pacman -S python\n' >&2
    elif command -v zypper >/dev/null 2>&1; then
        printf 'openSUSE:\n  sudo zypper install python3\n' >&2
    else
        printf 'Установите Python 3.9+ через пакетный менеджер вашей системы.\n' >&2
    fi
    printf '\nВ старых дистрибутивах пакет python3 может быть старее 3.9.\nПроверьте: python3 --version\nЗатем повторите исходную команду запуска аудитора.\nНичего автоматически не установлено.\n' >&2
}

if ! command -v python3 >/dev/null 2>&1; then
    printf 'Python 3 не найден. Аудит не запущен.\n' >&2
    install_hint
    exit 1
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    printf 'Не удалось запустить Python 3.9+. Аудит не запущен.\n' >&2
    install_hint
    exit 1
fi

if command -v apt-get >/dev/null 2>&1 && ! python3 -c 'import apt' >/dev/null 2>&1; then
    printf 'Подсказка: модуль python3-apt недоступен; проверка обновлений будет «Не проверено».\nУстановить: sudo apt-get install python3-apt\nЕсли пакет уже установлен, используйте системный /usr/bin/python3.\n\n' >&2
fi

exec python3 "$(cd -- "$(dirname -- "$0")" && pwd)/audit.py" "$@"
