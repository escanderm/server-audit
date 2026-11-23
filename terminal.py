"""Terminal presentation only; never runs audit commands or changes findings."""
import collections
import os
import shutil
import sys
import textwrap

LABELS = {'PASS': 'ОК', 'WARN': 'ВНИМАНИЕ', 'FAIL': 'ПРОБЛЕМА',
          'UNKNOWN': 'НЕ ПРОВЕРЕНО', 'INFO': 'ИНФО'}
COLORS = {'PASS': '32', 'WARN': '33', 'FAIL': '31', 'UNKNOWN': '35', 'INFO': '36'}
TITLES = {
    'SSH permitrootlogin': 'Вход root по SSH',
    'SSH passwordauthentication': 'Парольный вход по SSH',
    'SSH kbdinteractiveauthentication': 'Интерактивный вход по SSH',
    'SSH pubkeyauthentication': 'Вход по SSH-ключу',
    'SSH scope': 'Область проверки SSH', 'Loopback sockets': 'Локальные сокеты',
    'Non-loopback sockets': 'Сетевые сокеты', 'Internet exposure': 'Доступ из интернета',
    'UFW': 'Firewall UFW', 'Container forwarding': 'Трафик контейнеров',
    'Reboot required': 'Нужна перезагрузка', 'Root filesystem': 'Диск',
    'Memory availability': 'Память', 'Load average': 'Нагрузка',
    'Failed systemd units': 'Сбои служб', 'Running services': 'Работающие службы',
    'Available updates': 'Обновления', 'APT metadata age': 'Индексы APT',
    'Automatic updates schedule': 'Автоматические обновления',
    'APT recent errors': 'Ошибки APT за 24 часа', 'Sudo logging': 'Журнал sudo',
    'Fail2ban SSH jail': 'Fail2ban / SSH', 'Host SUID files': 'SUID на хосте',
    'Docker port mappings': 'Порты Docker',
    'Kubernetes published services': 'Публикации Kubernetes',
    'Kubernetes pod health': 'Состояние подов', 'Scheduled jobs': 'Задания по расписанию',
}
SECTIONS = {
    'ssh': 'Доступ и SSH', 'network': 'Сеть и firewall', 'system': 'Состояние сервера',
    'updates': 'Обновления', 'logging': 'Журналы и защита',
    'suid': 'Системные файлы', 'containers': 'Docker и Kubernetes',
}


class Terminal:
    def __init__(self, color='auto', stream=None, width=None):
        self.stream = stream or sys.stdout
        self.width = max(40, min(width or shutil.get_terminal_size((100, 24)).columns, 120))
        self.color = color == 'always' or (color == 'auto' and self.stream.isatty()
                     and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb')

    def paint(self, text, code):
        return '\033[' + code + 'm' + text + '\033[0m' if self.color else text

    def line(self, text=''):
        print(text, file=self.stream, flush=True)

    def paragraph(self, text, indent=4):
        for part in str(text).expandtabs(4).splitlines():
            for line in textwrap.wrap(part, max(12, self.width - indent),
                                      replace_whitespace=False) or ['']:
                self.line(' ' * indent + line)

    def header(self, version, host):
        self.line()
        self.line(self.paint('SERVER AUDIT', '1;36') + '  ' + self.paint('v' + version, '2'))
        self.line(self.paint(host + '  ·  аудит без изменения настроек', '2'))
        self.line(self.paint('─' * self.width, '2'))

    def section(self, key):
        self.line()
        self.line(self.paint(SECTIONS.get(key, key).upper(), '1'))

    def finding(self, row):
        status, name = row['status'], row['name']
        self.line('  ' + self.paint('● ' + LABELS.get(status, status), COLORS.get(status, '0'))
                  + '  ' + TITLES.get(name, name))
        detail = row['detail']
        if name == 'Internet exposure':
            detail = 'Проверки извне не было. Слушающий порт сам по себе не доказывает доступность из интернета.'
        elif name == 'Container forwarding':
            detail = 'Есть цепочки Docker/Kubernetes. Одного статуса UFW недостаточно для оценки проброшенного трафика.'
        elif name == 'APT recent errors':
            lines = list(dict.fromkeys(detail.splitlines()))
            detail = '\n'.join(lines) + '\nИстория за 24 часа: запись об ошибке может оставаться после её исправления.'
        self.paragraph(detail)

    def table(self, headers, rows):
        # Stack fields on narrow terminals; never chop long pod names or IPv6.
        if self.width < 90:
            for row in rows:
                for title, value in zip(headers, row):
                    self.paragraph(title + ': ' + str(value), 4)
                self.line()
            return
        widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
        if sum(widths) + 3 * (len(headers) - 1) > self.width - 4:
            for row in rows:
                self.paragraph('  ·  '.join(str(v) for v in row))
            return
        def formatted(row):
            return '    ' + '   '.join(str(v).ljust(w) for v, w in zip(row, widths)).rstrip()
        self.line(self.paint(formatted(headers), '2'))
        for row in rows:
            self.line(formatted(row))

    def structured(self, row, evidence):
        name = row['name']
        if name == 'Non-loopback sockets':
            rows = [[x['protocol'].upper(), x['address'], x['port'], ', '.join(x['processes']) or '—']
                    for x in evidence.get('listeners', []) if x['scope'] != 'loopback']
            headers = ['Протокол', 'Адрес', 'Порт', 'Процесс']
        elif name == 'Kubernetes published services':
            rows = [[s['namespace'] + '/' + s['name'], s['type'],
                     ', '.join(str(p['port']) + ((' → ' + str(p['nodePort'])) if p.get('nodePort') else '')
                               for p in s['ports'])] for s in evidence.get('kubernetes_external_services', [])]
            headers = ['Сервис', 'Тип', 'Порт → NodePort']
        elif name == 'Scheduled jobs':
            rows = [[x['job'], x['schedule'], x['lastSuccess'] or 'нет успешных запусков',
                     'пауза' if x['suspended'] else 'активно'] for x in evidence.get('cronjobs', [])]
            headers = ['Задание', 'Расписание', 'Последний успех (UTC)', 'Состояние']
        else:
            return False
        self.line('  ' + self.paint('● ' + LABELS[row['status']], COLORS[row['status']])
                  + '  ' + TITLES.get(name, name))
        if rows:
            self.table(headers, rows)
        else:
            self.paragraph('Нет записей.')
        if name == 'Kubernetes published services':
            self.paragraph('Инвентаризация NAT, а не проверка доступа извне.')
        if name == 'Scheduled jobs':
            self.paragraph('Успех задания не заменяет проверку восстановления.')
        return True

    def summary(self, findings, folder):
        self.line()
        self.line(self.paint('─' * self.width, '2'))
        counts = collections.Counter(x['status'] for x in findings)
        for status in ['FAIL', 'WARN', 'UNKNOWN', 'PASS', 'INFO']:
            if counts[status]:
                self.line('  ' + self.paint(LABELS[status] + ': ' + str(counts[status]), COLORS[status]))
        self.line()
        self.line('  Полный отчёт:')
        self.paragraph(str(folder / 'report.md'))
        self.paragraph('JSON: ' + str(folder / 'report.json'))
        self.line()
