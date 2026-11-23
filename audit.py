#!/usr/bin/env python3
"""Read-only Linux host/Kubernetes audit. Python standard library only."""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from terminal import Terminal

VERSION = '1.1.1'


def clean(value):
    return ''.join(c if c in '\n\t' or c.isprintable() else '?' for c in str(value))


def run(argv, timeout=20, raw=False):
    """No shell, bounded wall time; errors are not interpreted as empty success."""
    if not shutil.which(argv[0]):
        return {'ok': False, 'error': 'command unavailable: ' + argv[0]}
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, 'LC_ALL': 'C', 'SYSTEMD_PAGER': 'cat'})
        return {'ok': p.returncode == 0, 'code': p.returncode,
                'out': p.stdout if raw else clean(p.stdout), 'error': clean(p.stderr)[:1500]}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'timeout after %ss' % timeout}
    except OSError as e:
        return {'ok': False, 'error': str(e)}


def scope(address):
    address = address.split('%')[0].strip('[]')
    if address in ('*', '0.0.0.0', '::'):
        return 'all interfaces'
    try:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback:
            return 'loopback'
        if ip.is_link_local:
            return 'link-local'
        return 'global address' if ip.is_global else 'private address'
    except ValueError:
        return 'unknown'


def listeners(text):
    result = []
    for line in text.splitlines():
        fields = line.split(None, 6)
        if len(fields) < 6 or fields[0] not in ('tcp', 'udp'):
            continue
        address, sep, port = fields[4].rpartition(':')
        if not sep or not port.isdigit():
            continue
        # Extract process names only, never full command lines or arguments.
        processes = sorted(set(re.findall(r'\("([^"\n]+)"', fields[6] if len(fields) > 6 else '')))
        result.append({'protocol': fields[0], 'address': address, 'port': int(port),
                       'scope': scope(address), 'processes': processes})
    return result


def effective_sshd(text):
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition(' ')
        if sep:
            result.setdefault(key, []).append(value)
    return result


def read(path):
    try:
        return Path(path).read_text(errors='replace').strip()
    except OSError:
        return ''


class Audit:
    def __init__(self):
        self.findings = []
        self.evidence = {}

    def add(self, status, name, detail):
        self.findings.append({'status': status, 'name': name, 'detail': clean(detail)})

    def command(self, name, args, timeout=20, raw=False):
        r = run(args, timeout, raw)
        if not r['ok']:
            self.add('UNKNOWN', name, r.get('error') or 'exit code %s' % r.get('code'))
            return None
        return r['out']

    def ssh(self):
        text = self.command('Effective SSH configuration', ['sshd', '-T'])
        if text is None:
            return
        config = effective_sshd(text)
        keys = ['permitrootlogin', 'passwordauthentication', 'kbdinteractiveauthentication',
                'pubkeyauthentication', 'authenticationmethods', 'port', 'listenaddress']
        self.evidence['ssh'] = {k: config.get(k, []) for k in keys}
        for key, desired in [('permitrootlogin', 'no'), ('passwordauthentication', 'no'),
                             ('kbdinteractiveauthentication', 'no'), ('pubkeyauthentication', 'yes')]:
            actual = config.get(key, ['unknown'])[0]
            self.add('PASS' if actual == desired else 'WARN', 'SSH ' + key, actual)
        self.add('INFO', 'SSH scope', 'sshd -T shows the default configuration. Match blocks may override it for specific users/addresses. Port 22 is not a vulnerability by itself.')

    def network(self):
        text = self.command('Listening sockets', ['ss', '-H', '-lntup'])
        if text is not None:
            rows = listeners(text)
            self.evidence['listeners'] = rows
            local = [x for x in rows if x['scope'] == 'loopback']
            self.add('INFO', 'Loopback sockets', '%s sockets; these are not directly listening on LAN/WAN interfaces.' % len(local))
            other = [x for x in rows if x['scope'] != 'loopback']
            self.add('INFO', 'Non-loopback sockets', json.dumps(other, ensure_ascii=False))
            self.add('UNKNOWN', 'Internet exposure', 'Not measured from outside this network. Bind addresses, UFW, NAT/NodePort, IPv6 and router forwards must be assessed together. Use --probe from an external machine.')
        text = self.command('Host firewall', ['ufw', 'status', 'verbose'])
        if text is not None:
            self.evidence['ufw'] = text
            active = bool(re.search(r'^Status: active$', text, re.M))
            self.add('INFO' if active else 'WARN', 'UFW', 'Active; rules recorded, effectiveness not assumed.' if active else 'Inactive; inspect any other firewall before judging exposure.')
        rules = self.command('Forwarding firewall', ['iptables', '-S', 'FORWARD'])
        if rules is not None:
            self.evidence['forward_rules'] = rules
            if 'DOCKER' in rules or 'KUBE-' in rules:
                self.add('WARN', 'Container forwarding', 'Docker/Kubernetes chains are present. UFW INPUT status alone does not establish protection for forwarded container traffic.')
        text = self.command('IPv6 addresses', ['ip', '-j', '-6', 'addr', 'show', 'scope', 'global'])
        if text is not None:
            try:
                addresses = [a['local'] for i in json.loads(text) for a in i.get('addr_info', [])]
                self.evidence['ipv6'] = addresses
                self.add('WARN' if any(ipaddress.ip_address(a).is_global for a in addresses) else 'INFO', 'IPv6', ', '.join(addresses) or 'No global-scope IPv6 addresses assigned.')
            except (ValueError, KeyError):
                self.add('UNKNOWN', 'IPv6', 'Could not parse ip output.')

    def system(self):
        self.evidence['host'] = {'hostname': socket.gethostname(), 'kernel': os.uname().release,
                                 'os': read('/etc/os-release'), 'uptime_seconds': read('/proc/uptime').split(' ')[0]}
        reboot = Path('/var/run/reboot-required').exists()
        self.add('WARN' if reboot else 'PASS', 'Reboot required', read('/var/run/reboot-required.pkgs') if reboot else 'No distribution reboot marker. This is not a live-patch assessment.')
        usage = shutil.disk_usage('/')
        percent = usage.used * 100 / usage.total
        self.add('WARN' if percent >= 85 else 'PASS', 'Root filesystem', '%.1f%% used; %.1f GiB free' % (percent, usage.free / 2**30))
        mem = dict(re.findall(r'^(\w+):\s+(\d+)', read('/proc/meminfo'), re.M))
        if 'MemTotal' in mem and 'MemAvailable' in mem:
            used = 100 * (1 - int(mem['MemAvailable']) / int(mem['MemTotal']))
            self.add('WARN' if used >= 90 else 'PASS', 'Memory availability', '%.1f%% unavailable, using MemAvailable (includes reclaimable cache).' % used)
        self.add('INFO', 'Load average', '%s; CPUs: %s. A single sample is not a security finding.' % (os.getloadavg(), os.cpu_count()))
        failed = self.command('Failed systemd units', ['systemctl', 'list-units', '--failed', '--no-legend', '--plain', '--no-pager'])
        if failed is not None:
            self.add('WARN' if failed.strip() else 'PASS', 'Failed systemd units', failed.strip() or 'None.')
        services = self.command('Running services', ['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain', '--no-pager'])
        if services is not None:
            self.evidence['running_services'] = services
            self.add('INFO', 'Running services', '%s; count is inventory, not a security score.' % len(services.splitlines()))

    def updates(self):
        code = """import apt,json
c=apt.Cache()
print(json.dumps([{'name':p.name,'installed':p.installed.version,'candidate':p.candidate.version,'origins':[o.archive for o in p.candidate.origins]} for p in c if p.is_upgradable and p.installed and p.candidate]))
"""
        text = self.command('Package candidates (python3-apt)', ['python3', '-c', code], 45)
        if text is not None:
            try:
                packages = json.loads(text)
                self.evidence['updates'] = packages
                security = [p for p in packages if any(a.endswith('-security') for a in p['origins'])]
                self.add('WARN' if packages else 'PASS', 'Available updates', '%s total; %s candidates present in a security pocket. Remaining updates are not automatically security fixes. Local APT metadata only; no refresh performed.' % (len(packages), len(security)))
            except (ValueError, KeyError):
                self.add('UNKNOWN', 'Available updates', 'Could not parse package candidates.')
        paths = [p for p in Path('/var/lib/apt/lists').glob('*InRelease')
                 if any(pocket in p.name for pocket in ('-updates_', '-security_', '-backports_'))]
        if paths:
            age = (time.time() - min(p.stat().st_mtime for p in paths)) / 86400
            self.add('WARN' if age > 3 else 'INFO', 'APT metadata age', 'Oldest mutable Ubuntu pocket InRelease: %.1f days. Immutable release pocket excluded; timestamps do not prove that the last refresh succeeded.' % age)
        timers = self.command('Automatic updates timer', ['systemctl', 'show', 'apt-daily-upgrade.timer', '-p', 'ActiveState', '-p', 'NextElapseUSecRealtime'])
        if timers is not None:
            self.add('INFO' if 'ActiveState=active' in timers else 'WARN', 'Automatic updates schedule', timers + '\nAn active timer does not prove successful installation.')
        recent = self.command('APT service diagnostics', ['journalctl', '-u', 'apt-daily.service', '-u', 'apt-daily-upgrade.service', '--since', '24 hours ago', '-n', '100', '-o', 'json', '--no-pager'])
        if recent is not None:
            messages = []
            for line in recent.splitlines():
                try:
                    message = str(json.loads(line).get('MESSAGE', ''))
                    if re.search(r'timeout|error|failed', message, re.I):
                        messages.append(message)
                except ValueError:
                    continue
            self.add('WARN' if messages else 'INFO', 'APT recent errors', '\n'.join(messages[-10:]) if messages else 'No matching errors in the bounded journal sample.')

    def logging(self):
        # Count entries, never include sudo command arguments or login messages.
        text = self.command('Sudo journal access', ['journalctl', '_COMM=sudo', '--since', '7 days ago', '-n', '100', '-o', 'json', '--no-pager'])
        if text is not None:
            count = 0
            for line in text.splitlines():
                try:
                    count += 'COMMAND=' in str(json.loads(line).get('MESSAGE', ''))
                except ValueError:
                    continue
            self.add('PASS' if count else 'UNKNOWN', 'Sudo logging', '%s command entries found in last 100 journal records; command contents omitted.' % count if count else 'No command entries in bounded journal sample; does not prove logging is disabled.')
        if shutil.which('fail2ban-client'):
            text = self.command('Fail2ban runtime SSH jail', ['fail2ban-client', 'status', 'sshd'])
            if text is not None:
                self.evidence['fail2ban_sshd'] = text
                self.add('PASS', 'Fail2ban SSH jail', 'Runtime jail query succeeded; action effectiveness and blocked ports still need review.')
        else:
            self.add('INFO', 'Fail2ban', 'Not installed. Other controls may be in use.')

    def suid(self):
        excluded = ['/proc', '/sys', '/dev', '/run', '/snap', '/var/lib/docker',
                    '/var/lib/containerd', '/var/lib/rancher', '/var/lib/kubelet']
        args = ['find', '/', '-xdev', '(']
        for p in excluded:
            if args[-1] != '(':
                args += ['-o']
            args += ['-path', p]
        args += [')', '-prune', '-o', '-type', 'f', '-perm', '-4000', '-print0']
        text = self.command('Host SUID scan', args, 60, raw=True)
        if text is None:
            return
        paths = sorted(p for p in text.split('\0') if p)
        rows = []
        for p in paths:
            owner = run(['dpkg-query', '-S', p], 5)
            try:
                s = os.stat(p, follow_symlinks=False)
            except OSError:
                self.add('UNKNOWN', 'SUID file changed during scan', p)
                continue
            rows.append({'path': p, 'mode': oct(stat.S_IMODE(s.st_mode)), 'uid': s.st_uid,
                         'package': owner.get('out', '').strip() if owner['ok'] else None,
                         'world_writable': bool(s.st_mode & stat.S_IWOTH)})
        self.evidence['suid'] = rows
        dangerous = [r for r in rows if r['world_writable'] or r['uid'] != 0]
        unknown = [r for r in rows if not r['package']]
        self.add('FAIL' if dangerous else 'WARN' if unknown else 'INFO', 'Host SUID files', '%s files; %s not mapped to a dpkg package; %s non-root-owned or world-writable. Package ownership is not an integrity check. Root filesystem only; container layers, /snap and other filesystems excluded.' % (len(rows), len(unknown), len(dangerous)))

    def containers(self):
        if shutil.which('docker'):
            text = self.command('Docker published ports', ['docker', 'ps', '--format', '{{.Names}}\t{{.Ports}}'])
            if text is not None:
                self.evidence['docker_ports'] = text
                self.add('INFO', 'Docker port mappings', text.strip() or 'No running containers.')
        if not shutil.which('k3s'):
            self.add('INFO', 'K3s', 'Not installed; Kubernetes checks skipped.')
            return
        def get(kind):
            text = self.command('Kubernetes ' + kind, ['k3s', 'kubectl', 'get', kind, '-A', '-o', 'json', '--request-timeout=15s'], 25)
            if text is None:
                return None
            try:
                return json.loads(text)['items']
            except (ValueError, KeyError):
                self.add('UNKNOWN', 'Kubernetes ' + kind, 'Invalid JSON response.')
        services = get('services')
        if services is not None:
            rows = []
            for s in services:
                spec = s['spec']
                if spec.get('type') != 'ClusterIP' or spec.get('externalIPs'):
                    rows.append({'namespace': s['metadata']['namespace'], 'name': s['metadata']['name'],
                                 'type': spec.get('type'), 'ports': spec.get('ports', []),
                                 'externalIPs': spec.get('externalIPs', [])})
            self.evidence['kubernetes_external_services'] = rows
            self.add('INFO', 'Kubernetes published services', json.dumps(rows) + '\nNAT ports may not appear in ss; this is inventory, not an external reachability test.')
        pods = get('pods')
        if pods is not None:
            problems = []
            risky = []
            for p in pods:
                m, spec, status = p['metadata'], p['spec'], p.get('status', {})
                ident = m['namespace'] + '/' + m['name']
                if m.get('deletionTimestamp'):
                    continue
                phase = status.get('phase', 'Unknown')
                ready = any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in status.get('conditions', []))
                if phase not in ('Succeeded',) and (phase != 'Running' or not ready):
                    problems.append({'pod': ident, 'phase': phase, 'ready': ready})
                ports = [x for c in spec.get('containers', []) for x in c.get('ports', []) if x.get('hostPort')]
                privileged = any(c.get('securityContext', {}).get('privileged') for c in spec.get('containers', []))
                if spec.get('hostNetwork') or ports or privileged:
                    risky.append({'pod': ident, 'hostNetwork': spec.get('hostNetwork', False), 'hostPorts': ports, 'privileged': privileged})
            self.evidence['kubernetes_special_network_or_privileges'] = risky
            self.add('WARN' if problems else 'PASS', 'Kubernetes pod health', json.dumps(problems) if problems else 'No non-ready running/pending/failed pods. Completed jobs excluded.')
        cronjobs = get('cronjobs')
        if cronjobs is not None:
            rows = [{'job': c['metadata']['namespace'] + '/' + c['metadata']['name'],
                     'schedule': c['spec']['schedule'], 'suspended': c['spec'].get('suspend', False),
                     'lastSuccess': c.get('status', {}).get('lastSuccessfulTime'),
                     'lastSchedule': c.get('status', {}).get('lastScheduleTime')} for c in cronjobs]
            self.evidence['cronjobs'] = rows
            self.add('INFO', 'Scheduled jobs', json.dumps(rows) + '\nA successful job is not proof that restoration was tested.')

    def execute(self, skip_suid=False, terminal=None):
        for fn in [self.ssh, self.network, self.system, self.updates, self.logging,
                   *([] if skip_suid else [self.suid]), self.containers]:
            if terminal:
                terminal.section(fn.__name__)
            start = len(self.findings)
            try:
                fn()
            except Exception as e:
                self.add('UNKNOWN', fn.__name__, type(e).__name__ + ': ' + str(e))
            if terminal:
                for row in self.findings[start:]:
                    if not terminal.structured(row, self.evidence):
                        # Pod problems are structured too, keeping every name visible.
                        if row['name'] == 'Kubernetes pod health' and row['status'] == 'WARN':
                            try:
                                problems = json.loads(row['detail'])
                                terminal.line('  ' + terminal.paint('● ВНИМАНИЕ  Состояние подов', '33'))
                                terminal.table(['Под', 'Фаза', 'Готов'], [[p['pod'], p['phase'], 'да' if p['ready'] else 'нет'] for p in problems])
                                continue
                            except (ValueError, KeyError):
                                pass
                        terminal.finding(row)


def save_report(audit, output):
    base = Path(output).absolute()
    # Require owned private directory; don't follow a planted symlink as root.
    for p in [base, *base.parents]:
        if p.is_symlink():
            raise ValueError('Report path contains a symlink: ' + str(p))
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = base.stat()
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ValueError('Report directory must be owned by current user and mode 0700: ' + str(base))
    folder = Path(tempfile.mkdtemp(prefix=dt.datetime.now().strftime('%Y%m%d-%H%M%S-'), dir=base))
    data = {'version': VERSION, 'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(),
            'host': socket.gethostname(), 'findings': audit.findings, 'evidence': audit.evidence}
    summary = ['# Server audit ' + VERSION, '', 'Host: ' + socket.gethostname(), '',
               'Read-only local assessment. No external telemetry. UNKNOWN means not verified.', '']
    for row in audit.findings:
        summary += ['## [%s] %s' % (row['status'], row['name']), '', row['detail'], '']
    for filename, body in [('report.json', json.dumps(data, ensure_ascii=False, indent=2)), ('report.md', '\n'.join(summary))]:
        fd = os.open(folder / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(body + '\n')
    return folder


def probe(host, ports):
    # Only explicit user target, TCP connect (no exploit payloads or service login).
    rows = []
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError('Invalid TCP port')
        try:
            with socket.create_connection((host, port), timeout=3):
                result = 'TCP connect succeeded'
        except OSError as e:
            result = type(e).__name__ + ': ' + str(e)
        rows.append({'port': port, 'result': result})
    print(json.dumps({'source_host': socket.gethostname(), 'target': host, 'tcp': rows,
                      'note': 'Results apply only to this vantage point. LAN/hairpin probes do not prove internet exposure.'}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', help='Private report directory (owned by current user, 0700)')
    parser.add_argument('--skip-suid', action='store_true')
    parser.add_argument('--color', choices=['auto', 'always', 'never'], default='auto', help='ANSI colors; auto respects NO_COLOR and terminal detection')
    parser.add_argument('--probe', metavar='HOST', help='Explicit TCP test; run from an external machine for WAN evidence')
    parser.add_argument('--ports', default='22,80,443,5000,6443,8090,10250', help='Comma-separated TCP ports for --probe')
    args = parser.parse_args()
    if args.probe:
        probe(args.probe, [int(p) for p in args.ports.split(',')])
        return 0
    if os.uname().sysname != 'Linux':
        parser.error('Host audit requires Linux; --probe can run on macOS.')
    if os.geteuid() != 0:
        print('Running without root: unavailable checks will show UNKNOWN.')
    audit = Audit()
    terminal = Terminal(args.color)
    terminal.header(VERSION, socket.gethostname())
    audit.execute(args.skip_suid, terminal)
    output = args.output or str(Path(__file__).resolve().parent / 'reports')
    folder = save_report(audit, output)
    terminal.summary(audit.findings, folder)
    return 2 if any(r['status'] == 'FAIL' for r in audit.findings) else 0


if __name__ == '__main__':
    raise SystemExit(main())
