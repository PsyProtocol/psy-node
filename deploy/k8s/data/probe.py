#!/usr/bin/env python3
"""In-cluster stdlib RESP and NATS/JetStream probes; no secrets on stdout."""
import base64
import json
from pathlib import Path
import socket
import sys
import uuid


def require(ok, why):
    if not ok:
        raise ValueError(why)


def password(name):
    return Path('/credentials/' + name + '/app-password').read_text().strip()


class RedisError(Exception):
    pass


class RESP:
    def __init__(self):
        self.socket = socket.create_connection(('valkey.psy-data.svc.cluster.local', 6379), timeout=5)
        self.file = self.socket.makefile('rb')

    def command(self, *args):
        parts = [str(a).encode() for a in args]
        self.socket.sendall(b'*'+str(len(parts)).encode()+b'\r\n'+b''.join(b'$'+str(len(p)).encode()+b'\r\n'+p+b'\r\n' for p in parts))
        return self.read()

    def read(self):
        line = self.file.readline()
        require(line.endswith(b'\r\n'), 'Invalid RESP framing')
        typ, value = line[:1], line[1:-2]
        if typ == b'-':
            raise RedisError(value.decode())
        if typ == b'+':
            return value.decode()
        if typ == b':':
            return int(value)
        if typ == b'$':
            n = int(value)
            if n == -1:
                return None
            body = self.file.read(n)
            require(self.file.read(2) == b'\r\n', 'Invalid bulk framing')
            return body.decode()
        raise ValueError('Unexpected RESP result')

    def close(self):
        self.file.close()
        self.socket.close()


def valkey(run, phase):
    r = RESP()
    try:
        require(r.command('AUTH', 'psy_app', password('valkey')) == 'OK', 'Valkey auth failed')
        key, value = 'psy:lab-probe:'+run, 'persistent-'+run
        if phase == 'write':
            require(r.command('SET', key, value) == 'OK', 'Valkey write failed')
            temp = key+':crud'
            require(r.command('SET', temp, 'one') == 'OK', 'Valkey create failed')
            require(r.command('SET', temp, 'two') == 'OK' and r.command('GET', temp) == 'two', 'Valkey update failed')
            require(r.command('DEL', temp) == 1 and r.command('GET', temp) is None, 'Valkey delete failed')
        require(r.command('GET', key) == value, 'Valkey persistence/read failed')
        for args in [('CONFIG', 'GET', '*'), ('SET', 'outside-prefix', 'bad')]:
            try:
                r.command(*args)
            except RedisError as e:
                require('NOPERM' in str(e), 'Unexpected ACL failure')
            else:
                raise ValueError('Valkey app permission exceeded')
    finally:
        r.close()
    bad = RESP()
    try:
        try:
            bad.command('AUTH', 'psy_app', 'deliberately-invalid')
        except RedisError as e:
            require('WRONGPASS' in str(e), 'Wrong password was not rejected by auth')
        else:
            raise ValueError('Invalid Valkey password accepted')
    finally:
        bad.close()


class NatsError(Exception):
    pass


class NATS:
    def __init__(self, secret):
        self.socket = socket.create_connection(('nats.psy-data.svc.cluster.local', 4222), timeout=8)
        self.file = self.socket.makefile('rb')
        require(self.file.readline().startswith(b'INFO '), 'Missing NATS greeting')
        self.socket.sendall(b'CONNECT '+json.dumps({'user': 'psy_app', 'pass': secret, 'verbose': False, 'pedantic': True}).encode()+b'\r\nPING\r\n')
        while self.line() != b'PONG':
            pass
        self.sid = 0

    def line(self):
        while True:
            raw = self.file.readline()
            require(raw.endswith(b'\r\n'), 'NATS connection closed')
            line = raw[:-2]
            if line == b'PING':
                self.socket.sendall(b'PONG\r\n')
                continue
            if line.startswith(b'-ERR'):
                raise NatsError(line.decode())
            return line

    def request(self, subject, payload):
        inbox = '_INBOX.psy_lab.'+uuid.uuid4().hex
        self.sid += 1
        sid = str(self.sid)
        self.socket.sendall(('SUB '+inbox+' '+sid+'\r\nUNSUB '+sid+' 1\r\nPUB '+subject+' '+inbox+' '+str(len(payload))+'\r\n').encode()+payload+b'\r\n')
        while True:
            header = self.line()
            if header.startswith(b'MSG '):
                parts = header.split()
                require(parts[1].decode() == inbox and parts[2].decode() == sid, 'Unexpected NATS reply')
                n = int(parts[-1])
                body = self.file.read(n)
                require(self.file.read(2) == b'\r\n', 'Invalid NATS message framing')
                return json.loads(body)

    def close(self):
        self.file.close()
        self.socket.close()


def nats(run, phase):
    client = NATS(password('nats'))
    stream, subject, value = 'LAB_'+run.upper(), 'psy.lab-probe.'+run, ('persistent-'+run).encode()
    try:
        if phase == 'write':
            created = client.request('$JS.API.STREAM.CREATE.'+stream, json.dumps({'name': stream, 'subjects': [subject], 'storage': 'file', 'num_replicas': 1, 'max_msgs': 10, 'max_bytes': 65536}).encode())
            require('error' not in created and created['config']['storage'] == 'file', 'JetStream file stream creation failed')
            ack = client.request(subject, value)
            require(ack.get('stream') == stream and ack.get('seq') == 1, 'JetStream publish ack failed')
        response = client.request('$JS.API.STREAM.MSG.GET.'+stream, json.dumps({'last_by_subj': subject}).encode())
        require('error' not in response and base64.b64decode(response['message']['data']) == value, 'JetStream persistence/read failed')
    finally:
        client.close()
    try:
        bad = NATS('deliberately-invalid')
    except NatsError as e:
        require('Authorization Violation' in str(e), 'Unexpected NATS authentication error')
    else:
        bad.close()
        raise ValueError('Invalid NATS credentials accepted')


def tcp(services, denied):
    failures = []
    for name, port in services.items():
        try:
            with socket.create_connection((name+'.psy-data.svc.cluster.local', port), timeout=3):
                pass
        except (ConnectionRefusedError, TimeoutError):
            failures.append(name)
    require(len(failures) == (len(services) if denied else 0), 'Unexpected TCP allow/deny set')


if __name__ == '__main__':
    try:
        operation, run, phase = sys.argv[1:]
        require(len(run) == 8 and all(c in '0123456789abcdef' for c in run), 'Invalid test ID')
        if operation == 'valkey':
            valkey(run, phase)
        elif operation == 'nats':
            nats(run, phase)
        elif operation == 'tcp':
            tcp({'postgres-services':5432,'postgres-envio':5432,'scylla':9042,'valkey':6379,'nats':4222}, phase == 'deny')
        else:
            raise ValueError('Unknown probe')
        print(operation+' '+phase+' passed')
    except Exception as exc:
        # Never print auth payloads or credential-bearing server responses.
        print('Probe failed: '+type(exc).__name__, file=sys.stderr)
        sys.exit(1)
