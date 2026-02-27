#!/usr/bin/env python3

"""This utility acts a Prometheus exporter (it hosts an HTTP server that can be
scraped for metrics) that client programs can communicate with over a UNIX
domain socket to directly publish their metrics. This is useful for clients that
can natively record their metrics in the Prometheus exposition text format. This
releases the client from the need to host its own in-process HTTP server and the
need to integrate with a third-party Prometheus library.

It works in the following way:

- At startup, prometheus-relay (this Python process) creates a SOCK_SEQPACKET
  PF_UNIX listening socket and starts a lightweight HTTP server

- Clients connect to the UNIX domain socket, to establish a session. The pid of
  the client process will be queried by the server, using the SO_PEERCRED socket
  option

- When a "scrape" (an HTTP get of `/metrics`) occurs, all clients with an active
  socket connection will be sent a UNIX signal (SIGUSR1 by default) which acts
  as a notification that a scrape is now in progress

- Clients respond to this signal by publishing metrics (in Prometheus text
  format) to their socket as soon as possible. Whatever messages are sent over
  these sockets within a timeout period (the "scrape period") are appended to
  the in-progress scrape

- When the in-progress scrape timeout expires, the aggregated response text is
  sent as the HTTP response body

Messages that arrive "too late" (i.e., outside of an active scrape window) are
discarded.

Prometheus exposition text format: https://prometheus.io/docs/instrumenting/exposition_formats/
"""

import argparse
import datetime
import errno
import fcntl
import http.server
import io
import logging
import os
import pathlib
import select
import shlex
import signal
import socket
import sys
import typing

from collections.abc import Mapping
from dataclasses import dataclass
from http.server import HTTPServer

parser = argparse.ArgumentParser(
    description='Relay Prometheus metrics sent from client programs')

parser.add_argument('-v', '--verbose', action='count', default=0,
    help='Be more verbose; can be repeated')

parser.add_argument('-b', '--bind', default='0.0.0.0', type=str,
    metavar='<interface>',
    help='Bind address for the Prometheus exporter HTTP server')

parser.add_argument('-d', '--scrape-duration', default=2, type=int,
    metavar='<seconds>',
    help='Number of seconds to wait for all clients to respond to a scrape')

parser.add_argument('-l', '--labels', action='append', metavar='<label>',
    default=[], help='Label to append to all relayed metrics (can be repeated)')

parser.add_argument('-s', '--signal', default=int(signal.SIGUSR1),
    metavar='<signal>',
    help='Signal to send to clients to notify them of an active scrape')

parser.add_argument('port', type=int, metavar='<port>',
    help='Port on which to host the Prometheus exporter HTTP server')

parser.add_argument('socket_path', metavar='<socket-path>',
    help='Path to the UNIX domain socket that clients will connect to')

socket_path: pathlib.Path|None = None

def cleanup_socket_file():
  if socket_path:
    os.unlink(socket_path)

@dataclass
class Client:
  pid: int
  sock: socket.socket

  def fileno(self) -> int:
    return self.sock.fileno()

class RelayServer:
  """The UNIX domain socket server"""
  def __init__(self, sock: socket.socket, path: pathlib.Path) -> typing.Self:
    self.sock = sock
    self.path = path
    self.client_map: Mapping[int, Client] = dict()
    self.client_epoll = select.epoll()

  def close(self):
    self.sock.close()
    self.client_epoll.close()
    for client in self.client_map.values():
      client.sock.close()

  def accept_new_client(self) -> Client:
    client_sock, addr = self.sock.accept()
    client_sock.setblocking(False)
    client_pid = client_sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED)
    logging.info(f'accepted new client {client_sock.fileno()}:{client_pid}')
    c = Client(client_pid, client_sock)
    self.client_map[c.fileno()] = c
    self.client_epoll.register(c.fileno(), select.EPOLLIN)
    return c

  def remove_client(self, client: Client):
    logging.info(f'removed client {client.fileno()}:{client.pid}')
    self.client_epoll.unregister(client.fileno())
    del self.client_map[client.fileno()]
    client.sock.close()

  def recv_client_messages(self, timeout:float|None) -> list[tuple[Client, bytes]]:
    msgs = list()
    for (fd, event_mask) in self.client_epoll.poll(timeout):
      client = self.client_map[fd]
      if event_mask & (select.EPOLLERR | select.EPOLLHUP | select.EPOLLRDHUP):
        if event_mask & select.EPOLLERR:
          logging.error(f'error on client {client.fileno()}:{client.pid} socket')
        self.remove_client(client)
      elif event_mask & select.EPOLLIN:
        while True:
          try:
            (msg, ancdata, msg_flags, address) = client.sock.recvmsg(1 << 20)
            msgs.append((client, msg))
          except BlockingIOError:
            break
    return msgs

class MetricsServer(HTTPServer):
  """Prometheus HTTP exporter"""
  def __init__(self, *args, scrape_duration: int, labels: list[str],
               **kwargs) -> typing.Self:
    super().__init__(*args, **kwargs)
    self.scrape_duration = scrape_duration
    self.labels = labels
    self.relay_server: RelayServer|None = None

  def close(self):
    if self.relay_server:
      self.relay_server.close()

class RelayHttpRequestHandler(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    logging.debug("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
    if self.path == '/metrics':
      self.do_metrics()
    else:
      self.send_error(404)

  def do_metrics(self):
    relay_server = self.server.relay_server

    # Send all connected clients SIGUSR1
    for client in relay_server.client_map.values():
      os.kill(client.pid, signal.SIGUSR1)

    scrape_period = datetime.timedelta(seconds=self.server.scrape_duration)
    start_time = datetime.datetime.now()
    end_time = start_time + scrape_period
    append_buf = io.StringIO()

    while (time_now := datetime.datetime.now()) < end_time:
      time_left = (end_time - time_now).total_seconds()
      for client, msg in relay_server.recv_client_messages(time_left):
        # Process the Prometheus text format so we can insert any additional
        # labels injected by the relay
        for line in msg.decode('utf-8').split('\n'):
          if not line.strip():
            continue

          if line.startswith('#'):
            # Don't modify comment lines
            append_buf.write(f'{line}\n')
          else:
            enrich_fn = enrich_quoted_client_metric if line.startswith('{') else \
                        enrich_identifier_client_metric
            enrich_fn(shlex.shlex(line), self.server.labels, client, append_buf)
            append_buf.write('\n')

    self.send_response(200)
    self.send_header('Content-type', 'text/plain; version=0.0.4; charset=utf-8; escaping=underscores')
    self.end_headers()
    self.wfile.write(append_buf.getvalue().encode())

def peek_token(lexer: shlex.shlex) -> str|None:
  token = lexer.get_token()
  if token is not None:
    lexer.push_token(token)
  return token

def enrich_quoted_client_metric(lexer: shlex.shlex, labels: list[str],
                                client: Client, append_buf: io.StringIO):
  append_buf.write(lexer.get_token()) # '{'
  append_buf.write(lexer.get_token()) # Quoted metric name
  append_buf.write(','.join(labels))  # Injected labels
  if labels and peek_token(lexer) != '}':
    append_buf.write(',') # ',' separates injected labels and existing ones

  # Until we see '}', all tokens are joined with no whitespace; once we
  # see '}', all tokens are separated by one ' ' character
  finished_labels = False
  while (tok := lexer.get_token()):
    separator = ' ' if finished_labels else ''
    append_buf.write(f'{separator}{tok}')
    finished_labels |= tok == '}'

def enrich_identifier_client_metric(lexer: shlex.shlex, labels: list[str],
                                    client: Client, append_buf: io.StringIO):
  append_buf.write(lexer.get_token()) # Identifier metric name
  if peek_token(lexer) != '{':
    # No '{' after metric name; if we have any injected labels, they represent
    # all of them; if we don't have any, there are no labels at all
    if labels:
      append_buf.write(f'{{{",".join(labels)}}}')
    finished_labels = True
  else:
    # A '{' after the metric name; we need to merge the injected labels with
    # the ones already here
    append_buf.write(lexer.get_token()) # '{'
    append_buf.write(','.join(labels))  # Injected labels
    if labels and peek_token(lexer) != '}':
      append_buf.write(',') # Combining global labels and existing ones, need ','
    finished_labels = False

  while (tok := lexer.get_token()):
    separator = ' ' if finished_labels else ''
    append_buf.write(f'{separator}{tok}')
    finished_labels |= tok == '}'

def create_relay_server(args: argparse.Namespace) -> RelayServer:
  s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
  p = pathlib.Path(args.socket_path)
  if p.exists():
    if not p.is_socket():
      # We won't unlink the path if this is something that exists but isn't a
      # socket; this is a guard against accidental deletion
      raise ValueError(f'{p} already exists but is not a socket; will not cleanup')
    os.unlink(p)

  s.bind(str(p))
  global socket_path
  socket_path = p
  s.listen()
  return RelayServer(s, p)

def run(metrics_server: MetricsServer) -> int:
  p = select.epoll()

  relay_server = metrics_server.relay_server
  p.register(relay_server.sock.fileno(), select.EPOLLIN)
  p.register(relay_server.client_epoll.fileno(), select.EPOLLIN)
  p.register(metrics_server.fileno(), select.POLLIN)

  while True:
    for fd, event_mask in p.poll(0.1):
      if fd == relay_server.sock.fileno():
        new_client = relay_server.accept_new_client()
      elif fd == metrics_server.fileno():
        metrics_server.handle_request()
      elif fd == relay_server.client_epoll.fileno():
        for client, msg in relay_server.recv_client_messages(timeout=0):
          logging.warning(f'discarded {len(msg)} byte message from client '
                          f'{client.fileno()}:{client.pid}')
      else:
        logging.error(f'unexpected poll event mask {event_mask:x} on fd {fd}')

  return 0

def terminate_handler(signo: int, frame):
  cleanup_socket_file()
  signal.signal(signal.SIGTERM, signal.SIG_DFL)
  os.kill(os.getpid(), signal.SIGTERM)

def merge_label_tokens(what: str, label: str, tokens: list[str]) -> str:
  if not tokens:
    raise ValueError(f'{what} is empty in label {label}')
  if len(tokens) == 1:
    return f'"{tokens[0]}"' if tokens[0][0] != '=' else tokens[0]
  joined = ''.join(tokens)
  return f'"{joined}"'

def sanitize_labels(labels: list[str]) -> list[str]:
  new_labels = list()
  for label in labels:
    tokens = list(shlex.shlex(label))
    if '=' not in tokens:
      raise ValueError(f'label `{label}` missing \'=\'')
    key = merge_label_tokens('key', label, tokens[:tokens.index('=')])
    value = merge_label_tokens('value', label, tokens[tokens.index('=')+1:])
    new_labels.append(f'{key}={value}')
  logging.debug(f'adjusted labels: {",".join(new_labels)}')
  return new_labels

def main(args: argparse.Namespace) -> int:
  args.labels = sanitize_labels(args.labels)

  # Create the metrics server first; if we can bind to the desired TCP port
  # (i.e., no EADDRINUSE), we are more confident that we are "the server" and
  # unlinking any existing UNIX domain socket path (i.e., assuming it is stale)
  # is reasonable
  metrics_http_addr = (args.bind, args.port)
  metrics_server = MetricsServer(
      metrics_http_addr,
      RelayHttpRequestHandler,
      scrape_duration=args.scrape_duration,
      labels=args.labels)
  metrics_server.relay_server = create_relay_server(args)
  return run(metrics_server)

if __name__ == '__main__':
  signal.signal(signal.SIGTERM, terminate_handler)

  args = parser.parse_args()
  if args.verbose > 1:
    print(args)
  log_levels = [logging.INFO, logging.DEBUG]
  logging.basicConfig(level=log_levels[min(args.verbose, 1)])

  if isinstance(args.signal, int):
    if args.signal not in signal.Signals:
      print(f'{pathlib.Path(__file__).name}: {args.signal} is not a valid signal',
            file=sys.stderr)
      sys.exit(1)
  else:
    s = getattr(signal.Signals, args.signal, None)
    if not s:
      print(f'{pathlib.Path(__file__).name}: {args.signal} is not a valid signal',
            file=sys.stderr)
      sys.exit(1)
    args.signal = int(s)

  try:
    rc = main(args)
  except:
    cleanup_socket_file()
    raise
  else:
    cleanup_socket_file()
    sys.exit(rc)
