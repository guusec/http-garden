#!/usr/bin/env python3
"""
HTTP Garden Burp Suite Bridge

This module provides a bridge between Burp Suite and the HTTP Garden REPL.
It runs an HTTP server that receives requests from Burp Suite and processes
them through the HTTP Garden testing framework.
"""

import json
import socket
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from typing import Optional, Dict, Any, List
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from targets import SERVER_DICT, TRANSDUCER_DICT
from fanout import fanout, unparsed_fanout
from grid import generate_grid
from diff import ErrorType

# Import REPL functions for consistent behavior
import repl


class BurpBridgeHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Burp Suite integration."""
    
    def log_message(self, format, *args):
        """Override to provide cleaner logging."""
        print(f"[{time.strftime('%H:%M:%S')}] {format % args}")
    
    def do_GET(self):
        """Handle GET requests - serve status and documentation."""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/':
            self.send_status_page()
        elif parsed_path.path == '/status':
            self.send_json_response({'status': 'running', 'servers': list(SERVER_DICT.keys())})
        elif parsed_path.path == '/servers':
            self.send_json_response({'servers': list(SERVER_DICT.keys())})
        elif parsed_path.path == '/transducers':
            self.send_json_response({'transducers': list(TRANSDUCER_DICT.keys())})
        else:
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        """Handle POST requests - process HTTP Garden commands."""
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == '/test':
            self.handle_test_request()
        elif parsed_path.path == '/raw':
            self.handle_raw_request()
        else:
            self.send_error(404, "Not Found")
    
    def handle_test_request(self):
        """Handle structured test requests - also converts to REPL payload format."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            # Parse JSON request
            request_data = json.loads(post_data.decode('utf-8'))
            
            # Extract parameters
            payload_data = request_data.get('payload', '')
            command = request_data.get('command', 'grid')
            targets = request_data.get('targets', [])
            
            # Convert payload to REPL format (list of bytes)
            if isinstance(payload_data, str):
                # Handle escape sequences like \r\n properly
                try:
                    decoded_payload = payload_data.encode('latin1').decode('unicode-escape').encode('latin1')
                    payload = [decoded_payload]
                except:
                    payload = [payload_data.encode('latin1')]
            else:
                payload = [p.encode('latin1') for p in payload_data]
            
            # Debug: Show what we received
            print(f"[DEBUG] Bridge received structured request for {command} command")
            print(f"[DEBUG] Payload preview: {payload[0][:200].decode('latin1', errors='replace')}")
            print(f"[DEBUG] Targets: {targets}")
            
            # Execute the REPL command
            result = self.execute_repl_command(payload, command, targets)
            
            self.send_json_response(result)
            
        except Exception as e:
            self.send_json_response({'error': str(e)}, status=500)
    
    def handle_raw_request(self):
        """Handle raw HTTP requests from Burp Suite - convert to REPL payload format."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            raw_http = self.rfile.read(content_length)
            
            # Parse query parameters for command options
            parsed_path = urlparse(self.path)
            query_params = parse_qs(parsed_path.query)
            
            command = query_params.get('command', ['grid'])[0]
            targets = query_params.get('targets', [])
            if targets:
                targets = targets[0].split(',')
            
            # Convert raw HTTP to REPL payload format (list of bytes)
            # This is the key - take ANY HTTP request and make it a REPL payload
            payload = [raw_http]
            
            # Debug: Show raw data type and content
            print(f"[DEBUG] Raw data type: {type(raw_http)}")
            print(f"[DEBUG] Raw data repr: {repr(raw_http)[:100]}...")
            
            # Convert Java array to proper bytes if needed
            if hasattr(raw_http, '__iter__') and not isinstance(raw_http, (bytes, str)):
                print("[DEBUG] Converting from iterable to bytes")
                try:
                    raw_http = bytes(raw_http)
                except Exception as e:
                    print(f"[DEBUG] First conversion failed: {e}")
                    try:
                        raw_http = bytes([int(b) for b in raw_http])
                    except Exception as e2:
                        print(f"[DEBUG] Second conversion failed: {e2}")
                        # Last resort - convert string representation
                        raw_http = str(raw_http).encode('latin1')
            
            # Debug: Show what we received after conversion
            print(f"[DEBUG] Bridge received {len(raw_http)} bytes for {command} command")
            print(f"[DEBUG] Request preview: {raw_http[:200].decode('latin1', errors='replace')}")
            print(f"[DEBUG] Targets: {targets}")
            
            # Default to all servers if no targets specified
            if not targets:
                targets = list(SERVER_DICT.keys())
                print(f"[DEBUG] Using default targets: {targets[:5]}...")
            
            # Execute the REPL command with this payload
            result = self.execute_repl_command(payload, command, targets)
            
            self.send_json_response(result)
            
        except Exception as e:
            self.send_json_response({'error': str(e)}, status=500)
    
    def execute_repl_command(self, payload: List[bytes], command: str, targets: List[str]) -> Dict[str, Any]:
        """Execute REPL command exactly like the REPL does - this is the core functionality."""
        result = {
            'command': command,
            'payload_preview': payload[0][:200].decode('latin1', errors='replace') if payload else '',
            'targets': targets,
            'repl_output': '',
            'success': False
        }
        
        try:
            # Simulate REPL command execution exactly
            if command == 'grid':
                # Default to all servers if none specified
                if not targets:
                    targets = list(SERVER_DICT.keys())
                
                # Intelligently filter to only servers (not transducers)
                server_names = [t for t in targets if t in SERVER_DICT]
                invalid_names = [t for t in targets if t not in SERVER_DICT and t not in TRANSDUCER_DICT]
                
                if invalid_names:
                    result['error'] = f'Invalid target names: {invalid_names}'
                    return result
                
                if not server_names:
                    result['error'] = 'Grid command requires at least one server'
                    return result
                
                print(f"[DEBUG] Grid: Using {len(server_names)} servers: {server_names}")
                
                # Execute grid command exactly like REPL
                servers = [SERVER_DICT[s] for s in server_names]
                print(f"[DEBUG] About to run generate_grid with {len(servers)} servers")
                print(f"[DEBUG] Payload length: {len(payload[0])} bytes")
                
                grid = generate_grid(payload, servers)
                print(f"[DEBUG] Grid generated: {len(grid)} rows")
                
                # Capture the grid output like REPL would display it
                result['repl_output'] = self.capture_grid_output(grid, server_names)
                result['success'] = True
                
            elif command == 'fanout':
                # Default to all servers if none specified
                if not targets:
                    targets = list(SERVER_DICT.keys())
                
                # Intelligently filter to only servers (not transducers)
                server_names = [t for t in targets if t in SERVER_DICT]
                invalid_names = [t for t in targets if t not in SERVER_DICT and t not in TRANSDUCER_DICT]
                
                if invalid_names:
                    result['error'] = f'Invalid target names: {invalid_names}'
                    return result
                
                if not server_names:
                    result['error'] = 'Fanout command requires at least one server'
                    return result
                
                print(f"[DEBUG] Fanout: Using {len(server_names)} servers: {server_names}")
                
                # Execute fanout command exactly like REPL
                servers = [SERVER_DICT[s] for s in server_names]
                responses = fanout(payload, servers)
                
                # Capture the fanout output like REPL would display it
                result['repl_output'] = self.capture_fanout_output(responses, servers)
                result['success'] = True
                
            elif command == 'unparsed_fanout':
                # Default to all servers if none specified  
                if not targets:
                    targets = list(SERVER_DICT.keys())
                
                # Intelligently filter to only servers (not transducers)
                server_names = [t for t in targets if t in SERVER_DICT]
                invalid_names = [t for t in targets if t not in SERVER_DICT and t not in TRANSDUCER_DICT]
                
                if invalid_names:
                    result['error'] = f'Invalid target names: {invalid_names}'
                    return result
                
                if not server_names:
                    result['error'] = 'Unparsed fanout command requires at least one server'
                    return result
                
                print(f"[DEBUG] Unparsed fanout: Using {len(server_names)} servers: {server_names}")
                
                # Execute unparsed_fanout exactly like REPL
                servers = [SERVER_DICT[s] for s in server_names]
                responses = unparsed_fanout(payload, servers)
                
                # Capture the unparsed fanout output like REPL would display it
                result['repl_output'] = self.capture_unparsed_fanout_output(responses, servers)
                result['success'] = True
                
            elif command == 'transduce':
                # Transduce command - intelligently separate transducers from servers
                if not targets:
                    # Default to all transducers if none specified
                    targets = list(TRANSDUCER_DICT.keys())
                
                # Intelligently separate transducers from servers
                transducer_names = []
                server_names = []
                invalid_names = []
                
                for target in targets:
                    if target in TRANSDUCER_DICT:
                        transducer_names.append(target)
                    elif target in SERVER_DICT:
                        server_names.append(target)
                    else:
                        invalid_names.append(target)
                
                if invalid_names:
                    result['error'] = f'Invalid target names: {invalid_names}'
                    return result
                
                if not transducer_names:
                    result['error'] = 'Transduce command requires at least one transducer (proxy)'
                    return result
                
                print(f"[DEBUG] Transduce: {len(transducer_names)} transducers, {len(server_names)} servers")
                print(f"[DEBUG] Transducers: {transducer_names}")
                print(f"[DEBUG] Servers: {server_names}")
                
                # Execute transduce exactly like REPL - chain through transducers
                transducers = [TRANSDUCER_DICT[t_name] for t_name in transducer_names]
                tmp_payload = payload
                transduce_output = []
                
                # Show initial payload
                transduce_output.append(f"[0]: {' '.join(repr(b)[1:] for b in tmp_payload)}")
                
                # Chain through all transducers
                for i, transducer in enumerate(transducers):
                    try:
                        tmp_payload = transducer.transduce(tmp_payload)
                        print(f"[DEBUG] Transducer {transducer.name} processed payload")
                    except ValueError as e:
                        transduce_output.append(f"Error: {e}")
                        result['error'] = str(e)
                        break
                    
                    if len(tmp_payload) == 0:
                        transduce_output.append(f"{transducer.name} didn't respond")
                        result['error'] = f"{transducer.name} didn't respond"
                        break
                    
                    transduce_output.append(f"    ⬇️ {transducer.name}")
                    transduce_output.append(f"[{i+1}]: {' '.join(repr(b)[1:] for b in tmp_payload)}")
                
                # If we have servers specified, also run grid/fanout on final payload
                if 'error' not in result and server_names:
                    transduce_output.append(f"\nTesting final payload against {len(server_names)} servers:")
                    servers = [SERVER_DICT[s] for s in server_names]
                    
                    # Run grid analysis on the final transduced payload
                    grid = generate_grid(tmp_payload, servers)
                    transduce_output.append("\nGrid Analysis of Final Payload:")
                    transduce_output.append(self.capture_grid_output(grid, server_names))
                
                result['repl_output'] = '\n'.join(transduce_output)
                result['success'] = True
                
            else:
                result['error'] = f'Unknown command: {command}'
                
        except Exception as e:
            result['error'] = str(e)
            result['repl_output'] = f"Error: {str(e)}"
        
        return result
    
    def capture_grid_output(self, grid, labels: List[str]) -> str:
        """Capture grid output without ANSI color codes for Burp compatibility."""
        import itertools
        
        # Recreate print_grid logic but without ANSI color codes
        first_column_width = max(map(len, labels)) if labels else 10
        labels_padded = [label.ljust(first_column_width) for label in labels]

        # Vertical labels
        result = ""
        for row in itertools.zip_longest(
            *(s.strip().rjust(len(s)) for s in [" " * len(labels_padded[0]), *labels_padded]),
        ):
            result += "".join(f'{"".ljust(first_column_width - 1)}{" ".join(r or "" for r in row)}\n')
        
        result += f"{''.ljust(first_column_width)}+{'-' * (len(labels) * 2 - 1)}\n"

        # Horizontal labels and grid symbols (no colors)
        for label, row in zip(labels_padded, grid):
            result += label.ljust(first_column_width) + "|"
            for entry in row:
                if entry is None:
                    symbol = " "
                elif entry in (ErrorType.OK, ErrorType.RESPONSE_DISCREPANCY):
                    symbol = "✓"  # No color codes
                elif entry in (
                    ErrorType.DISCREPANCY,
                    ErrorType.REQUEST_DISCREPANCY,
                    ErrorType.TYPE_DISCREPANCY,
                    ErrorType.STREAM_DISCREPANCY,
                ):
                    symbol = "X"  # No color codes
                elif entry in (ErrorType.INVALID,):
                    symbol = "X"  # No color codes
                else:
                    symbol = "?"
                result += symbol + " "
            result += "\n"

        return result
    
    def capture_fanout_output(self, responses, servers) -> str:
        """Capture fanout output without ANSI color codes for Burp compatibility."""
        output = []
        for server, response_list in zip(servers, responses):
            output.append(f"{server.name}: [")
            for response in response_list:
                if hasattr(response, 'method'):  # HTTPRequest
                    output.append("    HTTPRequest(")
                    output.append(f"        method={response.method!r}, uri={response.uri!r}, version={response.version!r},")
                    if len(response.headers) == 0:
                        output.append("        headers=[],")
                    else:
                        output.append("        headers=[")
                        for name, value in response.headers:
                            output.append(f"            ({name!r}, {value!r}),")
                        output.append("        ],")
                    output.append(f"        body={response.body!r},")
                    output.append("    ),")
                elif hasattr(response, 'code'):  # HTTPResponse
                    output.append(f"    HTTPResponse(version={response.version!r}, code={response.code!r}, reason={response.reason!r}),")
            output.append("]")
        
        return "\n".join(output)
    
    def capture_unparsed_fanout_output(self, responses, servers) -> str:
        """Capture unparsed fanout output without ANSI color codes for Burp compatibility."""
        output = []
        for server, response_list in zip(servers, responses):
            output.append(f"{server.name}:")
            for response in response_list:
                response_repr = repr(response)
                if len(response_repr) > 80:
                    response_repr = response_repr[:80] + "..."
                output.append(f"    {response_repr}")
        
        return "\n".join(output)
    
    def format_grid(self, grid, labels: List[str]) -> Dict[str, Any]:
        """Format grid results for JSON response."""
        formatted_grid = []
        for i, row in enumerate(grid):
            row_data = {
                'server': labels[i],
                'results': []
            }
            for j, entry in enumerate(row):
                symbol = ' '
                status = 'unknown'
                if entry is None:
                    symbol = ' '
                    status = 'no_data'
                elif entry in (ErrorType.OK, ErrorType.RESPONSE_DISCREPANCY):
                    symbol = '✓'
                    status = 'ok'
                elif entry in (
                    ErrorType.DISCREPANCY,
                    ErrorType.REQUEST_DISCREPANCY,
                    ErrorType.TYPE_DISCREPANCY,
                    ErrorType.STREAM_DISCREPANCY,
                ):
                    symbol = 'X'
                    status = 'discrepancy'
                elif entry in (ErrorType.INVALID,):
                    symbol = 'X'
                    status = 'invalid'
                
                row_data['results'].append({
                    'target_server': labels[j] if j < len(labels) else 'unknown',
                    'symbol': symbol,
                    'status': status,
                    'error_type': entry.name if entry else None
                })
            formatted_grid.append(row_data)
        
        return {
            'grid': formatted_grid,
            'servers': labels
        }
    
    def format_fanout(self, responses, targets: List[str]) -> Dict[str, Any]:
        """Format fanout results for JSON response."""
        formatted_responses = {}
        for i, (target, response_list) in enumerate(zip(targets, responses)):
            formatted_responses[target] = []
            for response in response_list:
                if hasattr(response, 'method'):  # HTTPRequest
                    formatted_responses[target].append({
                        'type': 'request',
                        'method': response.method.decode('latin1', errors='replace'),
                        'uri': response.uri.decode('latin1', errors='replace'),
                        'version': response.version.decode('latin1', errors='replace'),
                        'headers': [(k.decode('latin1', errors='replace'), 
                                   v.decode('latin1', errors='replace')) 
                                  for k, v in response.headers],
                        'body': response.body.decode('latin1', errors='replace')
                    })
                elif hasattr(response, 'code'):  # HTTPResponse
                    formatted_responses[target].append({
                        'type': 'response',
                        'version': response.version.decode('latin1', errors='replace'),
                        'code': response.code.decode('latin1', errors='replace'),
                        'reason': response.reason.decode('latin1', errors='replace'),
                        'headers': [(k.decode('latin1', errors='replace'), 
                                   v.decode('latin1', errors='replace')) 
                                  for k, v in getattr(response, 'headers', [])],
                        'body': getattr(response, 'body', b'').decode('latin1', errors='replace')
                    })
        
        return formatted_responses
    
    def format_unparsed_fanout(self, responses, targets: List[str]) -> Dict[str, Any]:
        """Format unparsed fanout results for JSON response."""
        formatted_responses = {}
        for target, response_list in zip(targets, responses):
            formatted_responses[target] = [
                r.decode('latin1', errors='replace') for r in response_list
            ]
        
        return formatted_responses
    
    def format_grid_as_text(self, grid, labels: List[str]) -> str:
        """Format grid results as text like the REPL does."""
        output = []
        
        # Create the grid display like REPL
        first_column_width = max(map(len, labels)) if labels else 10
        
        # Vertical labels (simplified version)
        header_line = " " * first_column_width
        for label in labels:
            header_line += f" {label[0] if label else ' '}"
        output.append(header_line)
        
        # Separator line
        separator = " " * first_column_width + "+" + "-" * (len(labels) * 2 - 1)
        output.append(separator)
        
        # Grid rows
        for i, row in enumerate(grid):
            if i < len(labels):
                line = labels[i].ljust(first_column_width) + "|"
                for entry in row:
                    if entry is None:
                        symbol = " "
                    elif entry in (ErrorType.OK, ErrorType.RESPONSE_DISCREPANCY):
                        symbol = "✓"
                    elif entry in (
                        ErrorType.DISCREPANCY,
                        ErrorType.REQUEST_DISCREPANCY,
                        ErrorType.TYPE_DISCREPANCY,
                        ErrorType.STREAM_DISCREPANCY,
                    ):
                        symbol = "X"
                    elif entry in (ErrorType.INVALID,):
                        symbol = "X"
                    else:
                        symbol = "?"
                    line += symbol + " "
                output.append(line)
        
        return "\n".join(output)
    
    def format_fanout_as_text(self, responses, servers) -> str:
        """Format fanout results as text like the REPL does."""
        output = []
        
        for server, response_list in zip(servers, responses):
            output.append(f"{server.name}: [")
            for response in response_list:
                if hasattr(response, 'method'):  # HTTPRequest
                    output.append(f"    HTTPRequest(")
                    output.append(f"        method={response.method!r}, uri={response.uri!r}, version={response.version!r},")
                    if len(response.headers) == 0:
                        output.append("        headers=[],")
                    else:
                        output.append("        headers=[")
                        for name, value in response.headers:
                            output.append(f"            ({name!r}, {value!r}),")
                        output.append("        ],")
                    output.append(f"        body={response.body!r},")
                    output.append("    ),")
                elif hasattr(response, 'code'):  # HTTPResponse
                    output.append(f"    HTTPResponse(version={response.version!r}, code={response.code!r}, reason={response.reason!r}),")
            output.append("]")
        
        return "\n".join(output)
    
    def format_unparsed_fanout_as_text(self, responses, servers) -> str:
        """Format unparsed fanout results as text like the REPL does."""
        output = []
        
        for server, response_list in zip(servers, responses):
            output.append(f"{server.name}:")
            for response in response_list:
                is_response = response.startswith(b"HTTP/")
                response_str = repr(response)
                if len(response_str) > 80:
                    response_str = response_str[:80] + "..."
                output.append(f"    {response_str}")
        
        return "\n".join(output)
    
    def send_json_response(self, data: Dict[str, Any], status: int = 200):
        """Send a JSON response."""
        response_data = json.dumps(data, indent=2).encode('utf-8')
        
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_data)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        self.wfile.write(response_data)
    
    def send_status_page(self):
        """Send an HTML status page."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>HTTP Garden Burp Bridge</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .status {{ color: green; font-weight: bold; }}
        .endpoint {{ background: #f5f5f5; padding: 10px; margin: 10px 0; }}
        code {{ background: #eee; padding: 2px 4px; }}
    </style>
</head>
<body>
    <h1>HTTP Garden Burp Bridge</h1>
    <p class="status">Status: Running</p>
    
    <h2>Available Endpoints</h2>
    
    <div class="endpoint">
        <h3>GET /status</h3>
        <p>Get server status and available targets</p>
    </div>
    
    <div class="endpoint">
        <h3>POST /test</h3>
        <p>Send structured test request</p>
        <p>JSON payload:</p>
        <pre><code>{{
  "payload": "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n",
  "command": "grid",
  "targets": ["nginx", "gunicorn"]
}}</code></pre>
    </div>
    
    <div class="endpoint">
        <h3>POST /raw?command=grid&targets=nginx,gunicorn</h3>
        <p>Send raw HTTP request as payload</p>
        <p>Send the raw HTTP request as the POST body</p>
    </div>
    
    <h2>Available Servers</h2>
    <ul>
        {''.join(f'<li>{server}</li>' for server in sorted(SERVER_DICT.keys()))}
    </ul>
    
    <h2>Available Commands</h2>
    <ul>
        <li><code>grid</code> - Generate compatibility grid</li>
        <li><code>fanout</code> - Get parsed responses from servers</li>
        <li><code>unparsed_fanout</code> - Get raw responses from servers</li>
    </ul>
</body>
</html>
"""
        
        response_data = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(response_data)))
        self.end_headers()
        self.wfile.write(response_data)
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


class BurpBridge:
    """Main bridge server class."""
    
    def __init__(self, host: str = 'localhost', port: int = 8888):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
    
    def start(self):
        """Start the bridge server."""
        try:
            self.server = HTTPServer((self.host, self.port), BurpBridgeHandler)
            self.server_thread = threading.Thread(target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            print(f"HTTP Garden Burp Bridge started on http://{self.host}:{self.port}")
            print(f"Available servers: {len(SERVER_DICT)}")
            print(f"Available transducers: {len(TRANSDUCER_DICT)}")
            print(f"\nUsage:")
            print(f"   Status page: http://{self.host}:{self.port}/")
            print(f"   Send requests to: http://{self.host}:{self.port}/test")
            print(f"   Send raw HTTP to: http://{self.host}:{self.port}/raw")
            print(f"\nReady to receive requests from Burp Suite!")
            
        except OSError as e:
            if e.errno == 48:  # Address already in use
                print(f"ERROR: Port {self.port} is already in use. Try a different port.")
            else:
                print(f"ERROR: Failed to start server: {e}")
            raise
    
    def stop(self):
        """Stop the bridge server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("Bridge server stopped")
    
    def wait(self):
        """Wait for the server thread to finish."""
        if self.server_thread:
            try:
                self.server_thread.join()
            except KeyboardInterrupt:
                print("\nShutting down...")
                self.stop()


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTP Garden Burp Suite Bridge')
    parser.add_argument('--host', default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--port', type=int, default=8888, help='Port to bind to (default: 8888)')
    
    args = parser.parse_args()
    
    bridge = BurpBridge(args.host, args.port)
    
    try:
        bridge.start()
        bridge.wait()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        bridge.stop()


if __name__ == '__main__':
    main()