# -*- coding: utf-8 -*-
"""
HTTP Garden Burp Suite Extension

This extension adds HTTP Garden integration directly to Burp Suite.
It allows you to send requests from Burp to the HTTP Garden testing framework
with a simple right-click context menu.

Installation:
1. Start bridge: python3 tools/burp_bridge.py
2. Extensions -> Extensions -> Add -> Python -> Select this file
3. Right-click requests -> "Send to HTTP Garden"
4. View results in "HTTP Garden" tab or Extensions -> Output
"""

from burp import IBurpExtender, IContextMenuFactory, ITab, IMessageEditorTabFactory, IMessageEditorTab, IExtensionStateListener
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Frame, Component
from java.awt.event import ActionListener, KeyEvent
from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem, JPanel, JLabel, JTextField, JButton, JTextArea, JScrollPane, JComboBox, KeyStroke, AbstractAction, JComponent, SwingUtilities
from javax.swing.border import TitledBorder
import json
import threading


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IMessageEditorTabFactory, IExtensionStateListener, ActionListener):
    """Main Burp extension class."""
    
    def registerExtenderCallbacks(self, callbacks):
        """Register the extension with Burp."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Get output streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Default settings - MUST be set before UI creation
        self.bridge_host = "localhost"
        self.bridge_port = "8888"
        self.default_command = "grid"
        self.selected_targets = []
        
        # Cache for message editor tab results
        self._tab_instances = []
        
        # Track the last seen request content
        self._last_request_content = None
        
        # Set extension name
        callbacks.setExtensionName("HTTP Garden")
        
        # Register context menu factory
        callbacks.registerContextMenuFactory(self)
        
        # Register message editor tab factory for response tabs
        callbacks.registerMessageEditorTabFactory(self)
        
        # Set up global key bindings
        self._setup_key_bindings()
        
        # Create UI tab
        try:
            self._create_ui()
            callbacks.addSuiteTab(self)
        except Exception as e:
            self._stderr.println("Failed to create UI tab: {}".format(str(e)))
            self._stderr.println("Extension will work without UI tab")

    def _create_ui(self):
        """Create the extension UI tab."""
        self._main_panel = JPanel(BorderLayout())
        
        # Configuration panel
        config_panel = JPanel(GridBagLayout())
        config_panel.setBorder(TitledBorder("HTTP Garden Bridge Configuration"))
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        
        # Bridge host/port
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.anchor = GridBagConstraints.WEST
        config_panel.add(JLabel("Bridge Host:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self._host_field = JTextField(self.bridge_host, 20)
        config_panel.add(self._host_field, gbc)
        
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.fill = GridBagConstraints.NONE
        gbc.weightx = 0.0
        config_panel.add(JLabel("Bridge Port:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        self._port_field = JTextField(self.bridge_port, 20)
        config_panel.add(self._port_field, gbc)
        
        # Test connection button
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 2
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.CENTER
        self._test_button = JButton("Test Connection", actionPerformed=self.test_connection)
        config_panel.add(self._test_button, gbc)
        
        # Command selection
        gbc.gridx = 0
        gbc.gridy = 3
        gbc.gridwidth = 1
        gbc.anchor = GridBagConstraints.WEST
        config_panel.add(JLabel("Default Command:"), gbc)
        
        gbc.gridx = 1
        gbc.fill = GridBagConstraints.HORIZONTAL
        self._command_combo = JComboBox(["grid", "fanout", "unparsed_fanout"])
        self._command_combo.setSelectedItem(self.default_command)
        config_panel.add(self._command_combo, gbc)
        
        # Results panel
        results_panel = JPanel(BorderLayout())
        results_panel.setBorder(TitledBorder("Results"))
        
        self._results_area = JTextArea(20, 80)
        self._results_area.setEditable(False)
        self._results_area.setFont(self._results_area.getFont().deriveFont(12.0))
        results_scroll = JScrollPane(self._results_area)
        results_panel.add(results_scroll, BorderLayout.CENTER)
        
        # Add panels to main panel
        self._main_panel.add(config_panel, BorderLayout.NORTH)
        self._main_panel.add(results_panel, BorderLayout.CENTER)
    
    def getTabCaption(self):
        """Return the tab caption."""
        return "HTTP Garden"
    
    def getUiComponent(self):
        """Return the UI component."""
        return self._main_panel
    
    def createMenuItems(self, invocation):
        """Create context menu items."""
        menu_items = ArrayList()
        
        # Only show menu for requests
        if invocation.getInvocationContext() in [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE
        ]:
            # Create menu items with keyboard shortcuts
            grid_item = JMenuItem("HTTP Garden: Grid Analysis")
            grid_item.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_G, KeyEvent.CTRL_DOWN_MASK))
            grid_item.addActionListener(lambda event: self.send_to_garden(invocation, "grid"))
            menu_items.add(grid_item)
            
            fanout_item = JMenuItem("HTTP Garden: Fanout Analysis") 
            fanout_item.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_F, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK))
            fanout_item.addActionListener(lambda event: self.send_to_garden(invocation, "fanout"))
            menu_items.add(fanout_item)
            
            unparsed_item = JMenuItem("HTTP Garden: Raw Responses")
            unparsed_item.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_R, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK))
            unparsed_item.addActionListener(lambda event: self.send_to_garden(invocation, "unparsed_fanout"))
            menu_items.add(unparsed_item)
            
            # Add transduce command - chains through ALL transducers
            transduce_item = JMenuItem("HTTP Garden: Transduce (All Proxies)")
            transduce_item.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_T, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK))
            transduce_item.addActionListener(lambda event: self.send_to_garden(invocation, "transduce"))
            menu_items.add(transduce_item)
        
        return menu_items
    
    def send_to_garden(self, invocation, command):
        """Send ANY HTTP request from Burp to HTTP Garden for analysis."""
        # Get the selected request
        messages = invocation.getSelectedMessages()
        if not messages:
            self._stderr.println("No messages selected")
            return
        
        # Use the first selected message
        message = messages[0]
        request = message.getRequest()
        
        if not request:
            self._stderr.println("No request found")
            return
        
        # Convert request to string - let the bridge handle byte conversion
        request_string = self._helpers.bytesToString(request)
        
        # Log what we're sending
        self._stdout.println("HTTP Garden: Sending to bridge ({} command):".format(command))
        self._stdout.println("Request content: {}...".format(request_string[:200].replace('\r', '\\r').replace('\n', '\\n')))
        
        # Send to bridge in a separate thread
        thread = threading.Thread(target=self._send_request_to_bridge, args=(request_string, command, None))
        thread.daemon = True
        thread.start()
    
    def send_to_garden_with_targets(self, invocation, command, targets):
        """Send ANY HTTP request from Burp to HTTP Garden with specific targets."""
        # Get the selected request
        messages = invocation.getSelectedMessages()
        if not messages:
            self._stderr.println("No messages selected")
            return
        
        # Use the first selected message
        message = messages[0]
        request = message.getRequest()
        
        if not request:
            self._stderr.println("No request found")
            return
        
        # Convert request to string - let the bridge handle byte conversion
        request_string = self._helpers.bytesToString(request)
        
        # Log what we're sending
        self._stdout.println("HTTP Garden: Sending to bridge ({} command with targets: {}):".format(command, targets))
        self._stdout.println("Request content: {}...".format(request_string[:200].replace('\r', '\\r').replace('\n', '\\n')))
        
        # Send to bridge in a separate thread
        thread = threading.Thread(target=self._send_request_to_bridge, args=(request_string, command, targets))
        thread.daemon = True
        thread.start()
    
    def _send_request_to_bridge(self, request_string, command, targets=None):
        """Send raw HTTP request bytes to the HTTP Garden bridge."""
        try:
            import urllib2
            
            # Get current settings - use defaults if UI fields don't exist
            host = self.bridge_host
            port = self.bridge_port
            if hasattr(self, '_host_field') and self._host_field.getText():
                host = self._host_field.getText()
            if hasattr(self, '_port_field') and self._port_field.getText():
                port = self._port_field.getText()
            
            # Build URL with targets if specified
            bridge_url = "http://{}:{}/raw?command={}".format(host, port, command)
            if targets:
                bridge_url += "&targets={}".format(",".join(targets))
            
            # Send the request string as UTF-8 bytes
            request_data = request_string.encode('utf-8')
            
            # Create HTTP request to bridge
            req = urllib2.Request(bridge_url, request_data)
            req.add_header('Content-Type', 'application/octet-stream')
            
            # Send request
            response = urllib2.urlopen(req, timeout=30)
            response_data = response.read()
            
            # Parse JSON response
            result = json.loads(response_data)
            
            # Display results in both UI and console
            self._display_results(result, command)
            self._display_console_results(result, command)
            
            # Update message editor tabs with results
            self._update_message_editor_tabs(request_string, result, command)
            
        except Exception as e:
            error_msg = "Error sending request to HTTP Garden: {}".format(str(e))
            self._stderr.println(error_msg)
            self._stderr.println("Make sure bridge is running: python3 tools/burp_bridge.py")
            if hasattr(self, '_results_area'):
                self._results_area.setText(error_msg)
    
    def _display_results(self, result, command):
        """Display the results in the UI."""
        output = []
        output.append("=== HTTP Garden Results ===")
        output.append("Command: {}".format(command))
        output.append("Targets: {}".format(", ".join(result.get('targets', []))))
        output.append("")
        
        if 'error' in result:
            output.append("ERROR: {}".format(result['error']))
        elif 'repl_output' in result and result['repl_output']:
            # Display the REPL-style formatted output
            output.append("REPL Output:")
            output.append("")
            output.append(result['repl_output'])
        elif command == 'grid' and 'grid' in result:
            output.append("Compatibility Grid:")
            output.append("")
            grid_data = result['grid']
            for row in grid_data['grid']:
                server = row['server']
                symbols = [r['symbol'] for r in row['results']]
                output.append("{}: {}".format(server.ljust(20), " ".join(symbols)))
        elif 'responses' in result:
            output.append("Server Responses:")
            output.append("")
            for server, responses in result['responses'].items():
                output.append("=== {} ===".format(server))
                if isinstance(responses, list) and responses:
                    for i, response in enumerate(responses):
                        if isinstance(response, dict):
                            if response.get('type') == 'request':
                                output.append("Request {}: {} {} {}".format(
                                    i+1, response.get('method', ''), 
                                    response.get('uri', ''), response.get('version', '')
                                ))
                            elif response.get('type') == 'response':
                                output.append("Response {}: {} {} {}".format(
                                    i+1, response.get('version', ''),
                                    response.get('code', ''), response.get('reason', '')
                                ))
                        else:
                            output.append("Response {}: {}".format(i+1, str(response)[:100]))
                else:
                    output.append("No responses")
                output.append("")
        
        # Update UI
        final_output = "\n".join(output)
        if hasattr(self, '_results_area'):
            self._results_area.setText(final_output)
        self._stdout.println("Results updated in HTTP Garden tab")
    
    def _display_console_results(self, result, command):
        """Display results in console for compatibility."""
        self._stdout.println("")
        self._stdout.println("=== HTTP Garden Results ===")
        self._stdout.println("Command: {}".format(command))
        self._stdout.println("Targets: {}".format(", ".join(result.get('targets', []))))
        self._stdout.println("")
        
        if 'error' in result:
            self._stdout.println("ERROR: {}".format(result['error']))
        elif 'repl_output' in result and result['repl_output']:
            # Display the REPL-style formatted output
            self._stdout.println("REPL Output:")
            self._stdout.println(result['repl_output'])
        elif command == 'grid' and 'grid' in result:
            self._stdout.println("Compatibility Grid:")
            self._stdout.println("")
            grid_data = result['grid']
            for row in grid_data['grid']:
                server = row['server']
                symbols = [r['symbol'] for r in row['results']]
                self._stdout.println("{}: {}".format(server.ljust(20), " ".join(symbols)))
        elif 'responses' in result:
            self._stdout.println("Server Responses:")
            for server, responses in result['responses'].items():
                count = len(responses) if isinstance(responses, list) else 0
                self._stdout.println("{}: {} responses".format(server, count))
        
        self._stdout.println("=== End Results ===")
        self._stdout.println("")
    
    def test_connection(self, event):
        """Test connection to the HTTP Garden bridge."""
        try:
            import urllib2
            
            # Get current settings - use defaults if UI fields don't exist
            host = self.bridge_host
            port = self.bridge_port
            if hasattr(self, '_host_field') and self._host_field.getText():
                host = self._host_field.getText()
            if hasattr(self, '_port_field') and self._port_field.getText():
                port = self._port_field.getText()
            
            # Test connection
            test_url = "http://{}:{}/status".format(host, port)
            response = urllib2.urlopen(test_url, timeout=5)
            data = json.loads(response.read())
            
            if data.get('status') == 'running':
                servers = data.get('servers', [])
                message = "[OK] Connection successful!\nFound {} servers: {}".format(
                    len(servers), ", ".join(servers[:5]) + ("..." if len(servers) > 5 else "")
                )
                if hasattr(self, '_results_area'):
                    self._results_area.setText(message)
                self._stdout.println("Bridge connection test successful - {} servers available".format(len(servers)))
            else:
                error_msg = "[ERROR] Bridge responded but status is not running"
                if hasattr(self, '_results_area'):
                    self._results_area.setText(error_msg)
                self._stderr.println(error_msg)
                
        except Exception as e:
            error_msg = "[ERROR] Connection failed: {}".format(str(e))
            if hasattr(self, '_results_area'):
                self._results_area.setText(error_msg)
            self._stderr.println("Bridge connection test failed: {}".format(str(e)))
            self._stderr.println("Make sure bridge is running: python3 tools/burp_bridge.py")
    
    def _update_message_editor_tabs(self, request_string, result, command):
        """Update all message editor tabs with the results."""
        try:
            # Create formatted results for the tab
            formatted_results = "=== HTTP Garden Results ===\n"
            formatted_results += "Command: {}\n".format(command)
            formatted_results += "Targets: {}\n\n".format(", ".join(result.get('targets', [])))
            
            if 'error' in result:
                formatted_results += "ERROR: {}\n".format(result['error'])
            elif 'repl_output' in result and result['repl_output']:
                formatted_results += result['repl_output']
            else:
                formatted_results += "No results available\n"
            
            # Calculate hash for this request
            request_hash = hash(request_string.encode('utf-8'))
            
            # Update all tab instances
            for tab in self._tab_instances:
                if hasattr(tab, 'update_results'):
                    tab.update_results(request_hash, formatted_results)
                    
        except Exception as e:
            self._stderr.println("Error updating message editor tabs: {}".format(str(e)))
    
    def _get_current_request_from_focus(self):
        """Get the last request content we've seen."""
        if self._last_request_content:
            # Debug: Show what we're about to send
            request_string = self._last_request_content.decode('utf-8')
            self._stdout.println("HTTP Garden: Using captured request for analysis:")
            self._stdout.println("Request: {}...".format(request_string[:200].replace('\r', '\\r').replace('\n', '\\n')))
            return self._last_request_content
        else:
            self._stderr.println("No request content available. Open a request in Repeater first.")
            return None
    
    def extensionUnloaded(self):
        """Called when extension is unloaded."""
        pass
    
    def _setup_key_bindings(self):
       
        def setup_global_bindings():
            try:
                # Find the main Burp Suite window
                frames = Frame.getFrames()
                burp_frame = None
                
                for frame in frames:
                    if frame.isVisible() and ("Burp Suite" in str(frame.getTitle()) or "Burp" in str(frame.getTitle())):
                        burp_frame = frame
                        break
                
                if burp_frame:
                    self._add_global_key_bindings(burp_frame)
                   
                else:
                    self._stderr.println("Could not find Burp Suite main window")
                    
            except Exception as e:
                self._stderr.println("Error setting up global key bindings: {}".format(str(e)))
        
        # Set up bindings after a delay to ensure Burp is fully loaded
        timer = threading.Timer(3.0, setup_global_bindings)
        timer.start()
    
    def _add_global_key_bindings(self, root_component):
        """Add global key bindings to the root component."""
        try:
            # Find all JComponent descendants and add key bindings
            self._add_key_bindings_recursive(root_component)
            
        except Exception as e:
            self._stderr.println("Error adding key bindings: {}".format(str(e)))
    
    def _add_key_bindings_recursive(self, component):
        """Recursively add key bindings to all JComponents."""
        try:
            if isinstance(component, JComponent):
                # Get the input and action maps
                input_map = component.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                action_map = component.getActionMap()
                
                # Add Ctrl+G for Grid Analysis
                grid_keystroke = KeyStroke.getKeyStroke(KeyEvent.VK_G, KeyEvent.CTRL_DOWN_MASK)
                input_map.put(grid_keystroke, "http_garden_grid_global")
                action_map.put("http_garden_grid_global", HTTPGardenGlobalAction(self, "grid"))
                
                # Add Ctrl+Shift+F for Fanout Analysis
                fanout_keystroke = KeyStroke.getKeyStroke(KeyEvent.VK_F, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK)
                input_map.put(fanout_keystroke, "http_garden_fanout_global")
                action_map.put("http_garden_fanout_global", HTTPGardenGlobalAction(self, "fanout"))
                
                # Add Ctrl+Shift+R for Raw Responses
                raw_keystroke = KeyStroke.getKeyStroke(KeyEvent.VK_R, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK)
                input_map.put(raw_keystroke, "http_garden_raw_global")
                action_map.put("http_garden_raw_global", HTTPGardenGlobalAction(self, "unparsed_fanout"))
                
                # Add Ctrl+Shift+T for Transduce (All Proxies)
                transduce_keystroke = KeyStroke.getKeyStroke(KeyEvent.VK_T, KeyEvent.CTRL_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK)
                input_map.put(transduce_keystroke, "http_garden_transduce_all")
                action_map.put("http_garden_transduce_all", HTTPGardenGlobalAction(self, "transduce"))
            
            # Recursively process child components
            if hasattr(component, 'getComponents'):
                for child in component.getComponents():
                    self._add_key_bindings_recursive(child)
                    
        except Exception as e:
            # Silently continue - some components may not support key bindings
            pass
    
    def createNewInstance(self, controller, editable):
        """Create a new message editor tab instance."""
        tab = HTTPGardenTab(self, controller, editable)
        self._tab_instances.append(tab)
        return tab
    
    def actionPerformed(self, event):
        """Handle action events."""
        # This method is required by ActionListener interface
        pass


class HTTPGardenGlobalAction(AbstractAction):
   
    
    def __init__(self, extender, command, targets=None):
        self._extender = extender
        self._command = command
        self._targets = targets
    
    def actionPerformed(self, event):
        try:
            # Try to find the current request from the focused component
            current_request = self._extender._get_current_request_from_focus()
            
            if current_request:
                if self._targets:
                    self._extender._stdout.println("Executing {} command with targets {} via global shortcut".format(self._command, self._targets))
                else:
                    self._extender._stdout.println("Executing {} command via global shortcut".format(self._command))
                
                # Convert bytes to string for sending
                if isinstance(current_request, bytes):
                    request_string = current_request.decode('utf-8')
                else:
                    request_string = current_request
                
                # Send to bridge in a separate thread
                thread = threading.Thread(target=self._extender._send_request_to_bridge, args=(request_string, self._command, self._targets))
                thread.daemon = True
                thread.start()
            else:
                self._extender._stderr.println("No request found. Make sure you're focused on a request in Repeater/Proxy/etc.")
                
        except Exception as e:
            self._extender._stderr.println("Error executing global shortcut: {}".format(str(e)))


class HTTPGardenTab(IMessageEditorTab):
    """Custom message editor tab for HTTP Garden results."""
    
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._controller = controller
        self._editable = editable
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(False)
        self._current_message = None
        self._results_cache = {}
    
    def getTabCaption(self):
        """Return the tab caption."""
        return "HTTP Garden"
    
    def getUiComponent(self):
        """Return the UI component for this tab."""
        return self._txtInput.getComponent()
    
    def isEnabled(self, content, isRequest):
        """Determine if this tab should be enabled."""
        # Show for both requests and responses, but we'll handle them differently
        return content is not None
    
    def setMessage(self, content, isRequest):
        """Set the message content for this tab."""
        if content is None:
            self._txtInput.setText(None)
            return
        
        self._current_message = content
        self._is_request = isRequest
        
        # Store request content for keyboard shortcuts
        if isRequest and content:
            # Convert to string and store as UTF-8 bytes
            request_string = self._extender._helpers.bytesToString(content)
            self._extender._last_request_content = request_string.encode('utf-8')
            
            # Debug: Show what request we captured
            self._extender._stdout.println("HTTP Garden: Captured request content:")
            self._extender._stdout.println("Preview: {}...".format(request_string[:200].replace('\r', '\\r').replace('\n', '\\n')))
        
        if isRequest:
            # This is a request tab - check for cached results
            request_hash = hash(bytes(content))
            if request_hash in self._results_cache:
                self._txtInput.setText(self._results_cache[request_hash])
            else:
                # Show instructions for getting results
                instructions = """HTTP Garden Analysis


Results will appear here automatically.

Make sure the HTTP Garden bridge is running:
python3 tools/burp_bridge.py
"""
                self._txtInput.setText(instructions.encode('utf-8'))
        else:
            # This is a response tab
            instructions = """HTTP Garden Analysis - Response Tab

Results will appear here automatically.

Make sure the HTTP Garden bridge is running:
python3 tools/burp_bridge.py

Status: Ready for analysis...
"""
            self._txtInput.setText(instructions.encode('utf-8'))
    
    def getMessage(self):
        """Get the current message."""
        return self._current_message
    
    def isModified(self):
        """Check if the message has been modified."""
        return False
    
    def getSelectedData(self):
        """Get the selected data."""
        return self._txtInput.getSelectedText()
    
    def update_results(self, request_hash, results):
        """Update the results for a specific request."""
        self._results_cache[request_hash] = results.encode('utf-8')
        
        # Update display if this matches current message
        if self._current_message is not None:
            if hasattr(self, '_is_request') and self._is_request:
                # For request tabs, match by request hash
                current_hash = hash(bytes(self._current_message))
                if current_hash == request_hash:
                    self._txtInput.setText(results.encode('utf-8'))
            else:
                # For response tabs, always show the latest results
                # (since we can't easily correlate response to request)
                self._txtInput.setText(results.encode('utf-8'))
