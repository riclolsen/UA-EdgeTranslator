namespace Opc.Ua.Edge.Translator.ProtocolDrivers
{
    using Opc.Ua;
    using Opc.Ua.Client;
    using Opc.Ua.Client.ComplexTypes;
    using Opc.Ua.Edge.Translator.Interfaces;
    using Opc.Ua.Edge.Translator.Models;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Runtime.Serialization.Formatters.Binary;
    using System.Text;
    using System.Threading.Tasks;

    public class UAClient : IAsset
    {
        private ISession _session = null;
        private string _endpoint = string.Empty;

        private List<SessionReconnectHandler> _reconnectHandlers = new List<SessionReconnectHandler>();
        private object _reconnectHandlersLock = new object();

        private Dictionary<string, uint> _missedKeepAlives = new Dictionary<string, uint>();
        private object _missedKeepAlivesLock = new object();

        private readonly Dictionary<ISession, ComplexTypeSystem> _complexTypeList = new Dictionary<ISession, ComplexTypeSystem>();

        public bool IsConnected => _session != null && _session.Connected;

        public List<string> Discover()
        {
            List<string> discoveredServers = new();
            Log.Logger.Debug("[UAClient] Starting OPC UA server discovery");

            // connect to an OPC UA Global Discovery Server
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("OPC_UA_GDS_ENDPOINT_URL")))
            {
                var gdsEndpoint = Environment.GetEnvironmentVariable("OPC_UA_GDS_ENDPOINT_URL");
                Log.Logger.Debug($"[UAClient] Using GDS endpoint: {gdsEndpoint}");
                
                var client = DiscoveryClient.Create(new Uri(gdsEndpoint));

                var servers = client.FindServers(null);
                Log.Logger.Debug($"[UAClient] Found {servers.Count} servers from GDS");
                
                foreach (var server in servers)
                {
                    Log.Logger.Information($"[UAClient] Server: {server.ApplicationName}");
                    foreach (var endpoint in server.DiscoveryUrls)
                    {
                        discoveredServers.Add(endpoint);
                        Log.Logger.Debug($"[UAClient] Added endpoint: {endpoint}");
                    }
                }
            }
            else
            {
                Log.Logger.Debug("[UAClient] No GDS endpoint configured, skipping discovery");
            }

            Log.Logger.Debug($"[UAClient] Discovery completed. Found {discoveredServers.Count} endpoints");
            return discoveredServers;
        }

        public ThingDescription BrowseAndGenerateTD(string name, string endpoint)
        {
            Log.Logger.Debug($"[UAClient] Generating Thing Description for '{name}' at endpoint '{endpoint}'");
            
            ThingDescription td = new()
            {
                Context = new string[1] { "https://www.w3.org/2022/wot/td/v1.1" },
                Id = "urn:" + name,
                SecurityDefinitions = new() { NosecSc = new NosecSc() { Scheme = "nosec" } },
                Security = new string[1] { "nosec_sc" },
                Type = new string[1] { "Thing" },
                Name = name,
                Base = endpoint,
                Title = name,
                Properties = new Dictionary<string, Property>(),
                Actions = new Dictionary<string, TDAction>()

                // TODO: Add support for browsing OPC UA nodes and generating properties/actions
            };

            Log.Logger.Debug($"[UAClient] Generated Thing Description with {td.Properties.Count} properties and {td.Actions.Count} actions");
            return td;
        }

        public void Connect(string ipAddress, int port)
        {
            var url = "opc.tcp://" + ipAddress + ":" + port;
            Log.Logger.Debug($"[UAClient] Connecting to OPC UA server at {url}");
            
            var username = Environment.GetEnvironmentVariable("OPCUA_CLIENT_USERNAME");
            var password = Environment.GetEnvironmentVariable("OPCUA_CLIENT_PASSWORD");
            
            if (!string.IsNullOrEmpty(username))
            {
                Log.Logger.Debug($"[UAClient] Using username authentication: {username}");
            }
            else
            {
                Log.Logger.Debug("[UAClient] Using anonymous authentication");
            }
            
            try
            {
                ConnectSessionAsync(url, username, password).GetAwaiter().GetResult();
                Log.Logger.Information($"[UAClient] Successfully connected to {url}");
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"[UAClient] Failed to connect to {url}: {ex.Message}", ex);
                throw;
            }
        }

        public void Disconnect()
        {
            Log.Logger.Debug("[UAClient] Disconnecting from OPC UA server");
            
            if (_session != null)
            {
                var endpoint = _session.Endpoint?.EndpointUrl ?? "unknown";
                _session.Close();
                _session = null;
                Log.Logger.Information($"[UAClient] Disconnected from {endpoint}");
            }
            else
            {
                Log.Logger.Debug("[UAClient] No active session to disconnect");
            }
        }

        public string GetRemoteEndpoint()
        {
            return _endpoint;
        }

        public object Read(AssetTag tag)
        {
            Log.Logger.Debug($"[UAClient] Reading tag {tag.Address} of type {tag.Type}");
            
            object value = null;

            try
            {
                var readResult = ReadValue(tag.Address).GetAwaiter().GetResult();

                if (readResult != null)
                {
                    Log.Logger.Debug($"[UAClient] Read value from {tag.Address}: {readResult}");

                    if (tag.Type == "Float")
                    {
                        if (readResult is float floatValue)
                        {
                            value = floatValue;
                            Log.Logger.Debug($"[UAClient] Read Float value: {value}");
                        }
                        else if (readResult is double doubleValue)
                        {
                            value = (float)doubleValue;
                            Log.Logger.Debug($"[UAClient] Read Double value converted to Float: {value}");
                        }
                        else
                        {
                            Log.Logger.Warning($"[UAClient] Expected Float but got {readResult.GetType().Name} from {tag.Address}");
                            value = Convert.ToSingle(readResult);
                        }
                    }
                    else if (tag.Type == "Boolean")
                    {
                        value = Convert.ToBoolean(readResult);
                        Log.Logger.Debug($"[UAClient] Read Boolean value: {value}");
                    }
                    else if (tag.Type == "Integer")
                    {
                        value = Convert.ToInt32(readResult);
                        Log.Logger.Debug($"[UAClient] Read Integer value: {value}");
                    }
                    else if (tag.Type == "String")
                    {
                        value = Convert.ToString(readResult);
                        Log.Logger.Debug($"[UAClient] Read String value: {value}");
                    }
                    else
                    {
                        var error = $"Type {tag.Type} not supported by OPC UA.";
                        Log.Logger.Error($"[UAClient] {error}");
                        throw new ArgumentException(error);
                    }
                }
                else
                {
                    Log.Logger.Warning($"[UAClient] No data returned from read operation for {tag.Address}");
                }
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"[UAClient] Failed to read tag {tag.Address}: {ex.Message}", ex);
                throw;
            }

            return value;
        }

        public void Write(AssetTag tag, string value)
        {
            Log.Logger.Debug($"[UAClient] Writing value '{value}' to tag {tag.Address} of type {tag.Type}");
            
            object writeValue = null;
            try
            {
                if (tag.Type == "Float")
                {
                    var floatValue = float.Parse(value);
                    writeValue = floatValue / tag.Multiplier; // Reverse the multiplier for writing
                    Log.Logger.Debug($"[UAClient] Converted Float value: {floatValue} -> {writeValue} (multiplier: {tag.Multiplier})");
                }
                else if (tag.Type == "Boolean")
                {
                    writeValue = bool.Parse(value);
                    Log.Logger.Debug($"[UAClient] Converted Boolean value: {writeValue}");
                }
                else if (tag.Type == "Integer")
                {
                    writeValue = int.Parse(value);
                    Log.Logger.Debug($"[UAClient] Converted Integer value: {writeValue}");
                }
                else if (tag.Type == "String")
                {
                    writeValue = value;
                    Log.Logger.Debug($"[UAClient] Converted String value: {writeValue}");
                }
                else
                {
                    var error = $"Type {tag.Type} not supported by OPC UA.";
                    Log.Logger.Error($"[UAClient] {error}");
                    throw new ArgumentException(error);
                }

                WriteValue(tag.Address, writeValue).GetAwaiter().GetResult();
                Log.Logger.Information($"[UAClient] Successfully wrote value to {tag.Address}");
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"[UAClient] Failed to write value '{value}' to tag {tag.Address}: {ex.Message}", ex);
                throw;
            }
        }

        private Task<object> ReadValue(string addressWithinAsset)
        {
            if (_session != null)
            {
                var nodeId = ExpandedNodeId.ToNodeId(new ExpandedNodeId(addressWithinAsset), _session.NamespaceUris);
                var dataValue = _session.ReadValue(nodeId);
                return Task.FromResult(dataValue.Value);
            }
            else
            {
                return Task.FromResult<object>(null);
            }
        }

        private Task<byte[]> Read(string addressWithinAsset, byte unitID, string function, ushort count)
        {
            if (_session != null)
            {
                var nodeId = ExpandedNodeId.ToNodeId(new ExpandedNodeId(addressWithinAsset), _session.NamespaceUris);
                var value = _session.ReadValue(nodeId);

#pragma warning disable SYSLIB0011
                BinaryFormatter bf = new();
                using (MemoryStream ms = new())
                {
                    bf.Serialize(ms, value.Value);
#pragma warning restore SYSLIB0011

                    return Task.FromResult(ms.ToArray());
                }
            }
            else
            {
                return Task.FromResult(new byte[0]);
            }
        }

        private Task WriteValue(string addressWithinAsset, object value)
        {
            if (_session != null)
            {
                var nodeId = new NodeId(addressWithinAsset);
                var writeValue = new WriteValue
                {
                    NodeId = nodeId,
                    Value = new DataValue(new Variant(value))
                };

                WriteValueCollection nodesToWrite = new() { writeValue };

                RequestHeader requestHeader = new()
                {
                    ReturnDiagnostics = (uint)DiagnosticsMasks.All
                };

                StatusCodeCollection results = null;
                DiagnosticInfoCollection diagnosticInfos = null;

                var responseHeader = _session.Write(
                    requestHeader,
                    nodesToWrite,
                    out results,
                    out diagnosticInfos);

                ClientBase.ValidateResponse(results, nodesToWrite);
                ClientBase.ValidateDiagnosticInfos(diagnosticInfos, nodesToWrite);

                if (StatusCode.IsBad(results[0]))
                {
                    throw ServiceResultException.Create(results[0], 0, diagnosticInfos, responseHeader.StringTable);
                }

                return Task.CompletedTask;
            }
            else
            {
                throw new InvalidOperationException("No active OPC UA session");
            }
        }

        private Task Write(string addressWithinAsset, byte unitID, string function, byte[] values, bool singleBitOnly)
        {
            using (MemoryStream memStream = new(values))
            {
#pragma warning disable SYSLIB0011
                BinaryFormatter binForm = new();

                var value = binForm.Deserialize(memStream);
#pragma warning restore SYSLIB0011

                WriteValue nodeToWrite = new()
                {
                    NodeId = new NodeId(addressWithinAsset),
                    Value = new DataValue(new Variant(value))
                };

                WriteValueCollection nodesToWrite = new(){ nodeToWrite };

                RequestHeader requestHeader = new()
                {
                    ReturnDiagnostics = (uint)DiagnosticsMasks.All
                };

                StatusCodeCollection results = null;
                DiagnosticInfoCollection diagnosticInfos = null;

                var responseHeader = _session.Write(
                    requestHeader,
                    nodesToWrite,
                    out results,
                    out diagnosticInfos);

                ClientBase.ValidateResponse(results, nodesToWrite);
                ClientBase.ValidateDiagnosticInfos(diagnosticInfos, nodesToWrite);

                if (StatusCode.IsBad(results[0]))
                {
                    throw ServiceResultException.Create(results[0], 0, diagnosticInfos, responseHeader.StringTable);
                }

                return Task.CompletedTask;
            }
        }

        private async Task ConnectSessionAsync(string endpointUrl, string username, string password)
        {
            Log.Logger.Debug($"[UAClient] Starting session connection to {endpointUrl}");
            _endpoint = endpointUrl;

            // check if the required session is already available
            if (_session != null && _session.Endpoint.EndpointUrl == endpointUrl)
            {
                Log.Logger.Debug($"[UAClient] Session already exists for {endpointUrl}");
                return;
            }

            var selectedEndpoint = CoreClientUtils.SelectEndpoint(Program.App.ApplicationConfiguration, endpointUrl, true);
            Log.Logger.Debug($"[UAClient] Selected endpoint: {selectedEndpoint.EndpointUrl}");
            
            // Configure no security when WoT security definition is "nosec"
            //if (selectedEndpoint.SecurityPolicyUri != null && 
            //    (selectedEndpoint.SecurityPolicyUri.Contains("#None") || selectedEndpoint.SecurityPolicyUri.Contains("None")))
            //{
                Log.Logger.Debug("[UAClient] Configuring no security (nosec) for WoT connection");
                selectedEndpoint.SecurityPolicyUri = SecurityPolicies.None;
                selectedEndpoint.SecurityMode = MessageSecurityMode.None;
            //}
            
            var endpointConfiguration = EndpointConfiguration.Create(Program.App.ApplicationConfiguration);
            var configuredEndpoint = new ConfiguredEndpoint(null, selectedEndpoint, endpointConfiguration);

            var timeout = (uint)Program.App.ApplicationConfiguration.ClientConfiguration.DefaultSessionTimeout;
            Log.Logger.Debug($"[UAClient] Session timeout: {timeout}ms");

            UserIdentity userIdentity = null;
            if (username == null)
            {
                userIdentity = new UserIdentity(new AnonymousIdentityToken());
                Log.Logger.Debug("[UAClient] Using anonymous identity");
            }
            else
            {
                userIdentity = new UserIdentity(username, password);
                Log.Logger.Debug($"[UAClient] Using username identity: {username}");
            }

            try
            {
                Log.Logger.Debug($"[UAClient] Creating OPC UA session...");
                _session = await Session.Create(
                    Program.App.ApplicationConfiguration,
                    configuredEndpoint,
                    true, 
                    false, 
                    Program.App.ApplicationConfiguration.ApplicationName,
                    timeout,
                    userIdentity,
                    null // preferredLocales
                ).ConfigureAwait(false);
                
                Log.Logger.Information($"[UAClient] Session created successfully. SessionId: {_session.SessionId}");
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"[UAClient] Failed to create session: {ex.Message}", ex);
                return;
            }

            // enable diagnostics
            _session.ReturnDiagnostics = DiagnosticsMasks.All;
            Log.Logger.Debug("[UAClient] Enabled full diagnostics");

            // register keep alive callback
            _session.KeepAlive += KeepAliveHandler;
            Log.Logger.Debug("[UAClient] Registered keep alive handler");

            // enable subscriptions transfer
            _session.DeleteSubscriptionsOnClose = false;
            _session.TransferSubscriptionsOnReconnect = true;
            Log.Logger.Debug("[UAClient] Enabled subscription transfer");


            // load complex type system
            try
            {
                Log.Logger.Debug("[UAClient] Loading complex type system...");
                if (!_complexTypeList.ContainsKey(_session))
                {
                    _complexTypeList.Add(_session, new ComplexTypeSystem(_session));
                }

                await _complexTypeList[_session].Load().ConfigureAwait(false);
                Log.Logger.Debug("[UAClient] Complex type system loaded successfully");
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"[UAClient] Failed to load complex type system: {ex.Message}", ex);
            }
        }

        private void KeepAliveHandler(ISession session, KeepAliveEventArgs eventArgs)
        {
            if (eventArgs != null && session != null && session.ConfiguredEndpoint != null)
            {
                try
                {
                    var endpoint = session.ConfiguredEndpoint.EndpointUrl.ToString();

                    lock (_missedKeepAlivesLock)
                    {
                        if (!ServiceResult.IsGood(eventArgs.Status))
                        {
                            Log.Logger.Warning($"[UAClient] Keep alive failed for {endpoint}: {eventArgs.Status}");
                            
                            if (session.Connected)
                            {
                                // add a new entry, if required
                                if (!_missedKeepAlives.ContainsKey(endpoint))
                                {
                                    _missedKeepAlives.Add(endpoint, 0);
                                    Log.Logger.Debug($"[UAClient] Added missed keep alive counter for {endpoint}");
                                }

                                _missedKeepAlives[endpoint]++;
                                Log.Logger.Debug($"[UAClient] Missed keep alives for {endpoint}: {_missedKeepAlives[endpoint]}");
                            }

                            // start reconnect if there are 3 missed keep alives
                            if (_missedKeepAlives[endpoint] >= 3)
                            {
                                Log.Logger.Warning($"[UAClient] Starting reconnection for {endpoint} after {_missedKeepAlives[endpoint]} missed keep alives");
                                
                                // check if a reconnection is already in progress
                                var reconnectInProgress = false;
                                lock (_reconnectHandlersLock)
                                {
                                    foreach (var handler in _reconnectHandlers)
                                    {
                                        if (ReferenceEquals(handler.Session, session))
                                        {
                                            reconnectInProgress = true;
                                            break;
                                        }
                                    }
                                }

                                if (!reconnectInProgress)
                                {
                                    Log.Logger.Information($"[UAClient] Starting new reconnection process for {endpoint}");
                                    var reconnectHandler = new SessionReconnectHandler();
                                    lock (_reconnectHandlersLock)
                                    {
                                        _reconnectHandlers.Add(reconnectHandler);
                                    }
                                    reconnectHandler.BeginReconnect(session, 10000, ReconnectCompleteHandler);
                                }
                                else
                                {
                                    Log.Logger.Debug($"[UAClient] Reconnection already in progress for {endpoint}");
                                }
                            }
                        }
                        else
                        {
                            if (_missedKeepAlives.ContainsKey(endpoint) && _missedKeepAlives[endpoint] != 0)
                            {
                                // Reset missed keep alive count
                                var oldCount = _missedKeepAlives[endpoint];
                                _missedKeepAlives[endpoint] = 0;
                                Log.Logger.Debug($"[UAClient] Reset missed keep alive count for {endpoint} from {oldCount} to 0");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Logger.Error($"[UAClient] Error in keep alive handler: {ex.Message}", ex);
                }
            }
        }

        private void ReconnectCompleteHandler(object sender, EventArgs e)
        {
            Log.Logger.Debug("[UAClient] Reconnection completed");
            
            // find our reconnect handler
            SessionReconnectHandler reconnectHandler = null;
            lock (_reconnectHandlersLock)
            {
                foreach (var handler in _reconnectHandlers)
                {
                    if (ReferenceEquals(sender, handler))
                    {
                        reconnectHandler = handler;
                        break;
                    }
                }
            }

            // ignore callbacks from discarded objects
            if (reconnectHandler == null || reconnectHandler.Session == null)
            {
                Log.Logger.Warning("[UAClient] Reconnect handler or session is null, ignoring callback");
                return;
            }

            // update the session
            var oldEndpoint = _session?.Endpoint?.EndpointUrl?.ToString() ?? "unknown";
            _session = reconnectHandler.Session;
            var newEndpoint = _session?.Endpoint?.EndpointUrl?.ToString() ?? "unknown";
            
            Log.Logger.Information($"[UAClient] Session updated from {oldEndpoint} to {newEndpoint}");

            lock (_reconnectHandlersLock)
            {
                _reconnectHandlers.Remove(reconnectHandler);
            }
            reconnectHandler.Dispose();
            
            Log.Logger.Debug("[UAClient] Reconnect handler disposed");
        }

        public string ExecuteAction(MethodState method, IList<object> inputArgs, ref IList<object> outputArgs)
        {
            Log.Logger.Debug($"[UAClient] Executing method {method.NodeId} on object {method.Parent.NodeId}");
            
            if (inputArgs != null)
            {
                Log.Logger.Debug($"[UAClient] Method has {inputArgs.Count} input arguments");
            }
            
            CallMethodRequestCollection requests = new CallMethodRequestCollection
            {
                new CallMethodRequest
                {
                    ObjectId = new NodeId(method.Parent.NodeId),
                    MethodId = method.NodeId
                }
            };

            if (inputArgs != null)
            {
                requests[0].InputArguments = new VariantCollection();

                foreach (var arg in inputArgs)
                {
                    requests[0].InputArguments.Add(new Variant(arg));
                    Log.Logger.Debug($"[UAClient] Added input argument: {arg}");
                }
            }

            try
            {
                CallMethodResultCollection results;
                DiagnosticInfoCollection diagnosticInfos;

                ResponseHeader responseHeader = _session.Call(
                    null,
                    requests,
                    out results,
                    out diagnosticInfos);

                ClientBase.ValidateResponse(results, requests);
                ClientBase.ValidateDiagnosticInfos(diagnosticInfos, requests);

                StatusCode status = new StatusCode(0);
                if ((results != null) && (results.Count > 0))
                {
                    status = results[0].StatusCode;
                    Log.Logger.Debug($"[UAClient] Method call status: {status}");

                    if (StatusCode.IsBad(results[0].StatusCode) && (responseHeader.StringTable != null) && (responseHeader.StringTable.Count > 0))
                    {
                        var errorMessage = responseHeader.StringTable[0];
                        Log.Logger.Error($"[UAClient] Method call failed: {errorMessage}");
                        return errorMessage;
                    }

                    if ((results[0].OutputArguments != null) && (results[0].OutputArguments.Count > 0))
                    {
                        outputArgs = new List<object>(results[0].OutputArguments.Count);
                        Log.Logger.Debug($"[UAClient] Method returned {results[0].OutputArguments.Count} output arguments");

                        for (int i = 0; i < results[0].OutputArguments.Count; i++)
                        {
                            var outputArg = results[0].OutputArguments[i].Value;
                            outputArgs.Add(outputArg);
                            Log.Logger.Debug($"[UAClient] Output argument {i}: {outputArg}");
                        }
                    }
                }

                Log.Logger.Information($"[UAClient] Method {method.NodeId} executed successfully");
                return "Action executed successfully.";
            }
            catch (Exception ex)
            {
                Log.Logger.Error($"[UAClient] Failed to execute method {method.NodeId}: {ex.Message}", ex);
                throw;
            }
        }
    }
}
