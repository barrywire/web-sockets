require "socket" # Provides TCPServer and TCPSocket classes
require "digest/sha1" # Provides the sha1 hash function

server = TCPServer.new("localhost", 2345)

loop do

  # Wait for a connection
  socket = server.accept
  STDERR.puts "Incoming request from localhost:8000 for connection"

  # Read the HTTP request. We know it's finished when we see a line with nothing but \r\n
  http_request = ""
  while (line = socket.gets) && (line != "\r\n")
    http_request += line
  end

  # Grab the security key from the headers. If one isn't present, close the connection.
  if matches = http_request.match(/^Sec-WebSocket-Key: (\S+)/)
    websocket_key = matches[1]
    STDERR.puts "Websocket handshake detected with key: #{ websocket_key }"
  else
    STDERR.puts "Aborting non-websocket connection"
    socket.close
    next
  end


  # Generate a response key
  response_key = Digest::SHA1.base64digest([websocket_key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"].join)
  STDERR.puts "Responding to handshake with key: #{ response_key }"

  socket.write <<-eos
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: #{ response_key }

  eos

  STDERR.puts "Handshake completed. Starting to parse the websocket frame."
  
  # Parse the websocket frames
  first_byte = socket.getbyte
  fin = first_byte & 0b10000000
  opcode = first_byte & 0b00001111

  # Accept only text frames
  raise "We do not support continuations" unless fin
  raise "We only support opcode 1" unless opcode == 1

  second_byte = socket.getbyte
  is_masked = second_byte & 0b10000000
  payload_size = second_byte & 0b01111111

  raise "All incoming frames should be masked according to the websocket spec" unless is_masked
  raise "We only support payloads < 126 bytes in length" unless payload_size < 126

  mask = 4.times.map { socket.getbyte }
  data = payload_size.times.map { socket.getbyte }
  unmasked_data = data.each_with_index.map { |byte, i| byte ^ mask[i % 4] }

  STDERR.puts "Message from client: #{ unmasked_data.pack("C*").force_encoding("utf-8").inspect }"


  response = "Hello from the server. I have sent you a message after #{ rand(1..5) } seconds."
  socket.write [0b10000001, response.bytesize, response.bytes].flatten.pack("C*")
  STDERR.puts "Sent message to client: #{ response.inspect }"
  output = unmasked_data.pack("C*").force_encoding("utf-8")


  # Send data to client
  # response = "Sink that let in #{Time.now}"
  # STDERR.puts "Sending message to client: #{ response.inspect }"
  STDERR.puts "================================================="
  output = [0b10000001, response.size, response]
  socket.write output.pack("CCA#{response.size}")

  socket.close
end
