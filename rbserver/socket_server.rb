# # Creating a websocket server
# require 'socket' # Provides TCPServer and TCPSocket classes
# require 'digest/sha1' # Provides the sha1 hash function

# server = TCPServer.new('localhost', 2345)

# loop do

#     # Wait for a connection
#     socket = server.accept
#     STDERR.puts 'Incoming request for connection'

#     # Read the HTTPS request.
#     # The request is done when we see a line with nothing but \r\n

#     http_request = ''
#     while (line = socket.gets) && (line != '\r\n')
#         http_request += line
#     end

#     # Get the security key from the headers. 
#     # If it is absent, then close the connection.

#     if http_request =~ /Sec-WebSocket-Key: (.*)\r/
#         web_socket_key = $1
#         STDERR.puts 'WebSocket handshake detected with key: #{web_socket_key}'
#         key = $1
#     else
#         STDERR.puts 'No WebSocket handshake detected. Closing connection.'
#         socket.close
#         next
#     end

#     # Adding a security key to get a valid response
#     response_key = Digest::SHA1.base64digest([web_socket_key, '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'].join)
#     STDERR.puts 'Responding to handshake with key: #{response_key}'

#     socket.write <<-eos
# HTTP/1.1 101 Switching Protocols
# Upgrade: websocket
# Connection: Upgrade
# Sec-WebSocket-Accept: #{response_key}

#     eos
#     STDERR.puts 'Handshake complete. Starting to parse the websocket frames.'

#     socket.close
# end

require 'socket' # Provides TCPServer and TCPSocket classes
require 'digest/sha1' # Provides the sha1 hash function

server = TCPServer.new('localhost', 2345)

loop do

  # Wait for a connection
  socket = server.accept
  STDERR.puts 'Incoming request from localhost:8000 for connection'

  # Read the HTTP request. We know it's finished when we see a line with nothing but \r\n
  http_request = ''
  while (line = socket.gets) && (line != '\r\n')
    http_request += line
  end

  # Grab the security key from the headers. If one isn't present, close the connection.
  if matches = http_request.match(/^Sec-WebSocket-Key: (\S+)/)
    websocket_key = matches[1]
    STDERR.puts 'Websocket handshake detected with key: #{ websocket_key }'
  else
    STDERR.puts 'Aborting non-websocket connection'
    socket.close
    next
  end


  response_key = Digest::SHA1.base64digest([websocket_key, '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'].join)
  STDERR.puts 'Responding to handshake with key: #{ response_key }'

  socket.write <<-eos
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: #{ response_key }

  eos

  STDERR.puts 'Handshake completed. Starting to parse the websocket frame.'

  first_byte = socket.getbyte
  fin = first_byte & 0b10000000
  opcode = first_byte & 0b00001111

  raise 'We don't support continuations' unless fin
  raise 'We only support opcode 1' unless opcode == 1

  second_byte = socket.getbyte
  is_masked = second_byte & 0b10000000
  payload_size = second_byte & 0b01111111

  raise 'All incoming frames should be masked according to the websocket spec' unless is_masked
  raise 'We only support payloads < 126 bytes in length' unless payload_size < 126

#   STDERR.puts 'Payload size: #{ payload_size } bytes'

  mask = 4.times.map { socket.getbyte }
#   STDERR.puts 'Got mask: #{ mask.inspect }'

  data = payload_size.times.map { socket.getbyte }
#   STDERR.puts 'Got masked data: #{ data.inspect }'

  unmasked_data = data.each_with_index.map { |byte, i| byte ^ mask[i % 4] }
#   STDERR.puts 'Unmasked the data: #{ unmasked_data.inspect }'

  STDERR.puts 'Message from client: #{ unmasked_data.pack('C*').force_encoding('utf-8').inspect }'

  # Send data to the client
  output = [0b10000001, response.size]
  
  response = 'Sink that let in'
  STDERR.puts 'Sending message to client: #{ response.inspect }'

  output += [0b10000001, response.size, response]
  
  socket.write output.pack('CCA#{response.size}')

  socket.close
end
